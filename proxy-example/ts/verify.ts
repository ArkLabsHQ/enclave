// The caller of a proxy's GetInfo, as a TypeScript app would write it. It
// checks the signer evidence the proxy relays, so it need not trust the proxy,
// then decodes the signed signer response with the buf-generated schema. It
// mirrors client.VerifyProxyEvidence.
//
// It uses only web-standard APIs, so it runs in Node and in browsers; main.ts
// runs it from the command line.

import { fromBinary } from "@bufbuild/protobuf";
import { base64Decode } from "@bufbuild/protobuf/wire";
import { decode } from "cbor2";
import {
  type GetPubkeyResponse,
  GetPubkeyResponseSchema,
  SignerService,
} from "./gen/signer/v1/service_pb.ts";

// The attested user_data is 149 bytes; the response-signing key is bytes 47–79.
const userDataLength = 149;
const signingKeyStart = 47;
const signingKeyEnd = 79;

// The proxy's GET /v1/info answer. The caller speaks REST to the proxy, so
// this is plain JSON; only the signed signer response is protobuf.
type GetInfoResponse = {
  signerPubkey: string;
  signerEvidence: {
    attestation: string; // base64 NSM document
    payload: {
      method: string;
      nonce: string; // base64
      timestamp: number; // Unix milliseconds
      response: string; // base64 GetPubkeyResponse
    };
    signature: string; // base64
  };
};

type NitroDocument = {
  nonce: Uint8Array;
  pcrs: Map<number, Uint8Array>;
  timestamp: number; // Unix milliseconds
  user_data: Uint8Array;
};

const hex = (b: Uint8Array) =>
  Array.from(b, (byte) => byte.toString(16).padStart(2, "0")).join("");
const sha256 = async (b: Uint8Array) =>
  hex(new Uint8Array(await crypto.subtle.digest("SHA-256", b)));

export async function verifyGetInfo(
  proxyURL: string,
  expectedPCR0: string,
): Promise<GetPubkeyResponse> {
  // The caller notes when it asked: the evidence must be attested and signed
  // no earlier.
  const notBefore = Date.now();
  const res = await fetch(`${proxyURL}/v1/info`);
  if (!res.ok) {
    throw new Error(`GetInfo: HTTP ${res.status}`);
  }
  const info: GetInfoResponse = await res.json();
  const { attestation, payload } = info.signerEvidence;
  const nonce = base64Decode(payload.nonce);
  const signedResponse = base64Decode(payload.response);
  const signature = base64Decode(info.signerEvidence.signature);

  // 1. The attestation is a COSE_Sign1 whose payload is the NSM document. The
  // test's software NSM does not sign it, so, like the Go client's
  // InsecureSkipCOSEVerify, this skips the COSE signature; a real caller
  // verifies it and the AWS Nitro chain first.
  const [, , docBytes] = decode<[Uint8Array, unknown, Uint8Array, Uint8Array]>(
    base64Decode(attestation),
  );
  const doc = decode<NitroDocument>(docBytes);
  if (hex(doc.nonce) !== hex(nonce)) {
    throw new Error("attestation nonce mismatch");
  }
  const pcr0 = hex(doc.pcrs.get(0) ?? new Uint8Array());
  if (pcr0 !== expectedPCR0.toLowerCase()) {
    throw new Error(`PCR0 mismatch: expected ${expectedPCR0}, got ${pcr0}`);
  }
  if (doc.timestamp < notBefore) {
    throw new Error(`attestation from ${doc.timestamp}, before ${notBefore}`);
  }
  if (doc.user_data.length !== userDataLength) {
    throw new Error(`user_data must be exactly ${userDataLength} bytes`);
  }
  const signingKey = doc.user_data.subarray(signingKeyStart, signingKeyEnd);

  // 2. The signed call must be the one the caller expects, made no earlier
  // than it asked.
  const method = `/${SignerService.typeName}/${SignerService.method.getPubkey.name}`;
  if (payload.method !== method) {
    throw new Error(`evidence is for method ${payload.method}, not ${method}`);
  }
  if (payload.timestamp < notBefore) {
    throw new Error(`response from ${payload.timestamp}, before ${notBefore}`);
  }

  // 3. Rebuild the message the runtime signed (README, "Signed responses"): a
  // gRPC call is a POST to its method, GetPubkey's request is empty, and
  // grpc-status 0 is OK.
  const message = [
    "enclave-signed-response",
    `POST ${method}`,
    hex(nonce),
    payload.timestamp.toString(),
    await sha256(new Uint8Array()),
    "0",
    await sha256(signedResponse),
  ].join("\n");
  const key = await crypto.subtle.importKey("raw", signingKey, { name: "Ed25519" }, false, [
    "verify",
  ]);
  const signed = await crypto.subtle.verify(
    { name: "Ed25519" },
    key,
    signature,
    new TextEncoder().encode(message),
  );
  if (!signed) {
    throw new Error("invalid enclave signature");
  }

  // 4. Only the signed response is authenticated: decode it, and check the
  // pubkey GetInfo reports against it.
  const response = fromBinary(GetPubkeyResponseSchema, signedResponse);
  if (response.pubkey.toLowerCase() !== info.signerPubkey.toLowerCase()) {
    throw new Error("GetInfo pubkey mismatch");
  }
  return response;
}
