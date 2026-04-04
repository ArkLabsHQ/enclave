/**
 * Attestation verification, key binding, and Schnorr signature verification.
 */

import { createHash, randomBytes } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1.js";
import { EnclaveError, ErrorCodes } from "./error.js";
import {
  verifyAttestationDocument,
  type NitroVerifyResult,
} from "./nitro.js";
import type { EnclaveInfoResponse } from "./types.js";

/**
 * Fetch the attestation document from the enclave, verify it against the
 * AWS Nitro root certificate chain, check the nonce, and validate PCR0.
 */
export async function fetchAndVerifyAttestation(
  baseUrl: string,
  expectedPCR0: string,
  fetchFn: typeof fetch = globalThis.fetch,
): Promise<NitroVerifyResult> {
  // Generate a random nonce to prevent replay attacks.
  const nonce = randomBytes(20);
  const nonceHex = nonce.toString("hex");

  const url = `${baseUrl.replace(/\/+$/, "")}/enclave/attestation?nonce=${nonceHex}`;
  const resp = await fetchFn(url);

  if (!resp.ok) {
    const body = await resp.text();
    throw new EnclaveError(
      ErrorCodes.ATTESTATION_VERIFICATION,
      `status ${resp.status}: ${body.trim()}`,
    );
  }

  let payload = (await resp.text()).trim();

  // The attestation may be returned as raw base64 or as JSON {"document":"..."}.
  if (payload.startsWith("{")) {
    try {
      const parsed = JSON.parse(payload) as { document?: string };
      if (parsed.document) {
        payload = parsed.document;
      }
    } catch {
      // Not JSON, treat as raw base64.
    }
  }

  const docBytes = Buffer.from(payload, "base64");

  // Verify the COSE Sign1 document against the AWS Nitro root certs.
  const result = verifyAttestationDocument(docBytes);

  // Verify the nonce to confirm freshness.
  if (!result.document.nonce || result.document.nonce.length === 0) {
    throw new EnclaveError(ErrorCodes.NONCE_MISMATCH, "attestation missing nonce");
  }

  if (!nonce.equals(result.document.nonce)) {
    throw new EnclaveError(ErrorCodes.NONCE_MISMATCH, "attestation nonce mismatch");
  }

  // Verify PCR0 matches the expected enclave build measurement.
  const pcr0 = result.document.pcrs.get(0);
  if (!pcr0) {
    throw new EnclaveError(
      ErrorCodes.PCR_NOT_FOUND,
      "attestation missing PCR0",
    );
  }

  const pcr0Hex = pcr0.toString("hex");
  if (pcr0Hex.toLowerCase() !== expectedPCR0.toLowerCase()) {
    throw new EnclaveError(
      ErrorCodes.PCR_MISMATCH,
      `PCR0 mismatch: expected ${expectedPCR0}, got ${pcr0Hex}`,
    );
  }

  return result;
}

/**
 * Verify the enclave's ephemeral attestation key by checking that the
 * pubkey from /v1/enclave-info matches the appKeyHash in the attestation
 * document's UserData.
 *
 * UserData format (nitriding): [0x12, 0x20, tlsKeyHash:32] ++ [0x12, 0x20, appKeyHash:32]
 * Total 68 bytes. appKeyHash is at bytes 36:68.
 */
export async function verifyKeyBinding(
  baseUrl: string,
  userData: Buffer | undefined,
  fetchFn: typeof fetch = globalThis.fetch,
): Promise<string> {
  if (!userData || userData.length < 68) {
    return ""; // UserData too short, key binding not supported.
  }

  // Check multihash prefix at offset 34.
  if (userData[34] !== 0x12 || userData[35] !== 0x20) {
    throw new EnclaveError(
      ErrorCodes.KEY_BINDING,
      `UserData missing multihash prefix at offset 34 (got ${userData[34]!.toString(16)} ${userData[35]!.toString(16)})`,
    );
  }

  const appKeyHash = userData.subarray(36, 68);

  // Check if appKeyHash is all zeros.
  if (appKeyHash.every((b) => b === 0)) {
    throw new EnclaveError(
      ErrorCodes.KEY_BINDING,
      "attestation key not yet registered (appKeyHash is all zeros)",
    );
  }

  // Fetch the attestation pubkey from the enclave.
  const info = await fetchEnclaveInfo(baseUrl, fetchFn);

  if (!info.attestation_pubkey) {
    throw new EnclaveError(
      ErrorCodes.KEY_BINDING,
      "enclave reports no attestation pubkey but appKeyHash is set",
    );
  }

  const attestPubkeyBytes = Buffer.from(info.attestation_pubkey, "hex");

  // Verify that SHA256(pubkey) matches the appKeyHash from attestation.
  const expectedHash = createHash("sha256").update(attestPubkeyBytes).digest();

  if (!expectedHash.equals(appKeyHash)) {
    throw new EnclaveError(
      ErrorCodes.KEY_BINDING,
      `appKeyHash mismatch: expected SHA256(${info.attestation_pubkey}) = ${expectedHash.toString("hex")}, got ${appKeyHash.toString("hex")}`,
    );
  }

  return info.attestation_pubkey;
}

/**
 * Verify a BIP-340 Schnorr signature over SHA256(body) using the
 * hex-encoded compressed secp256k1 pubkey.
 */
export function verifySchnorrSignature(
  body: Buffer,
  sigHex: string,
  attestPubkeyHex: string,
): boolean {
  let pubkeyBytes = Buffer.from(attestPubkeyHex, "hex");

  // Drop the prefix byte (02/03) to get x-only (32 bytes).
  if (pubkeyBytes.length === 33) {
    pubkeyBytes = pubkeyBytes.subarray(1);
  }

  const sigBytes = Buffer.from(sigHex, "hex");
  const msgHash = createHash("sha256").update(body).digest();

  // BIP-340: the Go btcec library passes SHA256(body) as the raw 32-byte
  // message. @noble/secp256k1's schnorr.verify treats the input as the
  // message and applies tagged hashing internally. Use {raw: true} to
  // pass the pre-hashed message directly.
  return schnorr.verify(sigBytes, msgHash, pubkeyBytes);
}

/** Fetch the /v1/enclave-info endpoint. */
export async function fetchEnclaveInfo(
  baseUrl: string,
  fetchFn: typeof fetch = globalThis.fetch,
): Promise<EnclaveInfoResponse> {
  const url = `${baseUrl.replace(/\/+$/, "")}/v1/enclave-info`;
  const resp = await fetchFn(url);

  if (!resp.ok) {
    const body = await resp.text();
    throw new EnclaveError(
      ErrorCodes.HTTP,
      `enclave-info status ${resp.status}: ${body.trim()}`,
    );
  }

  const info = (await resp.json()) as EnclaveInfoResponse;

  if (info.error) {
    throw new EnclaveError(ErrorCodes.HTTP, `enclave init error: ${info.error}`);
  }

  return info;
}
