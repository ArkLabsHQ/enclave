/**
 * AWS Nitro Enclave attestation document verification.
 *
 * Implements COSE Sign1 parsing and certificate chain validation
 * equivalent to the Go nitrite library.
 */

import { createHash, createVerify, X509Certificate } from "node:crypto";
import { decode as cborDecode, encode as cborEncode } from "cbor-x";
import { EnclaveError, ErrorCodes } from "./error.js";

/** AWS Nitro Enclaves root certificate (PEM). */
const AWS_NITRO_ROOT_PEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`;

/** Attestation document fields from the CBOR payload. */
export interface AttestationDocument {
  module_id: string;
  timestamp: number;
  digest: string;
  pcrs: Map<number, Buffer>;
  certificate: Buffer;
  cabundle: Buffer[];
  public_key?: Buffer;
  user_data?: Buffer;
  nonce?: Buffer;
}

/** Result of verifying an attestation document. */
export interface NitroVerifyResult {
  document: AttestationDocument;
  signatureOk: boolean;
}

/** Verify a CBOR-encoded COSE Sign1 attestation document. */
export function verifyAttestationDocument(data: Buffer): NitroVerifyResult {
  // 1. CBOR-decode as COSE Sign1 array: [protected, unprotected, payload, signature]
  //    May be wrapped in CBOR tag 18.
  let decoded = cborDecode(data);
  if (decoded instanceof Map && decoded.has("tag")) {
    decoded = decoded.get("value");
  }

  const arr = Array.isArray(decoded) ? decoded : null;
  if (!arr || arr.length !== 4) {
    throw new EnclaveError(
      ErrorCodes.ATTESTATION_VERIFICATION,
      `not a COSE Sign1 array (got ${arr?.length ?? "non-array"} elements)`,
    );
  }

  const [protectedHeader, , payload, signature] = arr;

  if (!Buffer.isBuffer(protectedHeader) || protectedHeader.length === 0) {
    throw new EnclaveError(
      ErrorCodes.ATTESTATION_VERIFICATION,
      "empty protected section",
    );
  }
  if (!Buffer.isBuffer(payload) || payload.length === 0) {
    throw new EnclaveError(
      ErrorCodes.ATTESTATION_VERIFICATION,
      "empty payload section",
    );
  }
  if (!Buffer.isBuffer(signature) || signature.length === 0) {
    throw new EnclaveError(
      ErrorCodes.ATTESTATION_VERIFICATION,
      "empty signature section",
    );
  }

  // 2. Verify algorithm is ES384 (COSE alg -35).
  verifyAlgorithm(protectedHeader);

  // 3. CBOR-decode payload into AttestationDocument.
  const doc = parseAttestationDocument(payload);

  // 4. Validate mandatory fields.
  validateDocument(doc);

  // 5. Verify certificate chain.
  const leafCert = verifyCertChain(doc.certificate, doc.cabundle);

  // 6. Build COSE Sig_structure and verify ECDSA-P384 signature.
  const sigOk = verifyCoseSignature(
    protectedHeader,
    payload,
    signature,
    leafCert,
  );

  if (!sigOk) {
    throw new EnclaveError(
      ErrorCodes.ATTESTATION_VERIFICATION,
      "COSE signature verification failed",
    );
  }

  return { document: doc, signatureOk: sigOk };
}

function verifyAlgorithm(protectedHeader: Buffer): void {
  const header = cborDecode(protectedHeader);
  // COSE header key 1 = "alg"
  const alg = header instanceof Map ? header.get(1) : header?.[1];
  if (alg === -35 || alg === "ES384") return;
  throw new EnclaveError(
    ErrorCodes.ATTESTATION_VERIFICATION,
    `unsupported COSE algorithm: ${alg}`,
  );
}

function parseAttestationDocument(payload: Buffer): AttestationDocument {
  const raw = cborDecode(payload);
  if (!raw || typeof raw !== "object") {
    throw new EnclaveError(
      ErrorCodes.ATTESTATION_VERIFICATION,
      "document is not a CBOR map",
    );
  }

  // cbor-x may return a Map or a plain object depending on the CBOR structure.
  const get = (key: string): unknown => {
    if (raw instanceof Map) return raw.get(key);
    return (raw as Record<string, unknown>)[key];
  };

  const pcrsRaw = get("pcrs");
  const pcrs = new Map<number, Buffer>();
  if (pcrsRaw instanceof Map) {
    for (const [k, v] of pcrsRaw) {
      pcrs.set(Number(k), Buffer.from(v as Uint8Array));
    }
  } else if (pcrsRaw && typeof pcrsRaw === "object") {
    for (const [k, v] of Object.entries(pcrsRaw)) {
      pcrs.set(Number(k), Buffer.from(v as Uint8Array));
    }
  }

  const cabundleRaw = get("cabundle") as Uint8Array[] | undefined;
  const cabundle = cabundleRaw
    ? cabundleRaw.map((b) => Buffer.from(b))
    : [];

  const toBuffer = (v: unknown): Buffer | undefined =>
    v ? Buffer.from(v as Uint8Array) : undefined;

  return {
    module_id: get("module_id") as string,
    timestamp: get("timestamp") as number,
    digest: get("digest") as string,
    pcrs,
    certificate: Buffer.from(get("certificate") as Uint8Array),
    cabundle,
    public_key: toBuffer(get("public_key")),
    user_data: toBuffer(get("user_data")),
    nonce: toBuffer(get("nonce")),
  };
}

function validateDocument(doc: AttestationDocument): void {
  if (
    !doc.module_id ||
    !doc.digest ||
    !doc.timestamp ||
    doc.pcrs.size === 0 ||
    doc.certificate.length === 0 ||
    doc.cabundle.length === 0
  ) {
    throw new EnclaveError(
      ErrorCodes.ATTESTATION_VERIFICATION,
      "mandatory fields missing",
    );
  }

  if (doc.digest !== "SHA384") {
    throw new EnclaveError(
      ErrorCodes.ATTESTATION_VERIFICATION,
      "digest is not SHA384",
    );
  }

  if (doc.pcrs.size < 1 || doc.pcrs.size > 32) {
    throw new EnclaveError(
      ErrorCodes.ATTESTATION_VERIFICATION,
      "bad PCR count",
    );
  }

  for (const [idx, val] of doc.pcrs) {
    if (idx > 31) {
      throw new EnclaveError(
        ErrorCodes.ATTESTATION_VERIFICATION,
        `PCR index ${idx} out of range`,
      );
    }
    if (
      val.length === 0 ||
      !(val.length === 32 || val.length === 48 || val.length === 64)
    ) {
      throw new EnclaveError(
        ErrorCodes.ATTESTATION_VERIFICATION,
        `PCR${idx} has invalid length ${val.length}`,
      );
    }
  }
}

/**
 * Verify the certificate chain: leaf -> intermediates -> root.
 * Returns the leaf X509Certificate for COSE signature verification.
 */
function verifyCertChain(
  leafDer: Buffer,
  cabundle: Buffer[],
): X509Certificate {
  const rootCert = new X509Certificate(AWS_NITRO_ROOT_PEM);

  // Build chain: root, intermediates (cabundle), leaf
  const chain: X509Certificate[] = [rootCert];
  for (const certDer of cabundle) {
    chain.push(new X509Certificate(certDer));
  }
  const leafCert = new X509Certificate(leafDer);
  chain.push(leafCert);

  // Verify each pair: chain[i] signs chain[i+1]
  for (let i = 0; i < chain.length - 1; i++) {
    const isValid = chain[i + 1].checkIssued(chain[i]);
    if (!isValid) {
      throw new EnclaveError(
        ErrorCodes.CERTIFICATE,
        `certificate chain validation failed at depth ${i}`,
      );
    }
  }

  return leafCert;
}

/**
 * Build COSE Sig_structure and verify ECDSA-P384 signature.
 * Sig_structure = ["Signature1", protected, b"", payload]
 */
function verifyCoseSignature(
  protectedHeader: Buffer,
  payload: Buffer,
  signature: Buffer,
  leafCert: X509Certificate,
): boolean {
  // Build Sig_structure per RFC 8152 Section 4.4
  const sigStructure = [
    "Signature1",
    protectedHeader,
    Buffer.alloc(0),
    payload,
  ];

  const sigStructBytes = Buffer.from(cborEncode(sigStructure));

  // ECDSA-P384: signature is r || s, each 48 bytes
  if (signature.length !== 96) return false;

  // Convert raw r||s to DER format for Node.js crypto
  const r = signature.subarray(0, 48);
  const s = signature.subarray(48, 96);
  const derSig = encodeEcdsaDer(r, s);

  // Verify using Node.js crypto
  const verify = createVerify("SHA384");
  verify.update(sigStructBytes);

  return verify.verify(
    leafCert.publicKey,
    derSig,
  );
}

/** Encode raw r,s integers into DER-encoded ECDSA signature. */
function encodeEcdsaDer(r: Buffer, s: Buffer): Buffer {
  const encodeInt = (val: Buffer): Buffer => {
    // Strip leading zeros but keep at least one byte
    let i = 0;
    while (i < val.length - 1 && val[i] === 0) i++;
    let trimmed = val.subarray(i);
    // If high bit is set, prepend a 0x00
    if (trimmed[0]! & 0x80) {
      trimmed = Buffer.concat([Buffer.from([0x00]), trimmed]);
    }
    return Buffer.concat([Buffer.from([0x02, trimmed.length]), trimmed]);
  };

  const rDer = encodeInt(r);
  const sDer = encodeInt(s);
  const body = Buffer.concat([rDer, sDer]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}
