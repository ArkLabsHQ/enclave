export class EnclaveError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "EnclaveError";
  }
}

export const ErrorCodes = {
  MISSING_PCR0: "MISSING_PCR0",
  ATTESTATION_VERIFICATION: "ATTESTATION_VERIFICATION",
  PCR_MISMATCH: "PCR_MISMATCH",
  PCR_NOT_FOUND: "PCR_NOT_FOUND",
  NONCE_MISMATCH: "NONCE_MISMATCH",
  KEY_BINDING: "KEY_BINDING",
  SIGNATURE_VERIFICATION: "SIGNATURE_VERIFICATION",
  MANIFEST: "MANIFEST",
  PROVENANCE: "PROVENANCE",
  CERTIFICATE: "CERTIFICATE",
  HTTP: "HTTP",
} as const;
