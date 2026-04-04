/** Configuration for the enclave client. */
export interface Options {
  /** Hex-encoded PCR0 value to verify against. */
  expectedPCR0: string;
  /** Hex-encoded SHA256 hashes of secret compressed public keys (PCR16+). */
  expectedPCRs?: string[];
  /** How long a verified attestation is cached in ms. Default: 60000. */
  cacheTTL?: number;
  /** Skip TLS certificate verification. Default: true. */
  insecureTLS?: boolean;
  /** Enable GitHub artifact attestation verification. */
  verifyProvenance?: boolean;
  /** Optional GitHub API token for private repo attestations. */
  githubToken?: string;
}

/** Wraps an HTTP response with attestation verification metadata. */
export interface Response {
  statusCode: number;
  headers: Record<string, string>;
  body: Buffer;
  signatureVerified: boolean;
}

/** Contains the verified attestation state. */
export interface AttestationResult {
  pcr0: string;
  pcrs: Record<number, string>;
  /** Hex-encoded compressed secp256k1 pubkey. */
  attestationKey: string;
  verified: boolean;
  verifiedAt: number;
}

/** Deployment metadata from a GitHub Release (deployment.json). */
export interface Manifest {
  base_url: string;
  pcr0: string;
  pcr1?: string;
  pcr2?: string;
  timestamp?: string;
  commit?: string;
  repo?: string;
}

/** JSON structure returned by /v1/enclave-info. */
export interface EnclaveInfoResponse {
  version: string;
  previous_pcr0: string;
  attestation_pubkey: string;
  error?: string;
}
