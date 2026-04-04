/**
 * Verified HTTP client for AWS Nitro Enclaves.
 *
 * @example
 * ```ts
 * import { Client } from "introspector-enclave-client";
 *
 * const client = new Client("https://1.2.3.4", {
 *   expectedPCR0: "abc123...",
 * });
 *
 * const resp = await client.get("/my-endpoint");
 * console.log(resp.signatureVerified);
 * ```
 *
 * @packageDocumentation
 */

export { Client } from "./client.js";
export { EnclaveError, ErrorCodes } from "./error.js";
export {
  fetchManifest,
  manifestUrl,
  verifyManifestProvenance,
} from "./manifest.js";
export type {
  AttestationResult,
  Manifest,
  Options,
  Response,
} from "./types.js";
