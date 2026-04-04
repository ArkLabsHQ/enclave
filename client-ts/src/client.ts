/**
 * Main verified HTTP client for AWS Nitro Enclaves.
 */

import { Agent } from "node:https";
import type {
  AttestationResult,
  Options,
  Response as EnclaveResponse,
} from "./types.js";
import {
  fetchAndVerifyAttestation,
  verifyKeyBinding,
  verifySchnorrSignature,
} from "./verify.js";
import { fetchManifestRaw, verifyManifestProvenance } from "./manifest.js";
import { EnclaveError, ErrorCodes } from "./error.js";

/**
 * A verified HTTP client for an AWS Nitro Enclave.
 *
 * Every request first verifies the enclave's attestation document (PCR0,
 * optional secret PCRs, attestation key binding) and then verifies the
 * Schnorr response signature.
 *
 * @example
 * ```ts
 * const client = new Client("https://1.2.3.4", {
 *   expectedPCR0: "abc123...",
 * });
 * const resp = await client.get("/my-endpoint");
 * console.log(resp.signatureVerified);
 * ```
 */
export class Client {
  private baseUrl: string;
  private opts: Required<
    Pick<Options, "expectedPCR0" | "cacheTTL" | "insecureTLS">
  > &
    Options;
  private cachedState: AttestationResult | null = null;
  private fetchFn: typeof fetch;

  constructor(baseUrl: string, opts: Options) {
    if (!opts.expectedPCR0) {
      throw new EnclaveError(ErrorCodes.MISSING_PCR0, "expectedPCR0 is required");
    }

    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.opts = {
      cacheTTL: 60_000,
      insecureTLS: true,
      expectedPCRs: [],
      ...opts,
    };

    // Create a fetch function that skips TLS verification if needed.
    if (this.opts.insecureTLS) {
      const agent = new Agent({ rejectUnauthorized: false });
      this.fetchFn = (input: string | URL | Request, init?: RequestInit) =>
        fetch(input, {
          ...init,
          // @ts-expect-error Node.js fetch supports agent via dispatcher
          dispatcher: agent,
        });
    } else {
      this.fetchFn = globalThis.fetch;
    }
  }

  /**
   * Create a client by fetching deployment metadata from a GitHub Release
   * manifest URL.
   */
  static async fromManifest(
    manifestUrl: string,
    opts: Options,
  ): Promise<Client> {
    const [m, raw] = await fetchManifestRaw(manifestUrl);

    if (opts.verifyProvenance) {
      if (!m.repo) {
        throw new EnclaveError(
          ErrorCodes.MANIFEST,
          "missing repo field, cannot verify provenance",
        );
      }
      await verifyManifestProvenance(m.repo, raw, opts.githubToken);
    }

    if (
      opts.expectedPCR0 &&
      opts.expectedPCR0.toLowerCase() !== m.pcr0.toLowerCase()
    ) {
      throw new EnclaveError(
        ErrorCodes.MANIFEST,
        `manifest PCR0 ${m.pcr0} does not match expected ${opts.expectedPCR0}`,
      );
    }

    return new Client(m.base_url, { ...opts, expectedPCR0: m.pcr0 });
  }

  /** Make a verified GET request to the enclave. */
  async get(path: string): Promise<EnclaveResponse> {
    return this.execute(this.url(path), { method: "GET" });
  }

  /** Make a verified POST request to the enclave. */
  async post(path: string, body: string | Buffer): Promise<EnclaveResponse> {
    return this.execute(this.url(path), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
  }

  /** Make a verified generic HTTP request. */
  async request(
    url: string,
    init?: RequestInit,
  ): Promise<EnclaveResponse> {
    return this.execute(url, init);
  }

  /** Manually trigger attestation verification, bypassing the cache. */
  async verifyAttestation(): Promise<AttestationResult> {
    return this.verifyInner();
  }

  private async execute(
    url: string,
    init?: RequestInit,
  ): Promise<EnclaveResponse> {
    // Step 1: Verify attestation (uses cache if valid).
    const attest = await this.ensureVerified();

    // Step 2: Execute the actual request.
    const resp = await this.fetchFn(url, init);
    const body = Buffer.from(await resp.arrayBuffer());

    // Step 3: Verify response signature.
    let signatureVerified = false;
    if (attest.attestationKey) {
      const sigHex = resp.headers.get("x-attestation-signature");
      if (sigHex) {
        try {
          signatureVerified = verifySchnorrSignature(
            body,
            sigHex,
            attest.attestationKey,
          );
        } catch {
          // Signature verification failed silently.
        }
      }
    }

    // Collect headers.
    const headers: Record<string, string> = {};
    resp.headers.forEach((v, k) => {
      headers[k] = v;
    });

    return {
      statusCode: resp.status,
      headers,
      body,
      signatureVerified,
    };
  }

  private async ensureVerified(): Promise<AttestationResult> {
    if (
      this.cachedState &&
      this.cachedState.verified &&
      Date.now() - this.cachedState.verifiedAt < this.opts.cacheTTL
    ) {
      return this.cachedState;
    }
    return this.verifyInner();
  }

  private async verifyInner(): Promise<AttestationResult> {
    // 1. Fetch and verify attestation document.
    const nitroResult = await fetchAndVerifyAttestation(
      this.baseUrl,
      this.opts.expectedPCR0,
      this.fetchFn,
    );

    // 2. Verify additional PCRs (secret pubkey hashes).
    const pcrs: Record<number, string> = {};
    for (const [idx, bytes] of nitroResult.document.pcrs) {
      if (bytes.length > 0) {
        pcrs[idx] = bytes.toString("hex");
      }
    }

    const expectedPCRs = this.opts.expectedPCRs ?? [];
    for (let i = 0; i < expectedPCRs.length; i++) {
      const pcrIndex = 16 + i;
      const actual = pcrs[pcrIndex];
      if (!actual) {
        throw new EnclaveError(
          ErrorCodes.PCR_NOT_FOUND,
          `PCR${pcrIndex} not found in attestation document`,
        );
      }
      if (actual.toLowerCase() !== expectedPCRs[i]!.toLowerCase()) {
        throw new EnclaveError(
          ErrorCodes.PCR_MISMATCH,
          `PCR${pcrIndex} mismatch: expected ${expectedPCRs[i]}, got ${actual}`,
        );
      }
    }

    // 3. Verify attestation key binding.
    const attestKey = await verifyKeyBinding(
      this.baseUrl,
      nitroResult.document.user_data,
      this.fetchFn,
    );

    const result: AttestationResult = {
      pcr0: this.opts.expectedPCR0,
      pcrs,
      attestationKey: attestKey,
      verified: true,
      verifiedAt: Date.now(),
    };

    this.cachedState = result;
    return result;
  }

  private url(path: string): string {
    if (!path.startsWith("/")) path = "/" + path;
    return this.baseUrl + path;
  }
}
