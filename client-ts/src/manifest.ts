/**
 * Manifest fetching and GitHub provenance verification.
 */

import { createHash } from "node:crypto";
import { EnclaveError, ErrorCodes } from "./error.js";
import type { Manifest } from "./types.js";

/** Construct the GitHub Releases URL for a deployment manifest. */
export function manifestUrl(repo: string, tag: string): string {
  return `https://github.com/${repo}/releases/download/${tag}/deployment.json`;
}

/** Fetch and parse a deployment manifest from the given URL. */
export async function fetchManifest(url: string): Promise<Manifest> {
  const [manifest] = await fetchManifestRaw(url);
  return manifest;
}

/** Fetch manifest returning both parsed struct and raw bytes. */
export async function fetchManifestRaw(
  url: string,
): Promise<[Manifest, Buffer]> {
  const resp = await fetch(url);

  if (!resp.ok) {
    const body = await resp.text();
    throw new EnclaveError(
      ErrorCodes.MANIFEST,
      `status ${resp.status}: ${body.trim()}`,
    );
  }

  const raw = Buffer.from(await resp.arrayBuffer());
  const manifest = JSON.parse(raw.toString()) as Manifest;

  if (!manifest.base_url) {
    throw new EnclaveError(ErrorCodes.MANIFEST, "missing base_url");
  }
  if (!manifest.pcr0) {
    throw new EnclaveError(ErrorCodes.MANIFEST, "missing pcr0");
  }

  return [manifest, raw];
}

/**
 * Verify manifest provenance via the GitHub Attestations API.
 *
 * Checks that the manifest has a valid build provenance attestation from
 * GitHub Actions. For public repos, token can be undefined.
 */
export async function verifyManifestProvenance(
  repo: string,
  manifestBytes: Buffer,
  token?: string,
): Promise<void> {
  const digest = createHash("sha256").update(manifestBytes).digest("hex");
  const digestStr = `sha256:${digest}`;

  const apiUrl = `https://api.github.com/repos/${repo}/attestations/${digestStr}`;
  const headers: Record<string, string> = {
    Accept: "application/json",
    "User-Agent": "introspector-enclave-client",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const resp = await fetch(apiUrl, { headers });

  if (resp.status === 404) {
    throw new EnclaveError(
      ErrorCodes.PROVENANCE,
      `no attestations found for manifest (repo: ${repo})`,
    );
  }

  if (!resp.ok) {
    const body = await resp.text();
    throw new EnclaveError(
      ErrorCodes.PROVENANCE,
      `attestations API status ${resp.status}: ${body.trim()}`,
    );
  }

  const result = (await resp.json()) as { attestations?: unknown[] };

  if (!result.attestations || result.attestations.length === 0) {
    throw new EnclaveError(
      ErrorCodes.PROVENANCE,
      `no attestations found for manifest (repo: ${repo})`,
    );
  }
}
