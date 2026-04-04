import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { verifyAttestationDocument } from "../src/nitro.js";
import { verifySchnorrSignature } from "../src/verify.js";

const FIXTURE_DIR = join(__dirname, ".");

function loadTestAttestation(): Buffer {
  const b64 = readFileSync(join(FIXTURE_DIR, "attestation.b64"), "utf-8").trim();
  return Buffer.from(b64, "base64");
}

describe("nitro attestation verification", () => {
  it("verifies a real attestation document", () => {
    const doc = loadTestAttestation();
    const result = verifyAttestationDocument(doc);

    expect(result.signatureOk).toBe(true);
    expect(result.document.digest).toBe("SHA384");
    expect(result.document.module_id).toBeTruthy();
    expect(result.document.timestamp).toBeGreaterThan(0);

    // Verify PCR0.
    const pcr0 = result.document.pcrs.get(0);
    expect(pcr0).toBeDefined();
    expect(pcr0!.toString("hex")).toBe(
      "834837d8fdff29f35317acc40ba4e1e505b71a3cf7374ebba016a38e05c43784a01f0c1e88bf2b6174e4dbfc6f679ba9",
    );

    // Verify nonce.
    expect(result.document.nonce).toBeDefined();
    expect(result.document.nonce!.toString("hex")).toBe(
      "deadbeefcafebabe1234567890abcdef01020304",
    );

    // Verify UserData (68 bytes for nitriding).
    expect(result.document.user_data).toBeDefined();
    expect(result.document.user_data!.length).toBeGreaterThanOrEqual(68);
  });

  it("rejects a tampered attestation document", () => {
    const doc = loadTestAttestation();
    doc[doc.length - 1] ^= 0xff;

    expect(() => verifyAttestationDocument(doc)).toThrow();
  });
});

describe("schnorr signature verification", () => {
  // Real test vector captured from a running enclave.
  const body = Buffer.from('{"status":"ready"}\n');
  const sigHex =
    "f2f2c20eff91556cd3614fcf230a6e14b4d0574d3f91f8bf33b9acc76d61da40a691821f451e364385cbfed6ba6338e650f1de6fbca58c4a0cc7144185fa6eff";
  const pubkeyHex =
    "028d0bcf2b3384781e74e647351c01c0852775b59f063cde314d67328927d20dd0";

  it("verifies a real signature", () => {
    const ok = verifySchnorrSignature(body, sigHex, pubkeyHex);
    expect(ok).toBe(true);
  });

  it("rejects wrong body", () => {
    const tampered = Buffer.from('{"status":"tampered"}\n');
    const ok = verifySchnorrSignature(tampered, sigHex, pubkeyHex);
    expect(ok).toBe(false);
  });

  it("rejects wrong pubkey", () => {
    const wrongKey =
      "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ok = verifySchnorrSignature(body, sigHex, wrongKey);
    expect(ok).toBe(false);
  });
});

describe("key binding", () => {
  it("verifies appKeyHash from attestation UserData", () => {
    const doc = loadTestAttestation();
    const result = verifyAttestationDocument(doc);

    const userData = result.document.user_data!;
    expect(userData.length).toBeGreaterThanOrEqual(68);

    // Check multihash prefix at offset 34.
    expect(userData[34]).toBe(0x12);
    expect(userData[35]).toBe(0x20);

    const appKeyHash = userData.subarray(36, 68);

    // Should not be all zeros.
    expect(appKeyHash.some((b) => b !== 0)).toBe(true);

    // SHA256(attestation_pubkey) should match appKeyHash.
    const pubkeyHex =
      "028d0bcf2b3384781e74e647351c01c0852775b59f063cde314d67328927d20dd0";
    const pubkeyBytes = Buffer.from(pubkeyHex, "hex");
    const expectedHash = createHash("sha256").update(pubkeyBytes).digest();

    expect(expectedHash.equals(appKeyHash)).toBe(true);
  });
});
