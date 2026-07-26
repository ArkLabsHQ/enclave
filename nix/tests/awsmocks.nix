# awsmocks: the one piece of AWS behaviour no emulator provides — KMS
# Decrypt/GenerateDataKey with a Nitro `Recipient` (attestation document in,
# CMS EnvelopedData out) — plus an IMDSv2 credential stub.
#
# It is a rewriting reverse proxy: requests without a Recipient pass straight
# through to the upstream KMS (ministack), and those with one are stripped,
# forwarded, and the plaintext re-enveloped to the enclave's attested RSA key.
#
# Vendored from the previous framework repo (test/awsmocks); the source is
# unmodified apart from the module path.
{ pkgs }:
pkgs.buildGoModule {
  pname = "awsmocks";
  version = "0.1.0";
  src = ./awsmocks;
  vendorHash = "sha256-FlTEY1v5ZVqTICXGLTBgVW+JhlWwIiuJDekX2d3bfWs=";
  env.CGO_ENABLED = "0";
  meta.mainProgram = "awsmocks";
}
