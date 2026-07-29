# MiniStack lacks Nitro KMS Recipient handling. This proxy strips Recipient,
# forwards to MiniStack, and CMS-wraps plaintext to the attested RSA key; it
# also serves the IMDSv2 credential stub.
{ pkgs }:
pkgs.buildGoModule {
  pname = "awsmocks";
  version = "0.1.0";
  src = ./awsmocks;
  vendorHash = "sha256-FlTEY1v5ZVqTICXGLTBgVW+JhlWwIiuJDekX2d3bfWs=";
  env.CGO_ENABLED = "0";
  meta.mainProgram = "awsmocks";
}
