# MiniStack is the offline AWS backend for OpenTofu and runtime AWS calls.
# Recipient-aware KMS requests reach it through awsmocks. Cryptography is
# required by asymmetric KMS.
{ pkgs }:
pkgs.python3Packages.buildPythonApplication rec {
  pname = "ministack";
  version = "1.4.6";
  pyproject = true;

  src = pkgs.fetchFromGitHub {
    owner = "ministackorg";
    repo = "ministack";
    tag = "v${version}";
    hash = "sha256-6BUczgfnrSRcFpzmcStvOIIsULjqphGqqWPJZRQHNuU=";
  };

  # Patches add image registration and EC2 fields required by OpenTofu.
  # A MiniStack upgrade should fail if these patches no longer apply.
  patches = [
    ./patches/ministack-register-image.patch
    ./patches/ministack-terraform-ec2.patch
  ];

  build-system = with pkgs.python3Packages; [
    setuptools
    wheel
  ];

  dependencies = with pkgs.python3Packages; [
    hypercorn
    pyyaml
    defusedxml
    cryptography
  ];

  # The test suite needs boto3 + a live server; the e2e check exercises the
  # surface we actually depend on.
  doCheck = false;

  pythonImportsCheck = [ "ministack" ];

  meta.mainProgram = "ministack";
}
