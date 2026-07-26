# MiniStack — local AWS emulator (S3, SSM, STS, IAM, EC2, KMS, …) on :4566.
#
# Used as the single AWS backend for the e2e test: OpenTofu applies against
# it, and the enclave runtime's SSM/S3/STS/KMS calls land here too (KMS via
# awsmocks' attestation-aware proxy — see awsmocks.nix).
#
# Not in nixpkgs, and it must run offline inside the test VM, so it is
# packaged here from the release tarball. Only the core dependency set is
# wired up (`full` adds RDS/ECS/Athena backends we do not use); cryptography
# is included because KMS needs it for asymmetric key specs.
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

  # ministack's EC2 emulation serves a canned AMI list and has no
  # RegisterImage, so there is no way to reference an AMI we actually built.
  # The e2e test registers blue/green like a real release does, so teach it
  # RegisterImage/DeregisterImage and have DescribeImages include them.
  # Deliberately a patch (not a runtime monkey-patch): a version bump that
  # moves these anchors should fail loudly rather than silently degrade the
  # fidelity of the AMI step.
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
