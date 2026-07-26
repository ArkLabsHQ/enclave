{ pkgs }:
pkgs.rustPlatform.buildRustPackage (finalAttrs: {
  pname = "aws-nitro-enclaves-cli";
  version = "1.4.5";
  src = pkgs.fetchFromGitHub {
    owner = "aws";
    repo = finalAttrs.pname;
    rev = "v${finalAttrs.version}";
    hash = "sha256-3CuzadNYLiOG00xWo5yMhij/XW6Ny/xOgfKHxXB+yWc=";
  };
  cargoHash = "sha256-YXyYvjXj7OKHEP7kbxAkzRlqvJngIJ8tvOrMsfl7Wv4=";
  nativeBuildInputs = with pkgs; [
    pkg-config
    gnumake
    llvmPackages.llvm
    llvmPackages.clang
  ];
  buildInputs = with pkgs; [ openssl ];
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
  postInstall = ''
    substituteInPlace bootstrap/nitro-enclaves-allocator \
      --replace "/bin/bash" "${pkgs.bash}/bin/bash"
    install -Dm555 bootstrap/nitro-enclaves-allocator $out/bin/nitro-enclaves-allocator
  '';
  doCheck = false;
})
