{
  self,
  aws-nitro-util,
}:
{
  pkgs,
  app,
  env,
}:
let
  system = pkgs.stdenv.hostPlatform.system;
  runtime = self.packages.${system}.runtime;
  arch = pkgs.stdenv.hostPlatform.uname.processor;
  version = "${app.version}-${runtime.version}";
  nitro = aws-nitro-util.lib.${system};
in
nitro.buildEif {
  name = "${app.name}-enclave-${version}";
  inherit version arch;
  kernel = nitro.blobs.${arch}.kernel;
  kernelConfig = nitro.blobs.${arch}.kernelConfig;
  nsmKo = nitro.blobs.${arch}.nsmKo;
  copyToRoot = pkgs.buildEnv {
    name = "${app.name}-enclave-rootfs";
    paths = [
      pkgs.busybox
      pkgs.cacert
    ];
    pathsToLink = [ "/" ];
    postBuild = ''
      mkdir -p $out/app
      cp ${app}/bin/${app.name} $out/app/${app.name}
      cp ${runtime}/bin/runtime $out/app/runtime
    '';
  };
  entrypoint = "/app/runtime";
  env = pkgs.lib.generators.toKeyValue { } env;
}
