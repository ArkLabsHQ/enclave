{
  self,
  aws-nitro-util,
}:
{
  pkgs,
  app,
  env,
  extraPackages ? [ ],
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
      pkgs.cacert
    ] ++ extraPackages;
    pathsToLink = [ "/" ];
    postBuild = ''
      mkdir -p $out/app
      cp ${app}/bin/${app.name} $out/app/${app.name}
      cp ${runtime}/bin/runtime $out/app/runtime
    '';
  };
  entrypoint = "/app/runtime";
  # APP_BINARY_NAME tells the runtime which binary to exec under /app
  # (runtime.go defaults to "app", but we install the app under its own name).
  env = pkgs.lib.generators.toKeyValue { } ({ APP_BINARY_NAME = app.name; } // env);
}
