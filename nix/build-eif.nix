{
  self,
  aws-nitro-util,
}:
{
  pkgs,
  app,
  env,
  overrideAllowlist ? [ ],
  extraPackages ? [ ],
}:
let
  lib = pkgs.lib;
  system = pkgs.stdenv.hostPlatform.system;
  runtime = self.packages.${system}.runtime;
  arch = pkgs.stdenv.hostPlatform.uname.processor;
  appName = lib.getName app;
  appBinaryName = app.meta.mainProgram or appName;
  appExe = lib.getExe' app appBinaryName;
  version = "${app.version}-${runtime.version}";
  nitro = aws-nitro-util.lib.${system};
  # aws-nitro-util's init exits when its readiness connect is interrupted by a
  # signal, which panics the enclave kernel at boot; the patch retries it.
  init = aws-nitro-util.crossPackages.${system}."${arch}-linux".eif-init.overrideAttrs (old: {
    patches = (old.patches or [ ]) ++ [ ./patches/eif-init-retry-eintr.patch ];
  });
in
assert lib.assertMsg (
  !(env ? ENCLAVE_OVERRIDE_ALLOWLIST)
) "buildEif: set overrideAllowlist instead of env.ENCLAVE_OVERRIDE_ALLOWLIST";
nitro.buildEif ({
  name = "${appName}-enclave-${version}";
  inherit version arch;
  init = "${init}/bin/init";
  kernel = nitro.blobs.${arch}.kernel;
  kernelConfig = nitro.blobs.${arch}.kernelConfig;
  nsmKo = nitro.blobs.${arch}.nsmKo;
  copyToRoot = pkgs.buildEnv {
    name = "${appName}-enclave-rootfs";
    paths = [
      pkgs.cacert
    ] ++ extraPackages;
    pathsToLink = [ "/" ];
    postBuild = ''
      mkdir -p $out/app
      cp ${appExe} $out/app/${appBinaryName}
      cp ${runtime}/bin/runtime $out/app/runtime
    '';
  };
  entrypoint = "/app/runtime";
  env = lib.generators.toKeyValue { } (
    env
    // {
      APP_BINARY_NAME = appBinaryName;
      ENCLAVE_OVERRIDE_ALLOWLIST = lib.concatStringsSep "," overrideAllowlist;
    }
  );
})
