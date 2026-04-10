package introspector_enclave

import "os"

// frameworkFile describes a template file to scaffold during `enclave init`.
type frameworkFile struct {
	RelPath string      // path relative to user's project root
	Mode    os.FileMode // file permissions
	Content string      // file content
}

// getFrameworkFiles returns the list of framework files to scaffold.
// These are required by OpenTofu deploy and Nix build (flake.nix).
// The language parameter selects the correct flake.nix template.
func getFrameworkFiles(language string) []frameworkFile {
	flakeNix := frameworkFlakeNix // default: Go
	switch language {
	case "nodejs":
		flakeNix = frameworkFlakeNixNodejs
	case "dotnet":
		flakeNix = frameworkFlakeNixDotnet
	case "rust":
		flakeNix = frameworkFlakeNixRust
	}

	return []frameworkFile{
		{
			RelPath: "flake.nix",
			Mode:    0644,
			Content: flakeNix,
		},
		{
			RelPath: "enclave/start.sh",
			Mode:    0755,
			Content: frameworkStartSh,
		},
		{
			RelPath: "enclave/gvproxy/start.sh",
			Mode:    0755,
			Content: frameworkGvproxyStartSh,
		},
		{
			RelPath: "enclave/scripts/enclave_init.sh",
			Mode:    0755,
			Content: frameworkEnclaveInitSh,
		},
		{
			RelPath: "enclave/systemd/enclave-watchdog.service",
			Mode:    0644,
			Content: frameworkWatchdogService,
		},
		{
			RelPath: "enclave/systemd/enclave-imds-proxy.service",
			Mode:    0644,
			Content: frameworkIMDSProxyService,
		},
		{
			RelPath: "enclave/systemd/gvproxy.service",
			Mode:    0644,
			Content: frameworkGvproxyService,
		},
		{
			RelPath: "enclave/systemd/enclave-mgmt.service",
			Mode:    0644,
			Content: frameworkMgmtService,
		},
		{
			RelPath: "enclave/tofu/modules/enclave/templates/user_data.sh.tftpl",
			Mode:    0644,
			Content: frameworkUserData,
		},
		// OpenTofu root module.
		{
			RelPath: "enclave/tofu/main.tf",
			Mode:    0644,
			Content: tofuRootMain,
		},
		{
			RelPath: "enclave/tofu/variables.tf",
			Mode:    0644,
			Content: tofuRootVariables,
		},
		{
			RelPath: "enclave/tofu/outputs.tf",
			Mode:    0644,
			Content: tofuRootOutputs,
		},
		// OpenTofu enclave module.
		{
			RelPath: "enclave/tofu/modules/enclave/main.tf",
			Mode:    0644,
			Content: tofuModuleEnclaveMain,
		},
		{
			RelPath: "enclave/tofu/modules/enclave/variables.tf",
			Mode:    0644,
			Content: tofuModuleEnclaveVariables,
		},
		{
			RelPath: "enclave/tofu/modules/enclave/outputs.tf",
			Mode:    0644,
			Content: tofuModuleEnclaveOutputs,
		},
		{
			RelPath: "enclave/tofu/modules/enclave/kms.tf",
			Mode:    0644,
			Content: tofuModuleEnclaveKMS,
		},
		{
			RelPath: "enclave/tofu/modules/enclave/iam.tf",
			Mode:    0644,
			Content: tofuModuleEnclaveIAM,
		},
		{
			RelPath: "enclave/tofu/modules/enclave/ssm.tf",
			Mode:    0644,
			Content: tofuModuleEnclaveSSM,
		},
		{
			RelPath: "enclave/tofu/modules/enclave/s3.tf",
			Mode:    0644,
			Content: tofuModuleEnclaveS3,
		},
		{
			RelPath: "enclave/tofu/modules/enclave/vpc.tf",
			Mode:    0644,
			Content: tofuModuleEnclaveVPC,
		},
		{
			RelPath: "enclave/tofu/modules/enclave/ec2.tf",
			Mode:    0644,
			Content: tofuModuleEnclaveEC2,
		},
		// OpenTofu backend bootstrap module.
		{
			RelPath: "enclave/tofu/modules/backend/main.tf",
			Mode:    0644,
			Content: tofuModuleBackendMain,
		},
		{
			RelPath: "enclave/tofu/modules/backend/variables.tf",
			Mode:    0644,
			Content: tofuModuleBackendVariables,
		},
		{
			RelPath: "enclave/tofu/modules/backend/outputs.tf",
			Mode:    0644,
			Content: tofuModuleBackendOutputs,
		},
		// State migration script.
		{
			RelPath: "enclave/tofu/migrate-state.sh",
			Mode:    0755,
			Content: tofuMigrateState,
		},
		{
			RelPath: ".github/workflows/deploy-enclave.yml",
			Mode:    0644,
			Content: frameworkDeployWorkflow,
		},
		{
			RelPath: ".github/workflows/destroy-enclave.yml",
			Mode:    0644,
			Content: frameworkDestroyWorkflow,
		},
		{
			RelPath: ".github/workflows/verify-enclave.yml",
			Mode:    0644,
			Content: frameworkVerifyWorkflow,
		},
		{
			RelPath: ".github/workflows/build-eif.yml",
			Mode:    0644,
			Content: frameworkBuildEIFWorkflow,
		},
		{
			RelPath: "enclave/.gitignore",
			Mode:    0644,
			Content: frameworkGitignore,
		},
		{
			RelPath: "enclave/dokploy/docker-compose.yml",
			Mode:    0644,
			Content: frameworkDokployCompose,
		},
		{
			RelPath: "enclave/dokploy/seed.yaml",
			Mode:    0644,
			Content: frameworkDokploySeedYaml,
		},
	}
}

// Gitignore for the enclave/ subdirectory — excludes build artifacts and generated files.
const frameworkGitignore = `# Build artifacts (EIF image + PCR measurements)
artifacts/

# Generated build config (from enclave.yaml for Nix)
build-config.json

# OpenTofu state and outputs (contains account-specific IDs)
tofu-outputs.json
terraform.tfvars.json
terraform.tfstate
terraform.tfstate.backup
.terraform/

# Nix build symlinks
result
result-*
`

// EIF entrypoint — starts viproxy, nitriding, and the app binary.
const frameworkStartSh = `#!/bin/sh

set -e

# Seed kernel entropy pool from Nitro Security Module (NSM).
# The enclave starts with an empty entropy pool and /dev/random blocks until
# entropy is available. The SDK bypasses this via direct NSM calls, but user
# apps that read from /dev/random or /dev/urandom (e.g. OpenSSL, libsodium)
# will hang without seeding.
if [ -e /dev/nsm ]; then
  dd if=/dev/nsm of=/dev/urandom bs=256 count=1 2>/dev/null || true
  dd if=/dev/nsm of=/dev/random  bs=256 count=1 2>/dev/null || true
fi

# Start viproxy for IMDS access before nitriding sets up full networking
if [ "${ENCLAVE_VIPROXY_ENABLED:-true}" = "true" ]; then
  VIPROXY_IN_ADDRS="${ENCLAVE_VIPROXY_IN_ADDRS:-127.0.0.1:80}"
  VIPROXY_OUT_ADDRS="${ENCLAVE_VIPROXY_OUT_ADDRS:-3:8002}"
  IN_ADDRS="${VIPROXY_IN_ADDRS}" OUT_ADDRS="${VIPROXY_OUT_ADDRS}" /app/proxy &
  if [ -z "${AWS_EC2_METADATA_SERVICE_ENDPOINT:-}" ]; then
    export AWS_EC2_METADATA_SERVICE_ENDPOINT="http://127.0.0.1:80"
  fi
fi

export ENCLAVE_NO_TLS=true

# The AWS SDK needs a region. Inside the enclave, IMDS region detection
# may fail, so we set it explicitly from the deployment config.
if [ -z "${AWS_DEFAULT_REGION:-}" ]; then
  export AWS_DEFAULT_REGION="${ENCLAVE_AWS_REGION:-us-east-1}"
fi
APP_PORT="${ENCLAVE_PROXY_PORT:-7073}"
NITRIDING_EXT_PORT="${ENCLAVE_NITRIDING_EXT_PORT:-443}"
NITRIDING_INT_PORT="${ENCLAVE_NITRIDING_INT_PORT:-8080}"
NITRIDING_PROM_PORT="${ENCLAVE_NITRIDING_PROM_PORT:-9090}"
NITRIDING_PROM_NS="${ENCLAVE_NITRIDING_PROM_NAMESPACE:-enclave}"
NITRIDING_FQDN="${ENCLAVE_NITRIDING_FQDN:-localhost}"

NITRIDING_ARGS="-fqdn ${NITRIDING_FQDN} \
  -ext-pub-port ${NITRIDING_EXT_PORT} \
  -intport ${NITRIDING_INT_PORT} \
  -appwebsrv http://127.0.0.1:${APP_PORT} \
  -prometheus-namespace ${NITRIDING_PROM_NS} \
  -prometheus-port ${NITRIDING_PROM_PORT}"

if [ "${ENCLAVE_NITRIDING_DEBUG:-false}" = "true" ]; then
  NITRIDING_ARGS="${NITRIDING_ARGS} -debug"
fi

# Configure DNS to use gvproxy gateway
echo "nameserver 192.168.127.1" > /etc/resolv.conf

# Start nitriding in background (it will set up networking via gvproxy)
exec /app/nitriding ${NITRIDING_ARGS} -appcmd "/app/enclave-supervisor"
`

// Gvproxy entrypoint — starts gvproxy and sets up port forwarding.
const frameworkGvproxyStartSh = `#!/usr/bin/env sh
# Based on the gvproxy wrapper from the Nitro Enclave reference project.

set -e
set -x

VSOCK_SOCKET="${GVPROXY_SOCKET:-/tmp/network.sock}"
FORWARD_PORTS="${GVPROXY_FORWARD_PORTS:-${ENCLAVE_PORT:-7073}}"

setup_forward() {
  local_port=$1
  remote_port=$2
  curl --unix-socket "${VSOCK_SOCKET}" http:/unix/services/forwarder/expose \
    -X POST \
    -d "{\"local\":\":${local_port}\",\"remote\":\"192.168.127.2:${remote_port}\"}"
}

# Avoid "address already in use" if the socket is left behind.
if [ -S "${VSOCK_SOCKET}" ]; then
  rm -f "${VSOCK_SOCKET}"
fi

# Start gvproxy in the background.
GVPROXY_BIN="${GVPROXY_BIN:-/home/ec2-user/app/gvproxy/gvproxy}"
"${GVPROXY_BIN}" -listen vsock://:1024 -listen unix://"${VSOCK_SOCKET}" &
GVPROXY_PID=$!

# Wait for gvproxy to start.
sleep 5

for port in ${FORWARD_PORTS}; do
  setup_forward "${port}" "${port}"
done

wait "${GVPROXY_PID}"
`

// Host-side script — starts the Nitro Enclave and polls until it exits.
const frameworkEnclaveInitSh = `#!/bin/sh
# Starts the Nitro Enclave and polls until it exits.
# Designed to run under systemd with Restart=always.
set -eu

NITRO_CLI="${NITRO_CLI_PATH:-/usr/bin/nitro-cli}"
ENCLAVE_NAME="${ENCLAVE_NAME:-app}"
EIF_PATH="${EIF_PATH:-/home/ec2-user/app/server/signing_server.eif}"
CPU_COUNT="${CPU_COUNT:-2}"
MEMORY_MIB="${MEMORY_MIB:-4320}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
POLL_INTERVAL="${POLL_INTERVAL_SECONDS:-5}"
DEBUG_FLAG=""

if [ "${DEBUG_MODE:-false}" = "true" ]; then
  DEBUG_FLAG="--debug-mode"
fi

echo "starting enclave '${ENCLAVE_NAME}'"

$NITRO_CLI run-enclave \
  --cpu-count "$CPU_COUNT" \
  --memory "$MEMORY_MIB" \
  --eif-path "$EIF_PATH" \
  --enclave-cid "$ENCLAVE_CID" \
  --enclave-name "$ENCLAVE_NAME" \
  $DEBUG_FLAG

# Poll until the enclave stops running.
while $NITRO_CLI describe-enclaves \
  | grep -q "\"EnclaveName\": \"${ENCLAVE_NAME}\""; do
  sleep "$POLL_INTERVAL"
done

echo "enclave '${ENCLAVE_NAME}' is no longer running"
`

// Systemd unit — enclave lifecycle watchdog.
const frameworkWatchdogService = `#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
[Unit]
Description=Nitro Enclaves Init Service
After=network-online.target
DefaultDependencies=no
Requires=nitro-enclaves-allocator.service
After=nitro-enclaves-allocator.service

[Service]
EnvironmentFile=/etc/environment
Type=simple
StandardOutput=journal
StandardError=journal
ExecStart=/home/ec2-user/app/enclave_init.sh
ExecStop=/usr/bin/nitro-cli terminate-enclave --enclave-name app
Restart=always

[Install]
WantedBy=multi-user.target
`

// Systemd unit — vsock proxy for IMDS access from inside the enclave.
const frameworkIMDSProxyService = `#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
[Unit]
Description=Nitro Enclaves vsock IMDS Proxy
After=network-online.target
DefaultDependencies=no

[Service]
Type=simple
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vsock-proxy-imds
ExecStart=/bin/bash -ce "exec /usr/bin/vsock-proxy 8002 169.254.169.254 80 \
                --config /etc/nitro_enclaves/vsock-proxy.yaml \
                -w 5"
Restart=always
TimeoutSec=0

[Install]
WantedBy=multi-user.target
`

// Systemd unit — gvproxy binary for outbound networking.
const frameworkGvproxyService = `[Unit]
Description=gvproxy outbound networking for Nitro Enclave
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gvproxy
EnvironmentFile=/etc/environment
ExecStart=/home/ec2-user/app/gvproxy/start.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`

// Systemd unit — management server for health monitoring and guarded teardown.
const frameworkMgmtService = `[Unit]
Description=Enclave management server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
StandardOutput=journal
StandardError=journal
SyslogIdentifier=enclave-mgmt
EnvironmentFile=/etc/environment
ExecStart=/home/ec2-user/app/enclave-mgmt
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`

// EC2 user_data cloud-init — installs dependencies, downloads EIF, configures services.
// Template variables (e.g. ${region}) are resolved by OpenTofu templatefile() at deploy time.
// Shell variables use $$ escaping to avoid OpenTofu interpolation.
const frameworkUserData = `Content-Type: multipart/mixed; boundary="//"
MIME-Version: 1.0

--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"

#cloud-config
bootcmd:
  - [ dnf, install, aws-nitro-enclaves-cli, aws-nitro-enclaves-cli-devel, htop, git, jq, unzip, -y ]

--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"

#!/bin/bash

exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1

set -x
set +e

usermod -aG docker ec2-user
usermod -aG ne ec2-user

ALLOCATOR_YAML=/etc/nitro_enclaves/allocator.yaml
MEM_KEY=memory_mib
CPU_KEY=cpu_count
DEFAULT_MEM=6144
DEFAULT_CPU=2

sed -r "s/^(\s*$MEM_KEY\s*:\s*).*/\1$DEFAULT_MEM/" -i "$ALLOCATOR_YAML"
sed -r "s/^(\s*$CPU_KEY\s*:\s*).*/\1$DEFAULT_CPU/" -i "$ALLOCATOR_YAML"

VSOCK_PROXY_YAML=/etc/nitro_enclaves/vsock-proxy.yaml
cat <<EOF > $VSOCK_PROXY_YAML
allowlist:
- {address: kms.${region}.amazonaws.com, port: 443}
- {address: kms-fips.${region}.amazonaws.com, port: 443}
- {address: ssm.${region}.amazonaws.com, port: 443}
- {address: ssm-fips.${region}.amazonaws.com, port: 443}
- {address: sts.${region}.amazonaws.com, port: 443}
- {address: s3.${region}.amazonaws.com, port: 443}
- {address: 169.254.169.254, port: 80}

EOF

systemctl enable --now docker
systemctl enable --now nitro-enclaves-allocator.service
systemctl enable --now nitro-enclaves-vsock-proxy.service

cd /home/ec2-user

if [[ ! -d ./app/server ]]; then
  mkdir -p ./app/server
  chown -R ec2-user:ec2-user ./app
fi

# Wait for IAM policy to propagate before downloading from S3.
# The inline policy depends on the KMS key, so it may be created after the
# EC2 instance boots. IAM is eventually consistent — retry until it works.
for attempt in 1 2 3 4 5 6; do
  aws s3 cp ${eif_s3_url} /home/ec2-user/app/server/enclave.eif && break
  echo "S3 download failed (attempt $attempt), waiting for IAM propagation..."
  sleep 10
done
chmod 644 /home/ec2-user/app/server/enclave.eif
chown ec2-user:ec2-user /home/ec2-user/app/server/enclave.eif

# Download gvproxy binary and start script for outbound networking
aws s3 cp ${gvproxy_binary_s3_url} /home/ec2-user/app/gvproxy/gvproxy
aws s3 cp ${gvproxy_start_script_s3_url} /home/ec2-user/app/gvproxy/start.sh
chmod +x /home/ec2-user/app/gvproxy/gvproxy
chmod +x /home/ec2-user/app/gvproxy/start.sh
chown -R ec2-user:ec2-user /home/ec2-user/app/gvproxy

aws s3 cp ${enclave_init_s3_url} /home/ec2-user/app/enclave_init.sh
chmod +x /home/ec2-user/app/enclave_init.sh

aws s3 cp ${enclave_init_systemd_s3_url} /etc/systemd/system/enclave-watchdog.service
aws s3 cp ${imds_systemd_s3_url} /etc/systemd/system/enclave-imds-proxy.service
aws s3 cp ${gvproxy_systemd_s3_url} /etc/systemd/system/gvproxy.service

# Download management server binary and systemd unit
aws s3 cp ${mgmt_binary_s3_url} /home/ec2-user/app/enclave-mgmt
chmod +x /home/ec2-user/app/enclave-mgmt
chown ec2-user:ec2-user /home/ec2-user/app/enclave-mgmt
aws s3 cp ${mgmt_systemd_s3_url} /etc/systemd/system/enclave-mgmt.service

cat <<EOF >> /etc/environment
ENCLAVE_APP_NAME=${app_name}
EIF_PATH=/home/ec2-user/app/server/enclave.eif
ENCLAVE_NITRIDING_ENABLED=true
ENCLAVE_NITRIDING_FQDN=example.com
ENCLAVE_KMS_KEY_ID=${kms_key_id}
ENCLAVE_DEPLOYMENT=${dev_mode}
ENCLAVE_AWS_REGION=${region}
ENCLAVE_MIGRATION_COOLDOWN=${migration_cooldown}
ENCLAVE_PREVIOUS_PCR0=${previous_pcr0}
MEMORY_MIB=4320
CPU_COUNT=2
GVPROXY_FORWARD_PORTS=443 7073
EOF

systemctl enable --now enclave-watchdog.service
systemctl enable --now enclave-imds-proxy.service
systemctl enable --now gvproxy.service
systemctl enable --now enclave-mgmt.service
--//--
`

// Nix flake for reproducible EIF builds.
const frameworkFlakeNix = `{
  description = "Nitro Enclave - reproducible build";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    aws-nitro-util.url = "github:monzo/aws-nitro-util";
  };

  outputs = { self, nixpkgs, flake-utils, aws-nitro-util }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        eifPkgs = if system == "x86_64-linux" then pkgs
                  else import nixpkgs { system = "x86_64-linux"; };
        nitro = aws-nitro-util.lib.x86_64-linux;

        # Read build config generated by ` + "`" + `enclave build` + "`" + ` from enclave.yaml.
        # BUILD_CONFIG_PATH is set by the CLI; defaults to /src/enclave/build-config.json (Docker).
        # Requires --impure flag (already set by the CLI).
        configPath = let p = builtins.getEnv "BUILD_CONFIG_PATH"; in
          if p != "" then p else "/src/enclave/build-config.json";
        buildCfg = builtins.fromJSON (builtins.readFile configPath);
        appCfg = buildCfg.app;
        sdkCfg = buildCfg.sdk;

        # Fall back to env vars for backwards compatibility.
        version = buildCfg.version;
        region = buildCfg.region;
        deployment = buildCfg.prefix;

        # Enclave supervisor — built from the SDK repo.
        # Handles attestation, secrets, PCR extension, reverse proxy with
        # signing middleware. The user's app is just a plain HTTP server.
        enclave-supervisor = eifPkgs.buildGoModule {
          pname = "enclave-supervisor";
          version = buildCfg.version;

          src = eifPkgs.fetchFromGitHub {
            owner = "ArkLabsHQ";
            repo = "introspector-enclave";
            rev = sdkCfg.rev;
            hash = sdkCfg.hash;
          };

          sourceRoot = "source/sdk";
          vendorHash = sdkCfg.vendor_hash;
          subPackages = [ "cmd/enclave-supervisor" ];
          env.CGO_ENABLED = "0";
          ldflags = [
            "-X" "github.com/ArkLabsHQ/introspector-enclave/sdk.Version=` + "${version}" + `"
          ];
          buildFlags = [ "-trimpath" ];
          tags = [ "netgo" ];
          doCheck = false;
        };

        # User's app — fetched from GitHub. No SDK dependency needed.
        upstream-app = eifPkgs.buildGoModule ({
          pname = appCfg.binary_name;
          version = buildCfg.version;

          src = eifPkgs.fetchFromGitHub {
            owner = appCfg.nix_owner;
            repo = appCfg.nix_repo;
            rev = appCfg.nix_rev;
            hash = appCfg.nix_hash;
          };

          vendorHash = if appCfg.nix_vendor_hash == "" then null else appCfg.nix_vendor_hash;
          proxyVendor = true;

          subPackages = appCfg.nix_sub_packages;
          env.CGO_ENABLED = "0";
          buildFlags = [ "-trimpath" ];
          tags = [ "netgo" ];
          doCheck = false;

          postInstall = ''
            # Rename whatever was built to the configured binary name.
            for f in $out/bin/*; do
              if [ "$(basename "$f")" != "` + "${appCfg.binary_name}" + `" ]; then
                mv "$f" "$out/bin/` + "${appCfg.binary_name}" + `"
              fi
            done
          '';
        } // (if (appCfg.nix_subdir or "") != "" then {
          sourceRoot = "source/` + "${appCfg.nix_subdir}" + `";
        } else {}));

        # Nitriding TLS termination daemon.
        nitriding = eifPkgs.buildGoModule {
          pname = "nitriding-daemon";
          version = "unstable-2024-01-01";

          src = eifPkgs.fetchFromGitHub {
            owner = "brave";
            repo = "nitriding-daemon";
            rev = "c8cb7248843c82a5d72ff6cdde90f4a4cf68c87f";
            hash = "sha256-0ww8ZcoUh3UgRJyhfEVwmjxk3tZv7exCw0VmftdnM7U=";
          };

          vendorHash = "sha256-B/1tbPfId6qgvaMwPF5w4gFkkkeoI+5k+x0jEvJxQus=";

          env.CGO_ENABLED = "0";
          buildFlags = [ "-trimpath" ];
          doCheck = false;

          postInstall = ''
            mv $out/bin/nitriding-daemon $out/bin/nitriding
          '';
        };

        # Viproxy for IMDS forwarding inside the enclave.
        viproxy = eifPkgs.buildGoModule {
          pname = "viproxy";
          version = "0.1.2";

          src = eifPkgs.fetchFromGitHub {
            owner = "brave";
            repo = "viproxy";
            rev = "v0.1.2";
            hash = "sha256-xcQCvl+/d7a3fdqDMEEIyP3c49l1bu7ptCG+RZ94Xws=";
          };

          vendorHash = "sha256-WOzeqHo1cG8USbGUm3OAEUgh3yKTamCaIL3FpsshnjI=";

          subPackages = [ "example" ];
          env.CGO_ENABLED = "0";

          postInstall = ''
            mv $out/bin/example $out/bin/proxy
          '';
        };

        # Assemble the /app directory with all binaries and scripts.
        appDir = eifPkgs.runCommand "enclave-app" { } ''
          mkdir -p $out/app/data
          cp ` + "${upstream-app}" + `/bin/` + "${appCfg.binary_name}" + ` $out/app/` + "${appCfg.binary_name}" + `
          cp ` + "${enclave-supervisor}" + `/bin/enclave-supervisor $out/app/enclave-supervisor
          cp ` + "${nitriding}" + `/bin/nitriding $out/app/nitriding
          cp ` + "${viproxy}" + `/bin/proxy $out/app/proxy
          install -m 0755 ` + "${./enclave/start.sh}" + ` $out/app/start.sh
        '';

        # Complete rootfs for the enclave.
        enclaveRootfs = eifPkgs.buildEnv {
          name = "enclave-rootfs";
          paths = [
            appDir
            eifPkgs.busybox    # provides /bin/sh and basic utils
            eifPkgs.cacert     # TLS CA certificates
          ];
          pathsToLink = [ "/" ];
        };

        # Secrets config JSON baked into the EIF for runtime discovery.
        secretsCfgJson = builtins.toJSON (buildCfg.secrets or []);

        # Environment variables for the enclave.
        # Standard vars + all app-specific vars from build-config.json.
        enclaveEnv = let
          appEnvLines = builtins.concatStringsSep "\n"
            (builtins.map (k: "` + "${k}" + `=` + "${builtins.getAttr k appCfg.env}" + `")
              (builtins.attrNames appCfg.env));
        in ''
          PATH=/app:/bin:/usr/bin
          SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
          AWS_REGION=` + "${region}" + `
          ENCLAVE_APP_NAME=` + "${buildCfg.name}" + `
          ENCLAVE_SECRETS_CONFIG=` + "${secretsCfgJson}" + `
          ENCLAVE_MIGRATION_COOLDOWN=` + "${buildCfg.migration_cooldown or \"0s\"}" + `
          ENCLAVE_PREVIOUS_PCR0=` + "${buildCfg.previous_pcr0 or \"genesis\"}" + `
          ENCLAVE_DEPLOYMENT=` + "${deployment}" + `
          ` + "${appEnvLines}" + `
        '';

        # Build EIF using monzo/aws-nitro-util (reproducible, no Docker).
        eif = nitro.buildEif {
          name = "` + "${buildCfg.name}" + `-enclave";
          inherit version;

          arch = "x86_64";
          kernel = nitro.blobs.x86_64.kernel;
          kernelConfig = nitro.blobs.x86_64.kernelConfig;
          nsmKo = nitro.blobs.x86_64.nsmKo;

          copyToRoot = enclaveRootfs;
          entrypoint = "/app/start.sh";
          env = enclaveEnv;
        };

        # Vendor hash check — used by enclave setup to discover the correct hash.
        vendor-hash-check = (eifPkgs.buildGoModule {
          pname = "vendor-hash-check";
          version = buildCfg.version;
          src = eifPkgs.fetchFromGitHub {
            owner = appCfg.nix_owner;
            repo = appCfg.nix_repo;
            rev = appCfg.nix_rev;
            hash = appCfg.nix_hash;
          };
          vendorHash = "";
          proxyVendor = true;
          subPackages = appCfg.nix_sub_packages;
          env.CGO_ENABLED = "0";
          doCheck = false;
        } // (if (appCfg.nix_subdir or "") != "" then {
          sourceRoot = "source/` + "${appCfg.nix_subdir}" + `";
        } else {}));

      in
      {
        packages = {
          inherit upstream-app enclave-supervisor nitriding viproxy eif vendor-hash-check;
          default = eif;
        };
      }
    );
}
`

// Nix flake for Node.js apps — uses buildNpmPackage instead of buildGoModule.
const frameworkFlakeNixNodejs = `{
  description = "Nitro Enclave - reproducible build (Node.js)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    aws-nitro-util.url = "github:monzo/aws-nitro-util";
  };

  outputs = { self, nixpkgs, flake-utils, aws-nitro-util }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        eifPkgs = if system == "x86_64-linux" then pkgs
                  else import nixpkgs { system = "x86_64-linux"; };
        nitro = aws-nitro-util.lib.x86_64-linux;

        # Read build config generated by ` + "`" + `enclave build` + "`" + ` from enclave.yaml.
        # BUILD_CONFIG_PATH is set by the CLI; defaults to /src/enclave/build-config.json (Docker).
        # Requires --impure flag (already set by the CLI).
        configPath = let p = builtins.getEnv "BUILD_CONFIG_PATH"; in
          if p != "" then p else "/src/enclave/build-config.json";
        buildCfg = builtins.fromJSON (builtins.readFile configPath);
        appCfg = buildCfg.app;
        sdkCfg = buildCfg.sdk;

        # Fall back to env vars for backwards compatibility.
        version = buildCfg.version;
        region = buildCfg.region;
        deployment = buildCfg.prefix;

        # Enclave supervisor — built from the SDK repo.
        # Handles attestation, secrets, PCR extension, reverse proxy with
        # signing middleware. The user's app is just a plain HTTP server.
        enclave-supervisor = eifPkgs.buildGoModule {
          pname = "enclave-supervisor";
          version = buildCfg.version;

          src = eifPkgs.fetchFromGitHub {
            owner = "ArkLabsHQ";
            repo = "introspector-enclave";
            rev = sdkCfg.rev;
            hash = sdkCfg.hash;
          };

          sourceRoot = "source/sdk";
          vendorHash = sdkCfg.vendor_hash;
          subPackages = [ "cmd/enclave-supervisor" ];
          env.CGO_ENABLED = "0";
          ldflags = [
            "-X" "github.com/ArkLabsHQ/introspector-enclave/sdk.Version=` + "${version}" + `"
          ];
          buildFlags = [ "-trimpath" ];
          tags = [ "netgo" ];
          doCheck = false;
        };

        # Node.js runtime for the enclave.
        nodejs = eifPkgs.nodejs_22;

        # User's Node.js app — fetched from GitHub. No SDK dependency needed.
        upstream-app = eifPkgs.buildNpmPackage ({
          pname = appCfg.binary_name;
          version = buildCfg.version;

          src = eifPkgs.fetchFromGitHub {
            owner = appCfg.nix_owner;
            repo = appCfg.nix_repo;
            rev = appCfg.nix_rev;
            hash = appCfg.nix_hash;
          };

          npmDepsHash = if appCfg.nix_vendor_hash == "" then null else appCfg.nix_vendor_hash;
          dontNpmBuild = true;
          doCheck = false;
        } // (if (appCfg.nix_subdir or "") != "" then {
          sourceRoot = "source/` + "${appCfg.nix_subdir}" + `";
        } else {}));

        # Nitriding TLS termination daemon.
        nitriding = eifPkgs.buildGoModule {
          pname = "nitriding-daemon";
          version = "unstable-2024-01-01";

          src = eifPkgs.fetchFromGitHub {
            owner = "brave";
            repo = "nitriding-daemon";
            rev = "c8cb7248843c82a5d72ff6cdde90f4a4cf68c87f";
            hash = "sha256-0ww8ZcoUh3UgRJyhfEVwmjxk3tZv7exCw0VmftdnM7U=";
          };

          vendorHash = "sha256-B/1tbPfId6qgvaMwPF5w4gFkkkeoI+5k+x0jEvJxQus=";

          env.CGO_ENABLED = "0";
          buildFlags = [ "-trimpath" ];
          doCheck = false;

          postInstall = ''
            mv $out/bin/nitriding-daemon $out/bin/nitriding
          '';
        };

        # Viproxy for IMDS forwarding inside the enclave.
        viproxy = eifPkgs.buildGoModule {
          pname = "viproxy";
          version = "0.1.2";

          src = eifPkgs.fetchFromGitHub {
            owner = "brave";
            repo = "viproxy";
            rev = "v0.1.2";
            hash = "sha256-xcQCvl+/d7a3fdqDMEEIyP3c49l1bu7ptCG+RZ94Xws=";
          };

          vendorHash = "sha256-WOzeqHo1cG8USbGUm3OAEUgh3yKTamCaIL3FpsshnjI=";

          subPackages = [ "example" ];
          env.CGO_ENABLED = "0";

          postInstall = ''
            mv $out/bin/example $out/bin/proxy
          '';
        };

        # Assemble the /app directory with all binaries, scripts, and Node.js app.
        appDir = eifPkgs.runCommand "enclave-app" { } ''
          mkdir -p $out/app/data $out/app/src

          # Copy Node.js app from buildNpmPackage output.
          # The output lives under lib/node_modules/<package-json-name>/.
          # Use a wildcard so it works regardless of the package name.
          for dir in ` + "${upstream-app}" + `/lib/node_modules/*/; do
            cp -r "$dir"/* $out/app/src/
          done

          # Create launcher script that the supervisor will exec.
          cat > $out/app/` + "${appCfg.binary_name}" + ` <<'LAUNCHER'
#!/bin/sh
exec node /app/src/index.js "$@"
LAUNCHER
          chmod +x $out/app/` + "${appCfg.binary_name}" + `

          cp ` + "${enclave-supervisor}" + `/bin/enclave-supervisor $out/app/enclave-supervisor
          cp ` + "${nitriding}" + `/bin/nitriding $out/app/nitriding
          cp ` + "${viproxy}" + `/bin/proxy $out/app/proxy
          install -m 0755 ` + "${./enclave/start.sh}" + ` $out/app/start.sh
        '';

        # Complete rootfs for the enclave — includes Node.js runtime.
        enclaveRootfs = eifPkgs.buildEnv {
          name = "enclave-rootfs";
          paths = [
            appDir
            nodejs          # Node.js runtime
            eifPkgs.busybox    # provides /bin/sh and basic utils
            eifPkgs.cacert     # TLS CA certificates
          ];
          pathsToLink = [ "/" ];
        };

        # Secrets config JSON baked into the EIF for runtime discovery.
        secretsCfgJson = builtins.toJSON (buildCfg.secrets or []);

        # Environment variables for the enclave.
        # Standard vars + all app-specific vars from build-config.json.
        enclaveEnv = let
          appEnvLines = builtins.concatStringsSep "\n"
            (builtins.map (k: "` + "${k}" + `=` + "${builtins.getAttr k appCfg.env}" + `")
              (builtins.attrNames appCfg.env));
        in ''
          PATH=/app:/bin:/usr/bin
          SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
          AWS_REGION=` + "${region}" + `
          ENCLAVE_APP_NAME=` + "${buildCfg.name}" + `
          ENCLAVE_SECRETS_CONFIG=` + "${secretsCfgJson}" + `
          ENCLAVE_MIGRATION_COOLDOWN=` + "${buildCfg.migration_cooldown or \"0s\"}" + `
          ENCLAVE_PREVIOUS_PCR0=` + "${buildCfg.previous_pcr0 or \"genesis\"}" + `
          ENCLAVE_DEPLOYMENT=` + "${deployment}" + `
          ` + "${appEnvLines}" + `
        '';

        # Build EIF using monzo/aws-nitro-util (reproducible, no Docker).
        eif = nitro.buildEif {
          name = "` + "${buildCfg.name}" + `-enclave";
          inherit version;

          arch = "x86_64";
          kernel = nitro.blobs.x86_64.kernel;
          kernelConfig = nitro.blobs.x86_64.kernelConfig;
          nsmKo = nitro.blobs.x86_64.nsmKo;

          copyToRoot = enclaveRootfs;
          entrypoint = "/app/start.sh";
          env = enclaveEnv;
        };

        # Vendor hash check — used by enclave setup to discover the correct hash.
        vendor-hash-check = (eifPkgs.buildNpmPackage {
          pname = "vendor-hash-check";
          version = buildCfg.version;
          src = eifPkgs.fetchFromGitHub {
            owner = appCfg.nix_owner;
            repo = appCfg.nix_repo;
            rev = appCfg.nix_rev;
            hash = appCfg.nix_hash;
          };
          npmDepsHash = "";
          dontNpmBuild = true;
          doCheck = false;
        }) // (if (appCfg.nix_subdir or "") != "" then {
          sourceRoot = "source/` + "${appCfg.nix_subdir}" + `";
        } else {}));

      in
      {
        packages = {
          inherit upstream-app enclave-supervisor nitriding viproxy eif vendor-hash-check;
          default = eif;
        };
      }
    );
}
`

// GitHub Actions workflow — deploy enclave via OIDC-authenticated AWS credentials,
// then verify attestation and publish results to GitHub Pages.
// Users must set repo variables AWS_ROLE_ARN and AWS_REGION, and configure an
// OIDC identity provider in AWS IAM for token.actions.githubusercontent.com.
const frameworkDeployWorkflow = `name: Deploy Enclave

on:
  workflow_dispatch:

permissions:
  id-token: write
  contents: write
  attestations: write

# Required repo variables:
#   AWS_ROLE_ARN  - IAM role ARN with OIDC trust policy for this repo
#   AWS_REGION    - AWS region (e.g. us-east-1)

jobs:
  deploy:
    runs-on: ubuntu-latest
    if: vars.AWS_ROLE_ARN != ''
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: 'stable'

      - name: Install enclave CLI
        run: go install github.com/ArkLabsHQ/introspector-enclave/cmd/enclave@latest

      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ` + "${{ vars.AWS_ROLE_ARN }}" + `
          aws-region: ` + "${{ vars.AWS_REGION }}" + `

      - name: Install OpenTofu
        uses: opentofu/setup-opentofu@v1

      - name: Pull Nix Docker image
        run: docker pull nixos/nix:2.24.9

      - name: Build and deploy
        id: deploy
        run: |
          ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
          sed -i "s/^account: .*/account: \"${ACCOUNT_ID}\"/" enclave/enclave.yaml
          enclave build
          cd enclave/tofu
          tofu init
          tofu apply -auto-approve

          # Extract deployment outputs for manifest and verification.
          pcr0=$(jq -r '.PCR0' enclave/artifacts/pcr.json)
          pcr1=$(jq -r '.PCR1' enclave/artifacts/pcr.json)
          pcr2=$(jq -r '.PCR2' enclave/artifacts/pcr.json)
          echo "pcr0=${pcr0}" >> "$GITHUB_OUTPUT"
          echo "pcr1=${pcr1}" >> "$GITHUB_OUTPUT"
          echo "pcr2=${pcr2}" >> "$GITHUB_OUTPUT"

      - name: Publish deployment manifest
        continue-on-error: true
        env:
          PCR0: ` + "${{ steps.deploy.outputs.pcr0 }}" + `
          PCR1: ` + "${{ steps.deploy.outputs.pcr1 }}" + `
          PCR2: ` + "${{ steps.deploy.outputs.pcr2 }}" + `
          ELASTIC_IP: ` + "${{ steps.deploy.outputs.elastic_ip }}" + `
          REPO: ` + "${{ github.repository }}" + `
          COMMIT_SHA: ` + "${{ github.sha }}" + `
          GH_TOKEN: ` + "${{ github.token }}" + `
        run: |
          TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
          TAG="deploy-$(date -u +%Y%m%d-%H%M%S)"

          jq -n \
            --arg base_url "https://${ELASTIC_IP}" \
            --arg pcr0 "$PCR0" \
            --arg pcr1 "$PCR1" \
            --arg pcr2 "$PCR2" \
            --arg timestamp "$TIMESTAMP" \
            --arg commit "$COMMIT_SHA" \
            --arg repo "$REPO" \
            '{base_url: $base_url, pcr0: $pcr0, pcr1: $pcr1, pcr2: $pcr2, timestamp: $timestamp, commit: $commit, repo: $repo}' \
            > deployment.json

          # Create a timestamped release with the manifest attached.
          cat > /tmp/release-notes.md <<NOTES
          Deployed at ${TIMESTAMP} from commit ${COMMIT_SHA}.

          **Elastic IP:** ${ELASTIC_IP}
          **PCR0:** ${PCR0}
          NOTES
          gh release create "$TAG" deployment.json \
            --title "Deploy ${TAG}" \
            --notes-file /tmp/release-notes.md

          # Update the 'latest' release so clients can always fetch the
          # current manifest at releases/download/latest/deployment.json.
          gh release delete latest --yes 2>/dev/null || true
          git push origin :refs/tags/latest 2>/dev/null || true
          cat > /tmp/latest-notes.md <<NOTES
          Current production deployment. Updated by each deploy.

          **Elastic IP:** ${ELASTIC_IP}
          **PCR0:** ${PCR0}
          **Deployed:** ${TIMESTAMP}
          **Commit:** ${COMMIT_SHA}
          NOTES
          gh release create latest deployment.json \
            --title "Latest Deployment" \
            --notes-file /tmp/latest-notes.md

      - name: Attest deployment manifest
        if: steps.deploy.outputs.elastic_ip != ''
        continue-on-error: true
        uses: actions/attest-build-provenance@v3
        with:
          subject-path: deployment.json

      - name: Attest PCR measurements
        continue-on-error: true
        uses: actions/attest-build-provenance@v3
        with:
          subject-path: enclave/artifacts/pcr.json

      - name: Attestation verification instructions
        if: steps.deploy.outputs.elastic_ip != ''
        run: |
          echo "## Artifact Attestations" >> "$GITHUB_STEP_SUMMARY"
          echo "" >> "$GITHUB_STEP_SUMMARY"
          echo "Verify deployment manifest provenance:" >> "$GITHUB_STEP_SUMMARY"
          echo '` + "```" + `' >> "$GITHUB_STEP_SUMMARY"
          echo "gh attestation verify deployment.json --repo ` + "${{ github.repository }}" + `" >> "$GITHUB_STEP_SUMMARY"
          echo '` + "```" + `' >> "$GITHUB_STEP_SUMMARY"

      - name: Display PCR measurements
        run: |
          echo "## PCR Measurements" >> "$GITHUB_STEP_SUMMARY"
          echo '` + "```" + `json' >> "$GITHUB_STEP_SUMMARY"
          cat enclave/artifacts/pcr.json >> "$GITHUB_STEP_SUMMARY"
          echo '` + "```" + `' >> "$GITHUB_STEP_SUMMARY"

      - name: Verify attestation
        id: verify
        run: |
          pcr0="` + "${{ steps.deploy.outputs.pcr0 }}" + `"

          output=$(enclave verify \
            --base-url "https://` + "${{ steps.deploy.outputs.elastic_ip }}" + `" \
            --expected-pcr0 "${pcr0}" \
            --wait 300 2>&1) && status="pass" || status="fail"

          echo "status=${status}" >> "$GITHUB_OUTPUT"
          echo "output<<EOF" >> "$GITHUB_OUTPUT"
          echo "${output}" >> "$GITHUB_OUTPUT"
          echo "EOF" >> "$GITHUB_OUTPUT"

          echo "## Enclave Verification" >> "$GITHUB_STEP_SUMMARY"
          echo "- **Status:** ${status}" >> "$GITHUB_STEP_SUMMARY"
          echo "- **PCR0:** ${pcr0}" >> "$GITHUB_STEP_SUMMARY"
          echo '` + "```" + `' >> "$GITHUB_STEP_SUMMARY"
          echo "${output}" >> "$GITHUB_STEP_SUMMARY"
          echo '` + "```" + `' >> "$GITHUB_STEP_SUMMARY"

          if [ "${status}" = "fail" ]; then
            exit 1
          fi

      - name: Generate attestation status page
        if: always() && steps.verify.outcome != 'skipped'
        env:
          VERIFY_STATUS: ` + "${{ steps.verify.outputs.status || 'unknown' }}" + `
          VERIFY_PCR0: ` + "${{ steps.deploy.outputs.pcr0 || '' }}" + `
          VERIFY_PCR1: ` + "${{ steps.deploy.outputs.pcr1 || '' }}" + `
          VERIFY_PCR2: ` + "${{ steps.deploy.outputs.pcr2 || '' }}" + `
          VERIFY_OUTPUT: ` + "${{ steps.verify.outputs.output || '' }}" + `
          REPO: ` + "${{ github.repository }}" + `
          COMMIT_SHA: ` + "${{ github.sha }}" + `
        run: |
          mkdir -p _site
          cat > _site/index.html <<'HTMLEOF'
          <!DOCTYPE html>
          <html lang="en">
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Enclave Attestation</title>
            <style>
              body { font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
              h1 { font-size: 1.4rem; }
              .status { padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; display: inline-block; margin: 0.5rem 0; }
              .pass { background: #d4edda; color: #155724; }
              .fail { background: #f8d7da; color: #721c24; }
              .unknown { background: #fff3cd; color: #856404; }
              table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
              th, td { text-align: left; padding: 0.5rem; border-bottom: 1px solid #ddd; }
              th { font-weight: 600; width: 100px; }
              td { font-family: monospace; font-size: 0.85rem; word-break: break-all; }
              pre { background: #f5f5f5; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; }
              .meta { color: #666; font-size: 0.85rem; }
            </style>
          </head>
          <body>
            <h1>Enclave Attestation</h1>
            <div id="status"></div>
            <table id="pcr-table"></table>
            <h2>Verification Output</h2>
            <pre id="output"></pre>
            <p class="meta">Last verified: <span id="timestamp"></span></p>
            <p class="meta">Source: <a id="repo-link" href="#"></a></p>
            <script>
              fetch('status.json').then(r => r.json()).then(d => {
                const labels = { pass: 'Verified', fail: 'FAILED', unknown: 'Unknown' };
                document.getElementById('status').innerHTML =
                  '<span class="status ' + d.status + '">' + (labels[d.status] || d.status) + '</span>';
                const rows = [['PCR0', d.pcr0], ['PCR1', d.pcr1], ['PCR2', d.pcr2]];
                document.getElementById('pcr-table').innerHTML =
                  rows.map(function(r) { return '<tr><th>' + r[0] + '</th><td>' + (r[1] || 'N/A') + '</td></tr>'; }).join('');
                document.getElementById('output').textContent = d.output;
                document.getElementById('timestamp').textContent = d.timestamp;
                var link = document.getElementById('repo-link');
                link.href = 'https://github.com/' + d.repo;
                link.textContent = d.repo;
              });
            </script>
          </body>
          </html>
          HTMLEOF

          jq -n \
            --arg status "$VERIFY_STATUS" \
            --arg pcr0 "$VERIFY_PCR0" \
            --arg pcr1 "$VERIFY_PCR1" \
            --arg pcr2 "$VERIFY_PCR2" \
            --arg output "$VERIFY_OUTPUT" \
            --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --arg commit "$COMMIT_SHA" \
            --arg repo "$REPO" \
            '{status: $status, pcr0: $pcr0, pcr1: $pcr1, pcr2: $pcr2, output: $output, timestamp: $timestamp, commit: $commit, repo: $repo}' \
            > _site/status.json

      - name: Deploy to gh-pages branch
        if: always() && steps.verify.outcome != 'skipped'
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"

          # Save generated status page before discarding local changes.
          cp -r _site /tmp/_site

          # Discard all local modifications (e.g. sed on enclave.yaml, build
          # artifacts, flake.lock) so we can cleanly switch branches.
          git reset --hard HEAD
          git clean -fd

          if ! git ls-remote --exit-code --heads origin gh-pages > /dev/null 2>&1; then
            git checkout --orphan gh-pages
            git rm -rf .
          else
            git fetch origin gh-pages
            git checkout gh-pages
          fi

          mkdir -p attestation
          cp /tmp/_site/index.html attestation/
          cp /tmp/_site/status.json attestation/
          git add attestation/index.html attestation/status.json
          git diff --cached --quiet && exit 0
          git commit -m "update attestation status"
          git push origin gh-pages
`

// GitHub Actions workflow — destroy enclave infrastructure via OIDC-authenticated AWS credentials.
const frameworkDestroyWorkflow = `name: Destroy Enclave

on:
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

# Same repo variables as deploy:
#   AWS_ROLE_ARN  - IAM role ARN with OIDC trust policy
#   AWS_REGION    - AWS region

jobs:
  destroy:
    runs-on: ubuntu-latest
    if: vars.AWS_ROLE_ARN != ''
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: 'stable'

      - name: Install enclave CLI
        run: go install github.com/ArkLabsHQ/introspector-enclave/cmd/enclave@latest

      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ` + "${{ vars.AWS_ROLE_ARN }}" + `
          aws-region: ` + "${{ vars.AWS_REGION }}" + `

      - name: Destroy infrastructure
        run: |
          cd enclave/tofu
          tofu init
          tofu destroy -auto-approve
`

// Nix flake for .NET apps — uses buildDotnetModule with self-contained publish.
const frameworkFlakeNixDotnet = `{
  description = "Nitro Enclave - reproducible build (.NET)";

  inputs = {
    # Pinned nixpkgs commit for reproducible .NET SDK version.
    # Update deliberately with: nix flake update nixpkgs
    nixpkgs.url = "github:NixOS/nixpkgs/e38213b91d3786389a446dfce4ff5a8aaf6012f2";
    flake-utils.url = "github:numtide/flake-utils";
    aws-nitro-util.url = "github:monzo/aws-nitro-util";
  };

  outputs = { self, nixpkgs, flake-utils, aws-nitro-util }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        eifPkgs = if system == "x86_64-linux" then pkgs
                  else import nixpkgs { system = "x86_64-linux"; };
        nitro = aws-nitro-util.lib.x86_64-linux;

        # Read build config generated by ` + "`" + `enclave build` + "`" + ` from enclave.yaml.
        configPath = let p = builtins.getEnv "BUILD_CONFIG_PATH"; in
          if p != "" then p else "/src/enclave/build-config.json";
        buildCfg = builtins.fromJSON (builtins.readFile configPath);
        appCfg = buildCfg.app;
        sdkCfg = buildCfg.sdk;

        version = buildCfg.version;
        region = buildCfg.region;
        deployment = buildCfg.prefix;

        # Enclave supervisor — built from the SDK repo.
        enclave-supervisor = eifPkgs.buildGoModule {
          pname = "enclave-supervisor";
          version = buildCfg.version;

          src = eifPkgs.fetchFromGitHub {
            owner = "ArkLabsHQ";
            repo = "introspector-enclave";
            rev = sdkCfg.rev;
            hash = sdkCfg.hash;
          };

          sourceRoot = "source/sdk";
          vendorHash = sdkCfg.vendor_hash;
          subPackages = [ "cmd/enclave-supervisor" ];
          env.CGO_ENABLED = "0";
          ldflags = [
            "-X" "github.com/ArkLabsHQ/introspector-enclave/sdk.Version=` + "${version}" + `"
          ];
          buildFlags = [ "-trimpath" ];
          tags = [ "netgo" ];
          doCheck = false;
        };

        # User's .NET app — fetched from GitHub. No SDK dependency needed.
        upstream-app = eifPkgs.buildDotnetModule ({
          pname = appCfg.binary_name;
          version = buildCfg.version;

          src = eifPkgs.fetchFromGitHub {
            owner = appCfg.nix_owner;
            repo = appCfg.nix_repo;
            rev = appCfg.nix_rev;
            hash = appCfg.nix_hash;
          };

          # Pinned SDK feature band for reproducible builds.
          # sdk_10_0_1xx locks to 10.0.1xx (won't jump to 10.0.2xx+).
          dotnet-sdk = eifPkgs.dotnetCorePackages.sdk_10_0_1xx;
          dotnet-runtime = eifPkgs.dotnetCorePackages.aspnetcore_10_0;

          projectFile = appCfg.nix_project_file;
          nugetDeps = ./deps.json;

          selfContainedBuild = true;
          executables = [ appCfg.binary_name ];

          # Native AOT: produces a single statically-linked binary (like Go).
          # Eliminates 300+ runtime DLLs and removes JIT/IL non-determinism.
          dotnetBuildFlags = [ "/p:PublishAot=true" "/p:StripSymbols=true" ];
          dotnetPublishFlags = [ "/p:PublishAot=true" "/p:StripSymbols=true" ];

          doCheck = false;
        } // (if (appCfg.nix_subdir or "") != "" then {
          sourceRoot = "source/` + "${appCfg.nix_subdir}" + `";
        } else {}));

        # Nitriding TLS termination daemon.
        nitriding = eifPkgs.buildGoModule {
          pname = "nitriding-daemon";
          version = "unstable-2024-01-01";

          src = eifPkgs.fetchFromGitHub {
            owner = "brave";
            repo = "nitriding-daemon";
            rev = "c8cb7248843c82a5d72ff6cdde90f4a4cf68c87f";
            hash = "sha256-0ww8ZcoUh3UgRJyhfEVwmjxk3tZv7exCw0VmftdnM7U=";
          };

          vendorHash = "sha256-B/1tbPfId6qgvaMwPF5w4gFkkkeoI+5k+x0jEvJxQus=";

          env.CGO_ENABLED = "0";
          buildFlags = [ "-trimpath" ];
          doCheck = false;

          postInstall = ''
            mv $out/bin/nitriding-daemon $out/bin/nitriding
          '';
        };

        # Viproxy for IMDS forwarding inside the enclave.
        viproxy = eifPkgs.buildGoModule {
          pname = "viproxy";
          version = "0.1.2";

          src = eifPkgs.fetchFromGitHub {
            owner = "brave";
            repo = "viproxy";
            rev = "v0.1.2";
            hash = "sha256-xcQCvl+/d7a3fdqDMEEIyP3c49l1bu7ptCG+RZ94Xws=";
          };

          vendorHash = "sha256-WOzeqHo1cG8USbGUm3OAEUgh3yKTamCaIL3FpsshnjI=";

          subPackages = [ "example" ];
          env.CGO_ENABLED = "0";

          postInstall = ''
            mv $out/bin/example $out/bin/proxy
          '';
        };

        # Assemble the /app directory with all binaries and scripts.
        appDir = eifPkgs.runCommand "enclave-app" { } ''
          mkdir -p $out/app/data

          # With Native AOT: bin/ contains a real statically-linked native binary.
          # Without AOT: bin/ has a wrapper, lib/<name>/ has the DLL-based app.
          if [ -f "` + "${upstream-app}" + `/lib/` + "${appCfg.binary_name}" + `/` + "${appCfg.binary_name}" + `" ]; then
            # Non-AOT: copy from lib/ (the real binary + runtime DLLs).
            cp -r ` + "${upstream-app}" + `/lib/` + "${appCfg.binary_name}" + `/* $out/app/
          else
            # AOT: single native binary in bin/.
            cp ` + "${upstream-app}" + `/bin/` + "${appCfg.binary_name}" + ` $out/app/` + "${appCfg.binary_name}" + `
          fi
          chmod +x $out/app/` + "${appCfg.binary_name}" + `

          cp ` + "${enclave-supervisor}" + `/bin/enclave-supervisor $out/app/enclave-supervisor
          cp ` + "${nitriding}" + `/bin/nitriding $out/app/nitriding
          cp ` + "${viproxy}" + `/bin/proxy $out/app/proxy
          install -m 0755 ` + "${./enclave/start.sh}" + ` $out/app/start.sh
        '';

        # Complete rootfs for the enclave — includes ICU for .NET globalization.
        enclaveRootfs = eifPkgs.buildEnv {
          name = "enclave-rootfs";
          paths = [
            appDir
            eifPkgs.busybox    # provides /bin/sh and basic utils
            eifPkgs.cacert     # TLS CA certificates
            pkgs.icu        # ICU globalization data for .NET
          ];
          pathsToLink = [ "/" ];
        };

        # Secrets config JSON baked into the EIF for runtime discovery.
        secretsCfgJson = builtins.toJSON (buildCfg.secrets or []);

        # Environment variables for the enclave.
        enclaveEnv = let
          appEnvLines = builtins.concatStringsSep "\n"
            (builtins.map (k: "` + "${k}" + `=` + "${builtins.getAttr k appCfg.env}" + `")
              (builtins.attrNames appCfg.env));
        in ''
          PATH=/app:/bin:/usr/bin
          SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
          AWS_REGION=` + "${region}" + `
          ENCLAVE_APP_NAME=` + "${buildCfg.name}" + `
          ENCLAVE_SECRETS_CONFIG=` + "${secretsCfgJson}" + `
          ENCLAVE_MIGRATION_COOLDOWN=` + "${buildCfg.migration_cooldown or \"0s\"}" + `
          ENCLAVE_PREVIOUS_PCR0=` + "${buildCfg.previous_pcr0 or \"genesis\"}" + `
          ENCLAVE_DEPLOYMENT=` + "${deployment}" + `
          DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false
          ` + "${appEnvLines}" + `
        '';

        # Build EIF using monzo/aws-nitro-util (reproducible, no Docker).
        eif = nitro.buildEif {
          name = "` + "${buildCfg.name}" + `-enclave";
          inherit version;

          arch = "x86_64";
          kernel = nitro.blobs.x86_64.kernel;
          kernelConfig = nitro.blobs.x86_64.kernelConfig;
          nsmKo = nitro.blobs.x86_64.nsmKo;

          copyToRoot = enclaveRootfs;
          entrypoint = "/app/start.sh";
          env = enclaveEnv;
        };

        # Vendor hash check — used by enclave setup to discover the correct hash.
        # .NET uses fetch-deps for deps.json — no hash-based vendor check.
        vendor-hash-check = eifPkgs.runCommand "vendor-hash-check-noop" {} "echo noop > $out";

      in
      {
        packages = {
          inherit upstream-app enclave-supervisor nitriding viproxy eif vendor-hash-check;
          default = eif;
        };
      }
    );
}
`

// Nix flake for Rust apps — uses rustPlatform.buildRustPackage.
const frameworkFlakeNixRust = `{
  description = "Nitro Enclave - reproducible build (Rust)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    aws-nitro-util.url = "github:monzo/aws-nitro-util";
  };

  outputs = { self, nixpkgs, flake-utils, aws-nitro-util }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        eifPkgs = if system == "x86_64-linux" then pkgs
                  else import nixpkgs { system = "x86_64-linux"; };
        nitro = aws-nitro-util.lib.x86_64-linux;

        configPath = let p = builtins.getEnv "BUILD_CONFIG_PATH"; in
          if p != "" then p else "/src/enclave/build-config.json";
        buildCfg = builtins.fromJSON (builtins.readFile configPath);
        appCfg = buildCfg.app;
        sdkCfg = buildCfg.sdk;

        version = buildCfg.version;
        region = buildCfg.region;
        deployment = buildCfg.prefix;

        # Enclave supervisor — built from the SDK repo.
        enclave-supervisor = eifPkgs.buildGoModule {
          pname = "enclave-supervisor";
          version = buildCfg.version;

          src = eifPkgs.fetchFromGitHub {
            owner = "ArkLabsHQ";
            repo = "introspector-enclave";
            rev = sdkCfg.rev;
            hash = sdkCfg.hash;
          };

          sourceRoot = "source/sdk";
          vendorHash = sdkCfg.vendor_hash;
          subPackages = [ "cmd/enclave-supervisor" ];
          env.CGO_ENABLED = "0";
          ldflags = [
            "-X" "github.com/ArkLabsHQ/introspector-enclave/sdk.Version=` + "${version}" + `"
          ];
          buildFlags = [ "-trimpath" ];
          tags = [ "netgo" ];
          doCheck = false;
        };

        # User's Rust app — fetched from GitHub. No SDK dependency needed.
        upstream-app = eifPkgs.rustPlatform.buildRustPackage ({
          pname = appCfg.binary_name;
          version = buildCfg.version;

          src = eifPkgs.fetchFromGitHub {
            owner = appCfg.nix_owner;
            repo = appCfg.nix_repo;
            rev = appCfg.nix_rev;
            hash = appCfg.nix_hash;
          };

          cargoHash = if appCfg.nix_vendor_hash == "" then "" else appCfg.nix_vendor_hash;

          doCheck = false;

          postInstall = ''
            # Rename whatever was built to the configured binary name.
            for f in $out/bin/*; do
              if [ "$(basename "$f")" != "` + "${appCfg.binary_name}" + `" ]; then
                mv "$f" "$out/bin/` + "${appCfg.binary_name}" + `"
              fi
            done
          '';
        } // (if (appCfg.nix_subdir or "") != "" then {
          sourceRoot = "source";
          cargoRoot = appCfg.nix_subdir;
          buildAndTestSubdir = appCfg.nix_subdir;
        } else {}));

        nitriding = eifPkgs.buildGoModule {
          pname = "nitriding-daemon";
          version = "unstable-2024-01-01";

          src = eifPkgs.fetchFromGitHub {
            owner = "brave";
            repo = "nitriding-daemon";
            rev = "c8cb7248843c82a5d72ff6cdde90f4a4cf68c87f";
            hash = "sha256-0ww8ZcoUh3UgRJyhfEVwmjxk3tZv7exCw0VmftdnM7U=";
          };

          vendorHash = "sha256-B/1tbPfId6qgvaMwPF5w4gFkkkeoI+5k+x0jEvJxQus=";

          env.CGO_ENABLED = "0";
          buildFlags = [ "-trimpath" ];
          doCheck = false;

          postInstall = ''
            mv $out/bin/nitriding-daemon $out/bin/nitriding
          '';
        };

        viproxy = eifPkgs.buildGoModule {
          pname = "viproxy";
          version = "0.1.2";

          src = eifPkgs.fetchFromGitHub {
            owner = "brave";
            repo = "viproxy";
            rev = "v0.1.2";
            hash = "sha256-xcQCvl+/d7a3fdqDMEEIyP3c49l1bu7ptCG+RZ94Xws=";
          };

          vendorHash = "sha256-WOzeqHo1cG8USbGUm3OAEUgh3yKTamCaIL3FpsshnjI=";

          subPackages = [ "example" ];
          env.CGO_ENABLED = "0";

          postInstall = ''
            mv $out/bin/example $out/bin/proxy
          '';
        };

        appDir = eifPkgs.runCommand "enclave-app" { } ''
          mkdir -p $out/app/data
          cp ` + "${upstream-app}" + `/bin/` + "${appCfg.binary_name}" + ` $out/app/` + "${appCfg.binary_name}" + `
          cp ` + "${enclave-supervisor}" + `/bin/enclave-supervisor $out/app/enclave-supervisor
          cp ` + "${nitriding}" + `/bin/nitriding $out/app/nitriding
          cp ` + "${viproxy}" + `/bin/proxy $out/app/proxy
          install -m 0755 ` + "${./enclave/start.sh}" + ` $out/app/start.sh
        '';

        enclaveRootfs = eifPkgs.buildEnv {
          name = "enclave-rootfs";
          paths = [
            appDir
            eifPkgs.busybox
            eifPkgs.cacert
          ];
          pathsToLink = [ "/" ];
        };

        secretsCfgJson = builtins.toJSON (buildCfg.secrets or []);

        enclaveEnv = let
          appEnvLines = builtins.concatStringsSep "\n"
            (builtins.map (k: "` + "${k}" + `=` + "${builtins.getAttr k appCfg.env}" + `")
              (builtins.attrNames appCfg.env));
        in ''
          PATH=/app:/bin:/usr/bin
          SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
          AWS_REGION=` + "${region}" + `
          ENCLAVE_APP_NAME=` + "${buildCfg.name}" + `
          ENCLAVE_SECRETS_CONFIG=` + "${secretsCfgJson}" + `
          ENCLAVE_MIGRATION_COOLDOWN=` + "${buildCfg.migration_cooldown or \"0s\"}" + `
          ENCLAVE_PREVIOUS_PCR0=` + "${buildCfg.previous_pcr0 or \"genesis\"}" + `
          ENCLAVE_DEPLOYMENT=` + "${deployment}" + `
          ` + "${appEnvLines}" + `
        '';

        eif = nitro.buildEif {
          name = "` + "${buildCfg.name}" + `-enclave";
          inherit version;

          arch = "x86_64";
          kernel = nitro.blobs.x86_64.kernel;
          kernelConfig = nitro.blobs.x86_64.kernelConfig;
          nsmKo = nitro.blobs.x86_64.nsmKo;

          copyToRoot = enclaveRootfs;
          entrypoint = "/app/start.sh";
          env = enclaveEnv;
        };

        # Vendor hash check — used by enclave setup to discover the correct hash.
        vendor-hash-check = (eifPkgs.rustPlatform.buildRustPackage {
          pname = "vendor-hash-check";
          version = buildCfg.version;
          src = eifPkgs.fetchFromGitHub {
            owner = appCfg.nix_owner;
            repo = appCfg.nix_repo;
            rev = appCfg.nix_rev;
            hash = appCfg.nix_hash;
          };
          cargoHash = "";
          doCheck = false;
        }) // (if (appCfg.nix_subdir or "") != "" then {
          sourceRoot = "source/` + "${appCfg.nix_subdir}" + `";
          cargoRoot = appCfg.nix_subdir;
          buildAndTestSubdir = appCfg.nix_subdir;
        } else {}));

      in
      {
        packages = {
          inherit upstream-app enclave-supervisor nitriding viproxy eif vendor-hash-check;
          default = eif;
        };
      }
    );
}
`

// GitHub Actions workflow — daily enclave attestation verification.
// Fetches the deployment manifest from GitHub Releases, verifies the
// running enclave matches the expected PCR0, and publishes results
// to GitHub Pages.
const frameworkVerifyWorkflow = `name: Verify Enclave

on:
  schedule:
    - cron: '0 8 * * *'  # Every day at 8:00 UTC
  workflow_dispatch:

permissions:
  contents: write

# Verification inputs (base_url, PCR values) are read from the
# deployment manifest published by the deploy workflow. If base_url
# is not in the manifest (e.g. build-only), set the ENCLAVE_BASE_URL
# repository variable as a fallback.

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: stable

      - name: Install enclave CLI
        run: go install github.com/ArkLabsHQ/introspector-enclave/cmd/enclave@latest

      - name: Fetch deployment manifest
        id: manifest
        env:
          GH_TOKEN: ` + "${{ github.token }}" + `
        run: |
          gh release download latest -p deployment.json || {
            echo "No deployment manifest found. Run the deploy workflow first."
            exit 1
          }

          base_url=$(jq -r '.base_url // empty' deployment.json)
          pcr0=$(jq -r '.pcr0' deployment.json)
          pcr1=$(jq -r '.pcr1' deployment.json)
          pcr2=$(jq -r '.pcr2' deployment.json)
          echo "base_url=${base_url}" >> "$GITHUB_OUTPUT"
          echo "pcr0=${pcr0}" >> "$GITHUB_OUTPUT"
          echo "pcr1=${pcr1}" >> "$GITHUB_OUTPUT"
          echo "pcr2=${pcr2}" >> "$GITHUB_OUTPUT"

      - name: Verify attestation
        id: verify
        if: steps.manifest.outputs.base_url != '' || vars.ENCLAVE_BASE_URL != ''
        env:
          BASE_URL: ` + "${{ steps.manifest.outputs.base_url || vars.ENCLAVE_BASE_URL }}" + `
          PCR0: ` + "${{ steps.manifest.outputs.pcr0 }}" + `
        run: |
          output=$(enclave verify \
            --base-url "${BASE_URL}" \
            --expected-pcr0 "${PCR0}" \
            --wait 60 2>&1) && status="pass" || status="fail"

          echo "status=${status}" >> "$GITHUB_OUTPUT"
          echo "output<<EOF" >> "$GITHUB_OUTPUT"
          echo "${output}" >> "$GITHUB_OUTPUT"
          echo "EOF" >> "$GITHUB_OUTPUT"

          echo "## Enclave Verification" >> "$GITHUB_STEP_SUMMARY"
          echo "- **Status:** ${status}" >> "$GITHUB_STEP_SUMMARY"
          echo "- **PCR0:** ${PCR0}" >> "$GITHUB_STEP_SUMMARY"
          echo '` + "```" + `' >> "$GITHUB_STEP_SUMMARY"
          echo "${output}" >> "$GITHUB_STEP_SUMMARY"
          echo '` + "```" + `' >> "$GITHUB_STEP_SUMMARY"

      - name: Generate attestation status page
        if: always() && steps.verify.outcome != 'skipped'
        env:
          VERIFY_STATUS: ` + "${{ steps.verify.outputs.status || 'unknown' }}" + `
          VERIFY_PCR0: ` + "${{ steps.manifest.outputs.pcr0 || '' }}" + `
          VERIFY_PCR1: ` + "${{ steps.manifest.outputs.pcr1 || '' }}" + `
          VERIFY_PCR2: ` + "${{ steps.manifest.outputs.pcr2 || '' }}" + `
          VERIFY_OUTPUT: ` + "${{ steps.verify.outputs.output || '' }}" + `
          REPO: ` + "${{ github.repository }}" + `
          COMMIT_SHA: ` + "${{ github.sha }}" + `
        run: |
          mkdir -p _site
          cat > _site/index.html <<'HTMLEOF'
          <!DOCTYPE html>
          <html lang="en">
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Enclave Attestation</title>
            <style>
              body { font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
              h1 { font-size: 1.4rem; }
              .status { padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; display: inline-block; margin: 0.5rem 0; }
              .pass { background: #d4edda; color: #155724; }
              .fail { background: #f8d7da; color: #721c24; }
              .unknown { background: #fff3cd; color: #856404; }
              table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
              th, td { text-align: left; padding: 0.5rem; border-bottom: 1px solid #ddd; }
              th { font-weight: 600; width: 100px; }
              td { font-family: monospace; font-size: 0.85rem; word-break: break-all; }
              pre { background: #f5f5f5; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; }
              .meta { color: #666; font-size: 0.85rem; }
            </style>
          </head>
          <body>
            <h1>Enclave Attestation</h1>
            <div id="status"></div>
            <table id="pcr-table"></table>
            <h2>Verification Output</h2>
            <pre id="output"></pre>
            <p class="meta">Last verified: <span id="timestamp"></span></p>
            <p class="meta">Source: <a id="repo-link" href="#"></a></p>
            <script>
              fetch('status.json').then(r => r.json()).then(d => {
                const labels = { pass: 'Verified', fail: 'FAILED', unknown: 'Unknown' };
                document.getElementById('status').innerHTML =
                  '<span class="status ' + d.status + '">' + (labels[d.status] || d.status) + '</span>';
                const rows = [['PCR0', d.pcr0], ['PCR1', d.pcr1], ['PCR2', d.pcr2]];
                document.getElementById('pcr-table').innerHTML =
                  rows.map(function(r) { return '<tr><th>' + r[0] + '</th><td>' + (r[1] || 'N/A') + '</td></tr>'; }).join('');
                document.getElementById('output').textContent = d.output;
                document.getElementById('timestamp').textContent = d.timestamp;
                var link = document.getElementById('repo-link');
                link.href = 'https://github.com/' + d.repo;
                link.textContent = d.repo;
              });
            </script>
          </body>
          </html>
          HTMLEOF

          jq -n \
            --arg status "$VERIFY_STATUS" \
            --arg pcr0 "$VERIFY_PCR0" \
            --arg pcr1 "$VERIFY_PCR1" \
            --arg pcr2 "$VERIFY_PCR2" \
            --arg output "$VERIFY_OUTPUT" \
            --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --arg commit "$COMMIT_SHA" \
            --arg repo "$REPO" \
            '{status: $status, pcr0: $pcr0, pcr1: $pcr1, pcr2: $pcr2, output: $output, timestamp: $timestamp, commit: $commit, repo: $repo}' \
            > _site/status.json

      - name: Deploy to gh-pages branch
        if: always() && steps.verify.outcome != 'skipped'
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"

          cp -r _site /tmp/_site

          git reset --hard HEAD
          git clean -fd

          if ! git ls-remote --exit-code --heads origin gh-pages > /dev/null 2>&1; then
            git checkout --orphan gh-pages
            git rm -rf .
          else
            git fetch origin gh-pages
            git checkout gh-pages
          fi

          mkdir -p attestation
          cp /tmp/_site/index.html attestation/
          cp /tmp/_site/status.json attestation/
          git add attestation/index.html attestation/status.json
          git diff --cached --quiet && exit 0
          git commit -m "update attestation status"
          git push origin gh-pages
`

// GitHub Actions workflow — builds the EIF and uploads to a GitHub Release.
// Triggered on push when enclave-related files change, or manually.
// Dokploy (or any CI/CD tool) can pull the EIF from the "eif-latest" release
// to run QEMU enclave tests on a bare metal instance without needing Nix locally.
const frameworkBuildEIFWorkflow = `name: Build EIF

on:
  push:
    branches: [master, main]
    paths:
      - 'enclave/**'
      - 'flake.nix'
      - 'flake.lock'
  workflow_dispatch:

permissions:
  contents: write

jobs:
  build-eif:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: stable

      - name: Install enclave CLI
        run: go install github.com/ArkLabsHQ/introspector-enclave/cmd/enclave@latest

      - name: Pull Nix Docker image
        run: docker pull nixos/nix:2.24.9

      - name: Build EIF
        run: enclave build

      - name: Extract PCR values
        id: pcr
        run: |
          PCR0=$(jq -r '.PCR0 // .pcr0' enclave/artifacts/pcr.json)
          echo "pcr0=${PCR0}" >> "$GITHUB_OUTPUT"
          echo "PCR0: ${PCR0:0:32}..."

      - name: Upload EIF artifact
        uses: actions/upload-artifact@v4
        with:
          name: enclave-eif
          path: |
            enclave/artifacts/image.eif
            enclave/artifacts/pcr.json
            enclave/artifacts/enclave-mgmt
            enclave/artifacts/gvproxy
          retention-days: 7

      - name: Upload to latest release
        env:
          GH_TOKEN: ` + "${{ github.token }}" + `
          PCR0: ` + "${{ steps.pcr.outputs.pcr0 }}" + `
          COMMIT_SHA: ` + "${{ github.sha }}" + `
        run: |
          TAG="eif-latest"
          gh release delete "$TAG" --yes 2>/dev/null || true
          gh release create "$TAG" \
            --title "EIF (latest)" \
            --notes "Auto-built EIF from commit ${COMMIT_SHA::8}
          PCR0: ${PCR0}" \
            --prerelease \
            enclave/artifacts/image.eif \
            enclave/artifacts/pcr.json \
            enclave/artifacts/enclave-mgmt \
            enclave/artifacts/gvproxy

      - name: Publish build manifest
        continue-on-error: true
        env:
          GH_TOKEN: ` + "${{ github.token }}" + `
          REPO: ` + "${{ github.repository }}" + `
          COMMIT_SHA: ` + "${{ github.sha }}" + `
        run: |
          PCR0=$(jq -r '.PCR0 // .pcr0' enclave/artifacts/pcr.json)
          PCR1=$(jq -r '.PCR1 // .pcr1' enclave/artifacts/pcr.json)
          PCR2=$(jq -r '.PCR2 // .pcr2' enclave/artifacts/pcr.json)
          TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
          TAG="build-$(date -u +%Y%m%d-%H%M%S)"

          jq -n \
            --arg pcr0 "$PCR0" \
            --arg pcr1 "$PCR1" \
            --arg pcr2 "$PCR2" \
            --arg timestamp "$TIMESTAMP" \
            --arg commit "$COMMIT_SHA" \
            --arg repo "$REPO" \
            '{pcr0: $pcr0, pcr1: $pcr1, pcr2: $pcr2, timestamp: $timestamp, commit: $commit, repo: $repo}' \
            > deployment.json

          # Create a timestamped build release with the manifest.
          gh release create "$TAG" deployment.json \
            --title "Build ${TAG}" \
            --notes "Build manifest from commit ${COMMIT_SHA::8}
          **PCR0:** ${PCR0}"

          # Update the 'latest' release so the verify workflow can find it.
          # Only update if no deploy manifest exists yet (deploy takes precedence).
          if ! gh release view latest --json assets -q '.assets[].name' 2>/dev/null | grep -q deployment.json; then
            gh release delete latest --yes 2>/dev/null || true
            git push origin :refs/tags/latest 2>/dev/null || true
            gh release create latest deployment.json \
              --title "Latest Build" \
              --notes "Build manifest (no deploy yet). Updated by each build.

          **PCR0:** ${PCR0}
          **Built:** ${TIMESTAMP}
          **Commit:** ${COMMIT_SHA}"
          fi
`

const frameworkDokployCompose = `# Dokploy-compatible compose file for local QEMU enclave deployment.
#
# Dokploy connects to the GitHub repo and deploys this stack on push.
# The EIF is downloaded automatically from the "eif-latest" GitHub Release
# (built by .github/workflows/build-eif.yml).
#
# Setup in Dokploy:
#   1. Create a "Compose" project
#   2. Connect to your GitHub repo
#   3. Set compose path: enclave/dokploy/docker-compose.yml
#   4. Set env var GITHUB_REPO (e.g. owner/repo)
#   5. Optionally set GITHUB_TOKEN for private repos
#   6. Deploy
#
# Manual usage:
#   GITHUB_REPO=owner/repo docker compose up

services:
  # --- EIF Downloader ---
  # Downloads the latest EIF from GitHub Releases before the enclave starts.
  eif-downloader:
    image: curlimages/curl:latest
    user: "0:0"
    volumes:
      - eif-artifacts:/artifacts
    environment:
      GITHUB_REPO: "${GITHUB_REPO}"
      GITHUB_TOKEN: "${GITHUB_TOKEN:-}"
    entrypoint: ["/bin/sh", "-c"]
    command:
      - |
        set -e
        echo "=== Downloading EIF from GitHub Releases ==="
        REPO="$${GITHUB_REPO}"
        TAG="eif-latest"

        if [ -n "$${GITHUB_TOKEN}" ]; then
          AUTH_HEADER="Authorization: token $${GITHUB_TOKEN}"
        else
          AUTH_HEADER="X-No-Auth: true"
        fi

        RELEASE_URL="https://api.github.com/repos/$${REPO}/releases/tags/$${TAG}"
        echo "  Fetching release: $${RELEASE_URL}"

        ASSETS=$(curl -sfL -H "$${AUTH_HEADER}" "$${RELEASE_URL}" | grep -o '"browser_download_url": *"[^"]*"' | cut -d'"' -f4)

        if [ -z "$${ASSETS}" ]; then
          echo "ERROR: No assets found in release $${TAG}"
          echo "Has the build-eif workflow run? Check: https://github.com/$${REPO}/releases/tag/$${TAG}"
          exit 1
        fi

        mkdir -p /artifacts
        for URL in $${ASSETS}; do
          FILENAME=$(basename "$${URL}")
          echo "  Downloading: $${FILENAME}"
          curl -sfL -H "$${AUTH_HEADER}" -o "/artifacts/$${FILENAME}" "$${URL}"
        done

        echo "  Downloaded:"
        ls -lh /artifacts/
        echo "=== EIF download complete ==="

  # --- Mock AWS Services ---

  local-kms:
    image: nsmithuk/local-kms
    ports:
      - "8080:8080"
    environment:
      KMS_REGION: us-east-1
      KMS_ACCOUNT_ID: "123456789012"
    volumes:
      - ./seed.yaml:/init/seed.yaml:ro
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:8080/ || exit 0"]
      interval: 5s
      timeout: 3s
      retries: 5
    restart: unless-stopped

  kms-proxy:
    image: ghcr.io/arklabshq/enclave-kms-proxy:latest
    ports:
      - "4000:4000"
    environment:
      UPSTREAM_KMS_URL: "http://local-kms:8080"
      LISTEN_ADDR: ":4000"
    depends_on:
      local-kms:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:4000/ || exit 0"]
      interval: 5s
      timeout: 3s
      retries: 5
    restart: unless-stopped

  localstack:
    image: localstack/localstack
    ports:
      - "4566:4566"
    environment:
      SERVICES: ssm,sts,s3,cloudformation,iam
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:4566/_localstack/health || exit 1"]
      interval: 5s
      timeout: 3s
      retries: 10
    restart: unless-stopped

  mock-imds:
    image: ghcr.io/arklabshq/enclave-mock-imds:latest
    ports:
      - "1338:1338"
    environment:
      LISTEN_ADDR: ":1338"
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:1338/latest/api/token || exit 0"]
      interval: 5s
      timeout: 3s
      retries: 5
    restart: unless-stopped

  # --- QEMU Enclave ---
  # Boots the EIF in QEMU with nitro-enclave emulation.
  # Requires privileged mode for KVM + vsock access.

  enclave:
    image: ghcr.io/arklabshq/enclave-runner:latest
    privileged: true
    network_mode: host
    devices:
      - /dev/kvm:/dev/kvm
      - /dev/vsock:/dev/vsock
    volumes:
      - eif-artifacts:/eif
    depends_on:
      eif-downloader:
        condition: service_completed_successfully
      localstack:
        condition: service_healthy
      mock-imds:
        condition: service_healthy
      kms-proxy:
        condition: service_healthy
    environment:
      BOOT_TIMEOUT: "120"
    command: ["boot-qemu.sh", "/eif/image.eif"]
    restart: unless-stopped

volumes:
  eif-artifacts:
`

const frameworkDokploySeedYaml = `# Default KMS seed for local development.
# local-kms loads this at startup to create a pre-seeded encryption key.
# Customize the KeyId and alias to match your enclave.yaml configuration.
Keys:
  Symmetric:
    Aes:
      - Metadata:
          KeyId: "test-key-id"
          Description: "Local development enclave key"
          KeyUsage: ENCRYPT_DECRYPT
        BackingKeys:
          - "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

Aliases:
  - AliasName: alias/test-enclave-key
    TargetKeyId: "test-key-id"
`
