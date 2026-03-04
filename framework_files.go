package introspector_enclave

import "os"

// frameworkFile describes a template file to scaffold during `enclave init`.
type frameworkFile struct {
	RelPath string      // path relative to user's project root
	Mode    os.FileMode // file permissions
	Content string      // file content
}

// getFrameworkFiles returns the list of framework files to scaffold.
// These are required by CDK deploy (cdk.go) and Nix build (flake.nix).
// The language parameter selects the correct flake.nix template.
func getFrameworkFiles(language string) []frameworkFile {
	flakeNix := frameworkFlakeNix // default: Go
	switch language {
	case "nodejs":
		flakeNix = frameworkFlakeNixNodejs
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
			RelPath: "enclave/gvproxy/Dockerfile",
			Mode:    0644,
			Content: frameworkGvproxyDockerfile,
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
			RelPath: "enclave/user_data/user_data",
			Mode:    0644,
			Content: frameworkUserData,
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
			RelPath: "enclave/.gitignore",
			Mode:    0644,
			Content: frameworkGitignore,
		},
	}
}

// Gitignore for the enclave/ subdirectory — excludes build artifacts and generated files.
const frameworkGitignore = `# Build artifacts (EIF image + PCR measurements)
artifacts/

# Generated build config (from enclave.yaml for Nix)
build-config.json

# CDK outputs (contains account-specific IDs)
cdk-outputs.json
cdk.out/

# Nix build symlinks
result
result-*
`

// EIF entrypoint — starts viproxy, nitriding, and the app binary.
const frameworkStartSh = `#!/bin/sh

set -e

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

// Gvproxy Docker image — builds gvproxy binary for forwarding ports into the enclave.
const frameworkGvproxyDockerfile = `# Gvproxy container for forwarding HTTP ports into the enclave.
FROM golang:1.25.5 AS builder

ARG GVPROXY_VERSION=v0.7.4
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go install github.com/containers/gvisor-tap-vsock/cmd/gvproxy@${GVPROXY_VERSION}

FROM alpine:3.20

RUN apk update && apk upgrade
RUN apk --no-cache add curl

WORKDIR /app

COPY --from=builder /go/bin/gvproxy /app/gvproxy
COPY enclave/gvproxy/start.sh /app/start.sh

CMD ["/app/start.sh"]
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
/app/gvproxy -listen vsock://:1024 -listen unix://"${VSOCK_SOCKET}" &
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

// Systemd unit — gvproxy Docker container for outbound networking.
const frameworkGvproxyService = `[Unit]
Description=Start gvproxy docker container on boot
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/bin/docker run --restart=unless-stopped -d --name gvproxy \
  --privileged --security-opt seccomp=unconfined \
  -e GVPROXY_FORWARD_PORTS="443 7073 9090" \
  -p 443:443 -p 7073:7073 -p 9090:9090 \
  gvproxy:latest
RemainAfterExit=yes

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
// Template variables (e.g. ${__REGION__}) are resolved by CDK Fn::Sub at deploy time.
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
- {address: kms.${__REGION__}.amazonaws.com, port: 443}
- {address: kms-fips.${__REGION__}.amazonaws.com, port: 443}
- {address: ssm.${__REGION__}.amazonaws.com, port: 443}
- {address: ssm-fips.${__REGION__}.amazonaws.com, port: 443}
- {address: sts.${__REGION__}.amazonaws.com, port: 443}
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

# Download pre-built EIF from S3 (built reproducibly with Nix)
aws s3 cp ${__EIF_S3_URL__} /home/ec2-user/app/server/enclave.eif
chmod 644 /home/ec2-user/app/server/enclave.eif
chown ec2-user:ec2-user /home/ec2-user/app/server/enclave.eif

# Pull gvproxy image for outbound networking
ACCOUNT_ID=$( aws sts get-caller-identity | jq -r '.Account' )
REGION=$(TOKEN=` + "`" + `curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` + "`" + ` && curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/placement/region)
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com
docker pull ${__GVPROXY_IMAGE_URI__}
docker tag ${__GVPROXY_IMAGE_URI__} gvproxy:latest

aws s3 cp ${__ENCLAVE_INIT_S3_URL__} /home/ec2-user/app/enclave_init.sh
chmod +x /home/ec2-user/app/enclave_init.sh

aws s3 cp ${__ENCLAVE_INIT_SYSTEMD_S3_URL__} /etc/systemd/system/enclave-watchdog.service
aws s3 cp ${__IMDS_SYSTEMD_S3_URL__} /etc/systemd/system/enclave-imds-proxy.service
aws s3 cp ${__GVPROXY_SYSTEMD_S3_URL__} /etc/systemd/system/gvproxy.service

# Download management server binary and systemd unit
aws s3 cp ${__MGMT_BINARY_S3_URL__} /home/ec2-user/app/enclave-mgmt
chmod +x /home/ec2-user/app/enclave-mgmt
chown ec2-user:ec2-user /home/ec2-user/app/enclave-mgmt
aws s3 cp ${__MGMT_SYSTEMD_S3_URL__} /etc/systemd/system/enclave-mgmt.service

cat <<EOF >> /etc/environment
ENCLAVE_APP_NAME=${__APP_NAME__}
EIF_PATH=/home/ec2-user/app/server/enclave.eif
ENCLAVE_NITRIDING_ENABLED=true
ENCLAVE_NITRIDING_FQDN=example.com
ENCLAVE_KMS_KEY_ID=${__KMS_KEY_ID__}
ENCLAVE_DEPLOYMENT=${__DEV_MODE__}
ENCLAVE_AWS_REGION=${__REGION__}
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
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    aws-nitro-util.url = "github:monzo/aws-nitro-util";
  };

  outputs = { self, nixpkgs, flake-utils, aws-nitro-util }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        nitro = aws-nitro-util.lib.` + "${system}" + `;

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
        enclave-supervisor = pkgs.buildGoModule {
          pname = "enclave-supervisor";
          version = buildCfg.version;

          src = pkgs.fetchFromGitHub {
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
        upstream-app = pkgs.buildGoModule {
          pname = appCfg.binary_name;
          version = buildCfg.version;

          src = pkgs.fetchFromGitHub {
            owner = appCfg.nix_owner;
            repo = appCfg.nix_repo;
            rev = appCfg.nix_rev;
            hash = appCfg.nix_hash;
          };

          vendorHash = appCfg.nix_vendor_hash;

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
        };

        # Nitriding TLS termination daemon.
        nitriding = pkgs.buildGoModule {
          pname = "nitriding-daemon";
          version = "unstable-2024-01-01";

          src = pkgs.fetchFromGitHub {
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
        viproxy = pkgs.buildGoModule {
          pname = "viproxy";
          version = "0.1.2";

          src = pkgs.fetchFromGitHub {
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
        appDir = pkgs.runCommand "enclave-app" { } ''
          mkdir -p $out/app/data
          cp ` + "${upstream-app}" + `/bin/` + "${appCfg.binary_name}" + ` $out/app/` + "${appCfg.binary_name}" + `
          cp ` + "${enclave-supervisor}" + `/bin/enclave-supervisor $out/app/enclave-supervisor
          cp ` + "${nitriding}" + `/bin/nitriding $out/app/nitriding
          cp ` + "${viproxy}" + `/bin/proxy $out/app/proxy
          install -m 0755 ` + "${./enclave/start.sh}" + ` $out/app/start.sh
        '';

        # Complete rootfs for the enclave.
        enclaveRootfs = pkgs.buildEnv {
          name = "enclave-rootfs";
          paths = [
            appDir
            pkgs.busybox    # provides /bin/sh and basic utils
            pkgs.cacert     # TLS CA certificates
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

      in
      {
        packages = {
          inherit upstream-app enclave-supervisor nitriding viproxy eif;
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
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    aws-nitro-util.url = "github:monzo/aws-nitro-util";
  };

  outputs = { self, nixpkgs, flake-utils, aws-nitro-util }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        nitro = aws-nitro-util.lib.` + "${system}" + `;

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
        enclave-supervisor = pkgs.buildGoModule {
          pname = "enclave-supervisor";
          version = buildCfg.version;

          src = pkgs.fetchFromGitHub {
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
        nodejs = pkgs.nodejs_22;

        # User's Node.js app — fetched from GitHub. No SDK dependency needed.
        upstream-app = pkgs.buildNpmPackage {
          pname = appCfg.binary_name;
          version = buildCfg.version;

          src = pkgs.fetchFromGitHub {
            owner = appCfg.nix_owner;
            repo = appCfg.nix_repo;
            rev = appCfg.nix_rev;
            hash = appCfg.nix_hash;
          };

          npmDepsHash = appCfg.nix_vendor_hash;
          dontNpmBuild = true;
          doCheck = false;
        };

        # Nitriding TLS termination daemon.
        nitriding = pkgs.buildGoModule {
          pname = "nitriding-daemon";
          version = "unstable-2024-01-01";

          src = pkgs.fetchFromGitHub {
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
        viproxy = pkgs.buildGoModule {
          pname = "viproxy";
          version = "0.1.2";

          src = pkgs.fetchFromGitHub {
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
        appDir = pkgs.runCommand "enclave-app" { } ''
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
        enclaveRootfs = pkgs.buildEnv {
          name = "enclave-rootfs";
          paths = [
            appDir
            nodejs          # Node.js runtime
            pkgs.busybox    # provides /bin/sh and basic utils
            pkgs.cacert     # TLS CA certificates
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

      in
      {
        packages = {
          inherit upstream-app enclave-supervisor nitriding viproxy eif;
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

      - name: Install AWS CDK
        run: npm install -g aws-cdk

      - name: Pull Nix Docker image
        run: docker pull nixos/nix:2.24.9

      - name: Build and deploy
        id: deploy
        run: |
          ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
          sed -i "s/^account: .*/account: \"${ACCOUNT_ID}\"/" enclave/enclave.yaml
          enclave build
          enclave deploy

          # Extract deployment outputs for manifest and verification.
          pcr0=$(jq -r '.PCR0' enclave/artifacts/pcr.json)
          pcr1=$(jq -r '.PCR1' enclave/artifacts/pcr.json)
          pcr2=$(jq -r '.PCR2' enclave/artifacts/pcr.json)
          echo "pcr0=${pcr0}" >> "$GITHUB_OUTPUT"
          echo "pcr1=${pcr1}" >> "$GITHUB_OUTPUT"
          echo "pcr2=${pcr2}" >> "$GITHUB_OUTPUT"

          # Extract Elastic IP from CDK outputs.
          elastic_ip=$(jq -r 'to_entries[0].value | .ElasticIP // .["Elastic IP"] // empty' enclave/cdk-outputs.json 2>/dev/null || echo "")
          echo "elastic_ip=${elastic_ip}" >> "$GITHUB_OUTPUT"

      - name: Publish deployment manifest
        if: steps.deploy.outputs.elastic_ip != ''
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

          # Discard any local modifications (e.g. sed on enclave.yaml, build
          # artifacts) so we can cleanly switch to the gh-pages branch.
          git stash --include-untracked

          if ! git ls-remote --exit-code --heads origin gh-pages > /dev/null 2>&1; then
            git checkout --orphan gh-pages
            git rm -rf .
          else
            git fetch origin gh-pages
            git checkout gh-pages
          fi

          mkdir -p attestation
          cp _site/index.html attestation/
          cp _site/status.json attestation/
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

      - name: Install AWS CDK
        run: npm install -g aws-cdk

      - name: Destroy stack
        run: |
          ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
          sed -i "s/^account: .*/account: \"${ACCOUNT_ID}\"/" enclave/enclave.yaml
          # CDK stack synthesis references asset paths (EIF + mgmt binary).
          # They must exist even for destroy. Empty placeholders are sufficient.
          mkdir -p enclave/artifacts
          touch enclave/artifacts/image.eif
          touch enclave/artifacts/enclave-mgmt
          enclave destroy --force
`

