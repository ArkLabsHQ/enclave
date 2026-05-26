package cli

import "os"

// frameworkFile describes a template file to scaffold during `enclave init`.
type frameworkFile struct {
	RelPath string      // path relative to user's project root
	Mode    os.FileMode // file permissions
	Content string      // file content
}

// getInitFiles returns the build-time framework files scaffolded by
// `enclave init`. Limited to Nix build inputs and CI workflow templates
// that are tied to the build (not deployment). The language parameter
// selects the correct flake.nix template.
//
// Deployment scaffolding (OpenTofu module) is emitted by `enclave tofu init`
// via getTofuFiles; splitting the two lets users customize one without
// inadvertently regenerating the other.
func getInitFiles(language string) []frameworkFile {
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
			RelPath: "enclave/flake.nix",
			Mode:    0644,
			Content: flakeNix,
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
	}
}

// getTofuFiles returns the OpenTofu module scaffolding emitted by
// `enclave tofu init`. Paths are relative to the repo root; the tree lives
// under ./tofu/ so it's independent of the enclave/ build inputs.
//
// The language parameter is currently unused (templates don't vary by
// language) but kept for parity with getInitFiles in case per-language
// defaults are introduced later.
func getTofuFiles(_ string) []frameworkFile {
	return []frameworkFile{
		{RelPath: "tofu/main.tf", Mode: 0644, Content: tofuRootMain},
		{RelPath: "tofu/.gitignore", Mode: 0644, Content: frameworkTofuGitignore},
		{RelPath: "tofu/modules/backend/main.tf", Mode: 0644, Content: tofuModuleBackendMain},
		{RelPath: "tofu/modules/enclave/main.tf", Mode: 0644, Content: tofuModuleEnclaveMain},
		{RelPath: "tofu/modules/enclave/templates/user_data.sh.tftpl", Mode: 0644, Content: frameworkUserData},
	}
}

// Gitignore for the tofu/ scaffold — hides account-specific state and
// generated files. Scaffolded by `enclave tofu init` alongside the module tree.
const frameworkTofuGitignore = `# OpenTofu state and outputs (contains account-specific IDs)
tofu-outputs.json
terraform.tfvars.json
terraform.tfstate
terraform.tfstate.backup
.terraform/
backend.tf
modules/enclave/.signing/
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

systemctl enable --now docker
systemctl enable --now nitro-enclaves-allocator.service

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

# Download supervisor binary. The supervisor owns the enclave lifecycle,
# the gvproxy virtual network, and the IMDS AF_VSOCK forwarder in-process
# — no separate gvproxy/watchdog/vsock-proxy services.
aws s3 cp ${supervisor_binary_s3_url} /home/ec2-user/app/supervisor
chmod +x /home/ec2-user/app/supervisor
chown ec2-user:ec2-user /home/ec2-user/app/supervisor

# The systemd unit is inlined here (not scaffolded into enclave/systemd/)
# so deployment concerns live with the tofu module that owns them.
# The heredoc delimiter is single-quoted so neither shell nor tofu
# interpolate the contents — the unit is copied verbatim.
cat <<'UNIT_EOF' > /etc/systemd/system/enclave-supervisor.service
[Unit]
Description=Enclave host supervisor (networking, IMDS, lifecycle, management API)
After=network-online.target nitro-enclaves-allocator.service
Wants=network-online.target
Requires=nitro-enclaves-allocator.service

[Service]
Type=simple
StandardOutput=journal
StandardError=journal
SyslogIdentifier=enclave-supervisor
EnvironmentFile=/etc/environment
ExecStart=/home/ec2-user/app/supervisor
ExecStop=/usr/bin/nitro-cli terminate-enclave --enclave-name app
Restart=always
RestartSec=5
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
UNIT_EOF

cat <<EOF >> /etc/environment
ENCLAVE_APP_NAME=${app_name}
EIF_PATH=/home/ec2-user/app/server/enclave.eif
ENCLAVE_NITRIDING_ENABLED=true
ENCLAVE_DEPLOYMENT=${dev_mode}
ENCLAVE_AWS_REGION=${region}
ENCLAVE_MIGRATION_COOLDOWN=${migration_cooldown}
MEMORY_MIB=4320
CPU_COUNT=2
GVPROXY_FORWARD_PORTS=443
EOF

systemctl enable --now enclave-supervisor.service
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
        # BUILD_CONFIG_PATH is set by the CLI; is set by the CLI as an absolute path.
        # Requires --impure flag (already set by the CLI).
        configPath = let p = builtins.getEnv "BUILD_CONFIG_PATH"; in
          if p != "" then p else "../.enclave/build-config.json";
        buildCfg = builtins.fromJSON (builtins.readFile configPath);
        appCfg = buildCfg.app;
        runtimeCfg = buildCfg.runtime;

        # Fall back to env vars for backwards compatibility.
        version = buildCfg.version;
        region = buildCfg.region;
        deployment = buildCfg.prefix;

        # Resolve user-supplied package names from enclave.yaml
        # (nix_build_inputs / nix_native_build_inputs) against nixpkgs.
        resolveInputs = names: map (n: eifPkgs.${n}) names;

        # Enclave supervisor — built from the runtime repo.
        # Handles attestation, secrets, PCR extension, reverse proxy with
        # signing middleware. The user's app is just a plain HTTP server.
        runtime = eifPkgs.buildGoModule {
          pname = "runtime";
          version = buildCfg.version;

          src = eifPkgs.fetchFromGitHub {
            owner = "ArkLabsHQ";
            repo = "introspector-enclave";
            rev = runtimeCfg.rev;
            hash = runtimeCfg.hash;
          };

          sourceRoot = "source/runtime";
          vendorHash = runtimeCfg.vendor_hash;
          subPackages = [ "cmd/runtime" ];
          env.CGO_ENABLED = "0";
          ldflags = [
            "-X" "github.com/ArkLabsHQ/introspector-enclave/runtime.Version=` + "${version}" + `"
          ];
          buildFlags = [ "-trimpath" ];
          tags = [ "netgo" ];
          doCheck = false;
        };

        # User's app — fetched from GitHub. No runtime dependency needed.
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

          nativeBuildInputs = resolveInputs (appCfg.nix_native_build_inputs or []);
          buildInputs = resolveInputs (appCfg.nix_build_inputs or []);

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

        # Nitriding and viproxy are vendored into the runtime binary (see
        # runtime/nitriding/ and runtime/viproxy/), so no separate derivations
        # are needed here — the runtime /app/runtime is the whole enclave
        # userspace alongside the user's app.

        # Assemble the /app directory with all binaries and scripts.
        appDir = eifPkgs.runCommand "enclave-app" { } ''
          mkdir -p $out/app/data
          cp ` + "${upstream-app}" + `/bin/` + "${appCfg.binary_name}" + ` $out/app/` + "${appCfg.binary_name}" + `
          cp ` + "${runtime}" + `/bin/runtime $out/app/runtime
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
          ENCLAVE_KMS_KEY_LOCKED=` + "${if buildCfg.is_kms_key_locked or false then \"true\" else \"false\"}" + `
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
          entrypoint = "/app/runtime";
          env = enclaveEnv;
        };

        # Vendor hash check — used by enclave setup to discover the correct hash.
        vendor-hash-check = eifPkgs.buildGoModule ({
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

          nativeBuildInputs = resolveInputs (appCfg.nix_native_build_inputs or []);
          buildInputs = resolveInputs (appCfg.nix_build_inputs or []);
        } // (if (appCfg.nix_subdir or "") != "" then {
          sourceRoot = "source/` + "${appCfg.nix_subdir}" + `";
        } else {}));

      in
      {
        packages = {
          inherit upstream-app runtime eif vendor-hash-check;
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
        # BUILD_CONFIG_PATH is set by the CLI; is set by the CLI as an absolute path.
        # Requires --impure flag (already set by the CLI).
        configPath = let p = builtins.getEnv "BUILD_CONFIG_PATH"; in
          if p != "" then p else "../.enclave/build-config.json";
        buildCfg = builtins.fromJSON (builtins.readFile configPath);
        appCfg = buildCfg.app;
        runtimeCfg = buildCfg.runtime;

        # Fall back to env vars for backwards compatibility.
        version = buildCfg.version;
        region = buildCfg.region;
        deployment = buildCfg.prefix;

        # Resolve user-supplied package names from enclave.yaml
        # (nix_build_inputs / nix_native_build_inputs) against nixpkgs.
        resolveInputs = names: map (n: eifPkgs.${n}) names;

        # Enclave supervisor — built from the runtime repo.
        # Handles attestation, secrets, PCR extension, reverse proxy with
        # signing middleware. The user's app is just a plain HTTP server.
        runtime = eifPkgs.buildGoModule {
          pname = "runtime";
          version = buildCfg.version;

          src = eifPkgs.fetchFromGitHub {
            owner = "ArkLabsHQ";
            repo = "introspector-enclave";
            rev = runtimeCfg.rev;
            hash = runtimeCfg.hash;
          };

          sourceRoot = "source/runtime";
          vendorHash = runtimeCfg.vendor_hash;
          subPackages = [ "cmd/runtime" ];
          env.CGO_ENABLED = "0";
          ldflags = [
            "-X" "github.com/ArkLabsHQ/introspector-enclave/runtime.Version=` + "${version}" + `"
          ];
          buildFlags = [ "-trimpath" ];
          tags = [ "netgo" ];
          doCheck = false;
        };

        # Node.js runtime for the enclave.
        nodejs = eifPkgs.nodejs_22;

        # User's Node.js app — fetched from GitHub. No runtime dependency needed.
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

          nativeBuildInputs = resolveInputs (appCfg.nix_native_build_inputs or []);
          buildInputs = resolveInputs (appCfg.nix_build_inputs or []);
        } // (if (appCfg.nix_subdir or "") != "" then {
          sourceRoot = "source/` + "${appCfg.nix_subdir}" + `";
        } else {}));

        # Nitriding and viproxy are vendored into the runtime binary (see
        # runtime/nitriding/ and runtime/viproxy/), so no separate derivations
        # are needed here — the runtime /app/runtime is the whole enclave
        # userspace alongside the user's app.

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

          cp ` + "${runtime}" + `/bin/runtime $out/app/runtime
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
          ENCLAVE_KMS_KEY_LOCKED=` + "${if buildCfg.is_kms_key_locked or false then \"true\" else \"false\"}" + `
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
          entrypoint = "/app/runtime";
          env = enclaveEnv;
        };

        # Vendor hash check — used by enclave setup to discover the correct hash.
        vendor-hash-check = eifPkgs.buildNpmPackage ({
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

          nativeBuildInputs = resolveInputs (appCfg.nix_native_build_inputs or []);
          buildInputs = resolveInputs (appCfg.nix_build_inputs or []);
        } // (if (appCfg.nix_subdir or "") != "" then {
          sourceRoot = "source/` + "${appCfg.nix_subdir}" + `";
        } else {}));

      in
      {
        packages = {
          inherit upstream-app runtime eif vendor-hash-check;
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
        run: go install github.com/ArkLabsHQ/introspector-enclave/cli/cmd/enclave@latest

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
          enclave tofu init
          # Stash the artifacts dir before cd so the PCR reads below resolve
          # to the right path regardless of current working directory.
          ARTIFACTS="$PWD/.enclave/artifacts"
          tofu -chdir=tofu init
          tofu -chdir=tofu apply -auto-approve

          # Extract deployment outputs for manifest and verification.
          pcr0=$(jq -r '.PCR0' "$ARTIFACTS/pcr.json")
          pcr1=$(jq -r '.PCR1' "$ARTIFACTS/pcr.json")
          pcr2=$(jq -r '.PCR2' "$ARTIFACTS/pcr.json")
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
          subject-path: .enclave/artifacts/pcr.json

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
          cat .enclave/artifacts/pcr.json >> "$GITHUB_STEP_SUMMARY"
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
        run: go install github.com/ArkLabsHQ/introspector-enclave/cli/cmd/enclave@latest

      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ` + "${{ vars.AWS_ROLE_ARN }}" + `
          aws-region: ` + "${{ vars.AWS_REGION }}" + `

      - name: Destroy infrastructure
        run: |
          cd tofu
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
          if p != "" then p else "../.enclave/build-config.json";
        buildCfg = builtins.fromJSON (builtins.readFile configPath);
        appCfg = buildCfg.app;
        runtimeCfg = buildCfg.runtime;

        version = buildCfg.version;
        region = buildCfg.region;
        deployment = buildCfg.prefix;

        # Resolve user-supplied package names from enclave.yaml
        # (nix_build_inputs / nix_native_build_inputs) against nixpkgs.
        resolveInputs = names: map (n: eifPkgs.${n}) names;

        # Enclave supervisor — built from the runtime repo.
        runtime = eifPkgs.buildGoModule {
          pname = "runtime";
          version = buildCfg.version;

          src = eifPkgs.fetchFromGitHub {
            owner = "ArkLabsHQ";
            repo = "introspector-enclave";
            rev = runtimeCfg.rev;
            hash = runtimeCfg.hash;
          };

          sourceRoot = "source/runtime";
          vendorHash = runtimeCfg.vendor_hash;
          subPackages = [ "cmd/runtime" ];
          env.CGO_ENABLED = "0";
          ldflags = [
            "-X" "github.com/ArkLabsHQ/introspector-enclave/runtime.Version=` + "${version}" + `"
          ];
          buildFlags = [ "-trimpath" ];
          tags = [ "netgo" ];
          doCheck = false;
        };

        # User's .NET app — fetched from GitHub. No runtime dependency needed.
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

          nativeBuildInputs = resolveInputs (appCfg.nix_native_build_inputs or []);
          buildInputs = resolveInputs (appCfg.nix_build_inputs or []);
        } // (if (appCfg.nix_subdir or "") != "" then {
          sourceRoot = "source/` + "${appCfg.nix_subdir}" + `";
        } else {}));

        # Nitriding and viproxy are vendored into the runtime binary (see
        # runtime/nitriding/ and runtime/viproxy/), so no separate derivations
        # are needed here — the runtime /app/runtime is the whole enclave
        # userspace alongside the user's app.

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

          cp ` + "${runtime}" + `/bin/runtime $out/app/runtime
        '';

        # Complete rootfs for the enclave — includes ICU for .NET globalization.
        enclaveRootfs = eifPkgs.buildEnv {
          name = "enclave-rootfs";
          paths = [
            appDir
            eifPkgs.busybox    # provides /bin/sh and basic utils
            eifPkgs.cacert     # TLS CA certificates
            eifPkgs.icu        # ICU globalization data for .NET
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
          ENCLAVE_KMS_KEY_LOCKED=` + "${if buildCfg.is_kms_key_locked or false then \"true\" else \"false\"}" + `
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
          entrypoint = "/app/runtime";
          env = enclaveEnv;
        };

        # Vendor hash check — used by enclave setup to discover the correct hash.
        # .NET uses fetch-deps for deps.json — no hash-based vendor check.
        vendor-hash-check = eifPkgs.runCommand "vendor-hash-check-noop" {} "echo noop > $out";

      in
      {
        packages = {
          inherit upstream-app runtime eif vendor-hash-check;
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
          if p != "" then p else "../.enclave/build-config.json";
        buildCfg = builtins.fromJSON (builtins.readFile configPath);
        appCfg = buildCfg.app;
        runtimeCfg = buildCfg.runtime;

        version = buildCfg.version;
        region = buildCfg.region;
        deployment = buildCfg.prefix;

        # Resolve user-supplied package names from enclave.yaml
        # (nix_build_inputs / nix_native_build_inputs) against nixpkgs.
        resolveInputs = names: map (n: eifPkgs.${n}) names;

        # Enclave supervisor — built from the runtime repo.
        runtime = eifPkgs.buildGoModule {
          pname = "runtime";
          version = buildCfg.version;

          src = eifPkgs.fetchFromGitHub {
            owner = "ArkLabsHQ";
            repo = "introspector-enclave";
            rev = runtimeCfg.rev;
            hash = runtimeCfg.hash;
          };

          sourceRoot = "source/runtime";
          vendorHash = runtimeCfg.vendor_hash;
          subPackages = [ "cmd/runtime" ];
          env.CGO_ENABLED = "0";
          ldflags = [
            "-X" "github.com/ArkLabsHQ/introspector-enclave/runtime.Version=` + "${version}" + `"
          ];
          buildFlags = [ "-trimpath" ];
          tags = [ "netgo" ];
          doCheck = false;
        };

        # User's Rust app — fetched from GitHub. No runtime dependency needed.
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

          nativeBuildInputs = resolveInputs (appCfg.nix_native_build_inputs or []);
          buildInputs = resolveInputs (appCfg.nix_build_inputs or []);

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

        # Nitriding and viproxy are vendored into the runtime binary — no
        # separate derivations needed.

        appDir = eifPkgs.runCommand "enclave-app" { } ''
          mkdir -p $out/app/data
          cp ` + "${upstream-app}" + `/bin/` + "${appCfg.binary_name}" + ` $out/app/` + "${appCfg.binary_name}" + `
          cp ` + "${runtime}" + `/bin/runtime $out/app/runtime
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
          ENCLAVE_KMS_KEY_LOCKED=` + "${if buildCfg.is_kms_key_locked or false then \"true\" else \"false\"}" + `
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
          entrypoint = "/app/runtime";
          env = enclaveEnv;
        };

        # Vendor hash check — used by enclave setup to discover the correct hash.
        vendor-hash-check = eifPkgs.rustPlatform.buildRustPackage ({
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

          nativeBuildInputs = resolveInputs (appCfg.nix_native_build_inputs or []);
          buildInputs = resolveInputs (appCfg.nix_build_inputs or []);
        } // (if (appCfg.nix_subdir or "") != "" then {
          sourceRoot = "source";
          cargoRoot = appCfg.nix_subdir;
          buildAndTestSubdir = appCfg.nix_subdir;
        } else {}));

      in
      {
        packages = {
          inherit upstream-app runtime eif vendor-hash-check;
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
        run: go install github.com/ArkLabsHQ/introspector-enclave/cli/cmd/enclave@latest

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
// Any CI/CD tool can pull the EIF from the "eif-latest" release to run QEMU
// enclave tests on a bare metal instance without needing Nix locally.
const frameworkBuildEIFWorkflow = `name: Build EIF

on:
  push:
    branches: [master, main]
    paths:
      - 'enclave/**'
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
        run: go install github.com/ArkLabsHQ/introspector-enclave/cli/cmd/enclave@latest

      - name: Pull Nix Docker image
        run: docker pull nixos/nix:2.24.9

      - name: Build EIF
        run: enclave build

      - name: Extract PCR values
        id: pcr
        run: |
          PCR0=$(jq -r '.PCR0 // .pcr0' .enclave/artifacts/pcr.json)
          echo "pcr0=${PCR0}" >> "$GITHUB_OUTPUT"
          echo "PCR0: ${PCR0:0:32}..."

      - name: Upload EIF artifact
        uses: actions/upload-artifact@v4
        with:
          name: enclave-eif
          path: |
            .enclave/artifacts/image.eif
            .enclave/artifacts/pcr.json
            .enclave/artifacts/supervisor
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
            .enclave/artifacts/image.eif \
            .enclave/artifacts/pcr.json \
            .enclave/artifacts/supervisor

      - name: Publish build manifest
        continue-on-error: true
        env:
          GH_TOKEN: ` + "${{ github.token }}" + `
          REPO: ` + "${{ github.repository }}" + `
          COMMIT_SHA: ` + "${{ github.sha }}" + `
        run: |
          PCR0=$(jq -r '.PCR0 // .pcr0' .enclave/artifacts/pcr.json)
          PCR1=$(jq -r '.PCR1 // .pcr1' .enclave/artifacts/pcr.json)
          PCR2=$(jq -r '.PCR2 // .pcr2' .enclave/artifacts/pcr.json)
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
