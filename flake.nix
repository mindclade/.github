{
  description = "Pinned system toolchain for github.com/mindclade/.github";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
      ];
      forAllSystems =
        function:
        builtins.listToAttrs (
          map (system: {
            name = system;
            value = function system (import nixpkgs { inherit system; });
          }) systems
        );
    in
    {
      packages = forAllSystems (
        system: pkgs:
        let
          opaTarget =
            {
              aarch64-darwin = {
                asset = "opa_darwin_arm64";
                hash = "sha256-K4BdR2CZ+Bgo4KckZvI7fF9wNejlGCP14e88v08jIc4=";
              };
              x86_64-linux = {
                asset = "opa_linux_amd64";
                hash = "sha256-SBTKr4kGK5kp5zc8dF6xtzvoqjR75h2gZJH2j+kQJFs=";
              };
            }
            .${system};
          opa = pkgs.runCommand "opa-1.20.1" { } ''
            install -D -m 0755 ${pkgs.fetchurl {
              url = "https://github.com/open-policy-agent/opa/releases/download/v1.20.1/${opaTarget.asset}";
              inherit (opaTarget) hash;
            }} "$out/bin/opa"
          '';
          toolchainPackages = with pkgs; [
            actionlint
            bash
            bazelisk
            buildifier
            cacert
            coreutils
            curl
            findutils
            git
            gitleaks
            gnugrep
            gnused
            gnutar
            gzip
            jq
            just
            nixfmt-rfc-style
            nodejs_24
            opa
            python313
            shellcheck
            unzip
            yamllint
            yq-go
          ];
          toolchain = pkgs.buildEnv {
            name = "mindclade-dot-github-toolchain";
            paths = toolchainPackages;
            pathsToLink = [
              "/bin"
              "/share"
            ];
            ignoreCollisions = false;
          };
        in
        {
          inherit toolchain;
          default = toolchain;
        }
      );

      devShells = forAllSystems (
        system: pkgs:
        let
          toolchain = self.packages.${system}.toolchain;
          common = {
            packages = [ toolchain ];
            LANG = "C.UTF-8";
            LC_ALL = "C.UTF-8";
            TZ = "UTC";
            USE_BAZEL_VERSION = "9.2.0";
          };
        in
        {
          default = pkgs.mkShell common;
          ci = pkgs.mkShell (common // { CI = "true"; });
        }
      );

      formatter = forAllSystems (_: pkgs: pkgs.nixfmt-rfc-style);

      checks = forAllSystems (
        system: pkgs:
        let
          toolchain = self.packages.${system}.toolchain;
        in
        {
          toolchain = pkgs.runCommand "mindclade-dot-github-toolchain-check" {
            nativeBuildInputs = [ toolchain ];
          } ''
            set -euo pipefail
            test "$(actionlint -version)" = "1.7.12"
            test "$(just --version)" = "just 1.58.0"
            test "$(opa version --format json | jq -r .version)" = "1.20.1"
            test "$(python3 -c 'import platform; print(platform.python_version())')" = "3.13.15"
            test "${pkgs.bazelisk.version}" = "1.29.0"
            grep -Fq '>=9.2.0' ${self}/MODULE.bazel
            grep -Fq '<9.3.0' ${self}/MODULE.bazel
            mkdir -p "$out"
            printf '%s\n' '${nixpkgs.rev}' > "$out/nixpkgs-revision"
          '';

          source = pkgs.runCommand "mindclade-dot-github-source-check" {
            nativeBuildInputs = [ toolchain ];
          } ''
            set -euo pipefail
            export HOME="$TMPDIR/home"
            mkdir -p "$HOME" "$out"
            python3 ${self}/tools/validate_reusable_workflows.py validate --root ${self} \
              > "$out/validation.json"
          '';
        }
      );
    };
}
