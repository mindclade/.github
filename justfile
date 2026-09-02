set shell := ["bash", "-euo", "pipefail", "-c"]
set export

bazel := "bazel"

default:
    @just --list

format:
    biome check --write .
    ruff format .
    opa fmt -w policy
    git ls-files 'BUILD.bazel' 'MODULE.bazel' '*.bzl' | xargs buildifier -mode=fix
    nixfmt flake.nix
    just --fmt

format-check:
    biome check .
    ruff format --check .
    opa fmt --fail policy >/dev/null
    git ls-files 'BUILD.bazel' 'MODULE.bazel' '*.bzl' | xargs buildifier -mode=check -lint=warn
    nixfmt --check flake.nix
    just --fmt --check

lint:
    biome lint .
    ruff check .
    pyright
    actionlint .github/workflows/*.yml
    yamllint --config-file .yamllint.yaml .
    markdownlint-cli2

test:
    {{ bazel }} test --config=ci --symlink_prefix=/ //:self_test

policy:
    {{ bazel }} build --config=ci --symlink_prefix=/ //:policy_check

workflows:
    {{ bazel }} build --config=ci --symlink_prefix=/ //:workflow_lint

flake-check:
    nix flake check --no-accept-flake-config --no-build --no-update-lock-file

check: format-check lint policy workflows test flake-check

ci: check

validate-workflows:
    {{ bazel }} run --config=ci --symlink_prefix=/ //:validate_reusable_workflows -- validate --root "{{ justfile_directory() }}"
