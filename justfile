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
    zizmor --no-progress --offline .github/workflows/*.yml .github/actions
    yamllint --config-file .yamllint.yaml .
    markdownlint-cli2

# Vulnerability scan of declared dependencies. Requires network access to the
# OSV database, so it is deliberately separate from the hermetic lint recipe.
security:
    osv-scanner scan source --recursive .

test:
    {{ bazel }} test --config=ci --symlink_prefix=/ //:self_test

generated-check:
    python3 tools/generate_ci_policy.py check --root "{{ justfile_directory() }}"

policy:
    {{ bazel }} build --config=ci --symlink_prefix=/ //:policy_check

workflows:
    {{ bazel }} build --config=ci --symlink_prefix=/ //:workflow_lint

flake-check:
    nix flake check --no-accept-flake-config --no-build --no-update-lock-file

check: generated-check format-check lint policy workflows test security flake-check

ci: check

validate-workflows:
    {{ bazel }} run --config=ci --symlink_prefix=/ //:validate_reusable_workflows -- validate --root "{{ justfile_directory() }}"
