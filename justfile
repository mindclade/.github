set shell := ["/bin/sh", "-eu", "-c"]
set export

export USE_BAZEL_VERSION := "9.2.0"
bazel := "bazelisk"

default: test

test:
    {{bazel}} test --lockfile_mode=off --symlink_prefix=/ //:self_test --test_output=errors

policy:
    {{bazel}} build --lockfile_mode=off --symlink_prefix=/ //:policy_check

workflows:
    {{bazel}} build --lockfile_mode=off --symlink_prefix=/ //:workflow_lint

ci:
    {{bazel}} test --lockfile_mode=off --symlink_prefix=/ //:self_test --test_output=errors

validate-workflows:
    {{bazel}} run --lockfile_mode=off --symlink_prefix=/ //:validate_reusable_workflows -- validate --root "{{justfile_directory()}}"
