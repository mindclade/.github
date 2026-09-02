# pyright: basic, reportArgumentType=false, reportIndexIssue=false
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import generate_ci_policy as generator

ROOT = Path(__file__).resolve().parents[1]


class GeneratedCIPolicyTest(unittest.TestCase):
    def test_generated_policy_has_no_drift(self) -> None:
        self.assertEqual([], generator.check(ROOT))

    def test_render_is_reproducible_and_covers_standard_systems(self) -> None:
        revision = "a" * 40
        first = generator.render(ROOT, revision)
        second = generator.render(ROOT, revision)
        self.assertEqual(first, second)
        policy = json.loads((ROOT / generator.POLICY_SOURCE).read_text(encoding="utf-8"))
        systems = ["aarch64-darwin", "aarch64-linux", "x86_64-linux"]
        self.assertEqual(systems, policy["spec"]["systems"])
        self.assertEqual(
            systems,
            [entry["system"] for entry in policy["spec"]["native_runners"]],
        )
        manifest = json.loads(first[generator.MANIFEST_DEFAULTS])
        self.assertEqual(systems, manifest["supported_systems"])
        self.assertEqual(revision, manifest["authority"]["revision"])

    def test_lock_binds_every_source_and_generated_artifact(self) -> None:
        rendered = generator.render(ROOT, "b" * 40)
        lock = json.loads(rendered[generator.POLICY_LOCK])
        contract = {key: value for key, value in lock.items() if key != "contract_digest"}
        self.assertEqual(generator.sha256_json(contract), lock["contract_digest"])
        for relative, expected in lock["sources"].items():
            observed = "sha256:" + hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            self.assertEqual(expected, observed, relative)
        for relative, expected in lock["artifacts"].items():
            observed = "sha256:" + hashlib.sha256(rendered[Path(relative)]).hexdigest()
            self.assertEqual(expected, observed, relative)

    def test_reusable_workflow_materializes_the_fixed_native_runner_contract(self) -> None:
        workflow = (ROOT / ".github/workflows/reusable-nix-validation.yml").read_text(
            encoding="utf-8"
        )
        policy = json.loads((ROOT / generator.POLICY_SOURCE).read_text(encoding="utf-8"))
        for entry in policy["spec"]["native_runners"]:
            for key in ("system", "runner", "installer_asset", "installer_sha256"):
                self.assertIn(str(entry[key]), workflow)
        self.assertEqual(
            "import %workspace%/generated/bazelrc.common\n",
            (ROOT / ".bazelrc").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "policy = import ./generated/nix-bazel-policy.nix;",
            (ROOT / "flake.nix").read_text(encoding="utf-8"),
        )

    def test_check_fails_closed_on_source_or_golden_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (
                generator.POLICY_SOURCE,
                generator.PROFILE_SOURCE,
                *generator.EXTERNAL_LOCKS,
            ):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((ROOT / relative).read_bytes())
            generator.write(root, "c" * 40)
            self.assertEqual([], generator.check(root))
            profile = json.loads((root / generator.PROFILE_SOURCE).read_text(encoding="utf-8"))
            profile["metadata"]["revision"] = 2
            (root / generator.PROFILE_SOURCE).write_text(
                json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            errors = generator.check(root)
            self.assertTrue(any("profiles.generated.json" in error for error in errors), errors)
            self.assertTrue(any("nix-bazel-policy.lock.json" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
