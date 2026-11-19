"""Tests for probe.py. Run with: python3 -m unittest discover -s tests"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROBE = os.path.join(ROOT, "probe.py")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")


def run_probe(extra_env):
    out = tempfile.mkdtemp()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "INPUT_DIR": FIXTURES,
        "OUTPUT_DIR": out,
        "NETWORK_CHECKS": "false",
        **extra_env,
    }
    proc = subprocess.run([sys.executable, PROBE], env=env, capture_output=True, text=True)
    return proc, out


class ProbeTest(unittest.TestCase):
    def test_inspect_writes_report_and_hides_secrets(self):
        proc, out = run_probe({
            "SESSION_TOKEN": "secret-session-value",
            "MY_SHARED_SECRET": "secret-user-value",
            "EXECUTION_RUN_ID": "run-123",
        })
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(os.path.join(out, "report.json")) as f:
            report = json.load(f)
        with open(os.path.join(out, "report.md")) as f:
            markdown = f.read()

        for text in (proc.stdout, markdown, json.dumps(report)):
            self.assertNotIn("secret-session-value", text)
            self.assertNotIn("secret-user-value", text)

        variables = {v["name"]: v for v in report["environment"]["variables"]}
        self.assertEqual(variables["EXECUTION_RUN_ID"]["value"], "run-123")
        self.assertIsNone(variables["SESSION_TOKEN"]["value"])
        self.assertEqual(variables["SESSION_TOKEN"]["kind"], "known-secret")
        self.assertIsNone(variables["MY_SHARED_SECRET"]["value"])
        self.assertIn("SESSION_TOKEN", report["environment"]["knownSecretsPresent"])

        self.assertEqual(report["inputs"]["fileCount"], 2)
        self.assertIn("nested/", report["inputs"]["topLevel"])
        self.assertIn("APP_PROBE_SUMMARY", proc.stdout)

    def test_echo_copies_inputs_without_report(self):
        proc, out = run_probe({"MODE": "echo"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.isfile(os.path.join(out, "hello.txt")))
        self.assertTrue(os.path.isfile(os.path.join(out, "nested", "data.csv")))
        self.assertFalse(os.path.exists(os.path.join(out, "report.json")))

    def test_exit_code_and_filler(self):
        proc, out = run_probe({"EXIT_CODE": "3", "WRITE_MB": "1", "LOG_LINES": "5"})
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(os.path.getsize(os.path.join(out, "app-probe-filler.bin")), 1 << 20)
        self.assertIn("log line 5/5", proc.stdout)
        self.assertTrue(os.path.isfile(os.path.join(out, "report.json")))

    def test_release_tag_from_image_reference(self):
        sys.path.insert(0, ROOT)
        try:
            import probe
        finally:
            sys.path.remove(ROOT)
        repo = "123456789012.dkr.ecr.us-east-1.amazonaws.com/dev-appstore-private-use1"
        self.assertEqual(probe.release_tag(f"{repo}:4101059555-v0.1.3"), "v0.1.3")
        self.assertEqual(probe.release_tag(f"{repo}:4101059555-v0.1.3-soci"), "v0.1.3")
        self.assertEqual(probe.release_tag(f"{repo}:4101059555-v1.0.0-rc.1"), "v1.0.0-rc.1")
        self.assertIsNone(probe.release_tag(f"{repo}@sha256:" + "a" * 64))
        self.assertIsNone(probe.release_tag("python:3.12-slim"))
        self.assertIsNone(probe.release_tag(None))

    def test_bad_parameters_fall_back_to_defaults(self):
        proc, _ = run_probe({"MODE": "bogus", "EXIT_CODE": "not-a-number"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("using inspect", proc.stdout)


if __name__ == "__main__":
    unittest.main()
