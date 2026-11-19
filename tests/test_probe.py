"""Tests for probe.py. Run with: python3 -m unittest discover -s tests"""

import json
import os
import shutil
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

    def test_resources_use_the_smallest_limit(self):
        sys.path.insert(0, ROOT)
        try:
            import probe
        finally:
            sys.path.remove(ROOT)
        ecs = {"taskLimits": {"CPU": 0.5, "Memory": 1024}, "container": {"limits": {"CPU": 2}}}
        r = probe.resources(ecs)
        self.assertEqual(r["cpu"]["effectiveVcpu"], 0.5)
        self.assertEqual(r["cpu"]["limitedBy"], "task limit")
        self.assertEqual(r["cpu"]["containerCpuUnits"], 2)
        self.assertEqual(r["memory"]["effectiveMiB"], 1024)
        self.assertEqual(r["memory"]["limitedBy"], "task limit")
        self.assertEqual(probe.smallest({"a": None, "b": None}), (None, None))

    def test_lambda_resources_are_not_the_hosts(self):
        sys.path.insert(0, ROOT)
        try:
            import probe
        finally:
            sys.path.remove(ROOT)
        os.environ.pop("AWS_LAMBDA_FUNCTION_MEMORY_SIZE", None)
        r = probe.resources(None, "lambda")
        self.assertIsNone(r["cpu"]["effectiveVcpu"])
        self.assertIsNone(r["memory"]["effectiveMiB"])
        self.assertIn("unknown", probe.memory_line(r["memory"]))
        os.environ["AWS_LAMBDA_FUNCTION_MEMORY_SIZE"] = "3538"
        try:
            r = probe.resources(None, "lambda")
        finally:
            del os.environ["AWS_LAMBDA_FUNCTION_MEMORY_SIZE"]
        self.assertEqual(r["memory"]["effectiveMiB"], 3538)
        self.assertEqual(r["cpu"]["effectiveVcpu"], 2.0)

    def test_lambda_report_says_limits_are_unknown(self):
        # The Lambda step runtime puts INPUT_DIR under /tmp, which is how the probe detects it.
        base = tempfile.mkdtemp(dir="/tmp")
        inputs = os.path.join(base, "input")
        shutil.copytree(FIXTURES, inputs)
        proc, out = run_probe({"INPUT_DIR": inputs})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(os.path.join(out, "report.md")) as f:
            markdown = f.read()
        self.assertIn("Compute: **lambda**", markdown)
        self.assertIn("- CPU: **unknown** (not visible on Lambda", markdown)
        self.assertIn("- Memory: **unknown** (not visible on Lambda", markdown)

    def import_probe(self):
        sys.path.insert(0, ROOT)
        try:
            import probe
        finally:
            sys.path.remove(ROOT)
        return probe

    def write_crate(self, crate):
        root = tempfile.mkdtemp()
        with open(os.path.join(root, "view.json"), "w") as f:
            json.dump(crate, f)
        return self.import_probe().view_summary(root, os.path.join(root, "view.json"))

    def test_reports_staged_workspace_view(self):
        # The shape views-service writes for a workspace dataset (internal/crate/crate.go).
        inputs = os.path.join(tempfile.mkdtemp(), "input")
        shutil.copytree(FIXTURES, inputs)
        os.makedirs(os.path.join(inputs, ".pennsieve"))
        crate = {"@graph": [
            {"@id": "./", "@type": "Dataset", "identifier": "view-1", "name": "Run: files",
             "version": "1", "views:lifecycle": "run", "views:entryCount": 1,
             "isBasedOn": [{"@id": "#source-1"}]},
            {"@id": "#source-1", "@type": "Dataset", "name": "N:dataset:abc", "views:sourceType": "workspace",
             "identifier": [{"@id": "#source-1-pennsieve"}, {"@id": "#source-1-pennsieve-organization"}]},
            {"@id": "#source-1-pennsieve", "propertyID": "pennsieve", "value": "N:dataset:abc"},
            {"@id": "#source-1-pennsieve-organization", "propertyID": "pennsieve-organization", "value": "N:organization:o"},
        ]}
        with open(os.path.join(inputs, ".pennsieve", "view.json"), "w") as f:
            json.dump(crate, f)
        proc, out = run_probe({"INPUT_DIR": inputs})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(os.path.join(out, "report.json")) as f:
            views = json.load(f)["inputs"]["views"]
        self.assertEqual(len(views), 1)
        self.assertEqual(views[0]["lifecycle"], "run")
        source = views[0]["sources"][0]
        self.assertEqual(source["ids"], {"pennsieve": "N:dataset:abc", "pennsieve-organization": "N:organization:o"})
        self.assertEqual(source["unexpected"], [])
        with open(os.path.join(out, "report.md")) as f:
            self.assertIn('View `Run: files` `view-1` v1 (run, 1 entries) from "N:dataset:abc" '
                          "(pennsieve N:dataset:abc, pennsieve-organization N:organization:o, type workspace)", f.read())

    def test_published_dataset_source(self):
        # The shape views-service writes for a Discover dataset: a DOI string and a reference.
        summary = self.write_crate({"@graph": [
            {"@id": "./", "isBasedOn": [{"@id": "https://doi.org/10.21397/qswm-ysfc"}]},
            {"@id": "https://doi.org/10.21397/qswm-ysfc", "name": "No More STRIDES buckets",
             "alternateName": "dataset-5363-v1",
             "identifier": ["https://doi.org/10.21397/qswm-ysfc", {"@id": "#source-1-pennsieve-discover"}]},
            {"@id": "#source-1-pennsieve-discover", "propertyID": "pennsieve-discover", "value": "5363"},
        ]})
        source = summary["sources"][0]
        self.assertEqual(source["doi"], "10.21397/qswm-ysfc")
        self.assertEqual(source["ids"], {"pennsieve-discover": "5363"})
        self.assertEqual(self.import_probe().source_label(source),
                         '"No More STRIDES buckets" (pennsieve-discover 5363, doi:10.21397/qswm-ysfc, '
                         "alternateName dataset-5363-v1)")

    def test_unexpected_crates_are_reported_not_fatal(self):
        # views-service is still changing: unknown shapes are recorded, never raised.
        source = self.write_crate({"@graph": [
            {"@id": "./", "isBasedOn": {"@id": "#s"}},
            {"@id": "#s", "name": "s", "identifier": "N:dataset:xyz"},
        ]})["sources"][0]
        self.assertEqual(len(source["unexpected"]), 2)  # not a list; not a DOI or a reference
        self.assertIn("2 unexpected (see report.json)", self.import_probe().source_label(source))
        for crate in (["not a crate"], {"@graph": "nope"}, {"@graph": []}):
            with self.subTest(crate=crate):
                self.assertIn("not a view crate as expected", self.write_crate(crate)["error"])

    def test_bad_parameters_fall_back_to_defaults(self):
        proc, _ = run_probe({"MODE": "bogus", "EXIT_CODE": "not-a-number"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("using inspect", proc.stdout)


if __name__ == "__main__":
    unittest.main()
