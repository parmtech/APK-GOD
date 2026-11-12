import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Allow the isolated native probe to run this test file directly.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from apk_god.runtime import devices, observe


class RuntimeValidationTests(unittest.TestCase):
    def test_existing_report_and_invalid_hooks_are_rejected_before_attach(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "runtime.json"
            output.write_text("preserve this")
            with self.assertRaisesRegex(ValueError, "already exists"):
                observe("local", 99999999, output=output)
            self.assertEqual(output.read_text(), "preserve this")
        with self.assertRaisesRegex(ValueError, "module-name"):
            observe("local", 99999999, hooks=["libc.so.6:getpid; execute unwanted code"])
        with self.assertRaisesRegex(ValueError, "duration"):
            observe("local", 99999999, seconds=0)


@unittest.skipUnless(importlib.util.find_spec("frida") and sys.platform.startswith("linux"), "Actual native hook fixture requires the embedded Frida library on Linux.")
class RuntimeObservationTests(unittest.TestCase):
    def test_embedded_frida_observes_only_test_owned_child(self):
        # Frida has native components. Probe in an isolated Python process so a
        # host initialization failure cannot terminate the complete test suite.
        probe = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--native-probe"],
                               capture_output=True, text=True, timeout=25)
        if "idund did not start listening" in probe.stderr and (probe.returncode < 0 or "exit code -11" in probe.stderr):
            self.skipTest("Frida native backend could not start its local helper on this host (idund, signal 11); no runtime observation was completed.")
        if probe.returncode == 77:
            self.skipTest(probe.stdout.strip())
        self.assertEqual(probe.returncode, 0, probe.stderr)
        payload = json.loads(probe.stdout)
        result, pid = payload["result"], payload["child_pid"]
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["basis"], "runtime-observed")
        self.assertEqual(result["target"], pid)
        self.assertGreater(result["counts"].get("libc.so.6:getpid", 0), 0, result["events"])
        self.assertTrue(any(x.get("type") == "process" and x.get("pid") == pid for x in result["events"]))
        self.assertTrue(payload["persisted_matches"])
        self.assertTrue(payload["child_survived"], "Observation must detach without terminating the test process")


def native_probe():
    local = [x for x in devices() if x["type"] == "local"]
    if not local:
        raise AssertionError("Frida must expose a local device")
    child = subprocess.Popen([sys.executable, "-u", "-c", "import os,time\nprint('fixture-ready',flush=True)\nwhile True:\n os.getpid()\n time.sleep(0.01)\n"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if child.stdout.readline().strip() != b"fixture-ready":
            raise AssertionError("Fixture process did not initialize")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "runtime.json"
            try:
                result = observe(local[0]["id"], child.pid, seconds=0.4, hooks=["libc.so.6:getpid"], output=output)
            except ValueError as exc:
                message = str(exc).lower()
                if any(x in message for x in ("operation not permitted", "permission denied", "ptrace", "access denied")):
                    print("Local attachment unavailable under the host's process permissions: " + str(exc))
                    return 77
                raise
            print(json.dumps({"result": result, "child_pid": child.pid,
                              "persisted_matches": json.loads(output.read_text()) == result,
                              "child_survived": child.poll() is None}))
    finally:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
        child.stdout.close()
        child.stderr.close()
    return 0


if __name__ == "__main__":
    if "--native-probe" in sys.argv:
        raise SystemExit(native_probe())
    unittest.main()
