"""Exercise embedded native reconstruction with an original compiled fixture.

The compiler builds the test binary, but the binary is never run on the host.
Actual angr CFG/decompiler/solver APIs analyze it under their symbolic model.
"""
import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from apk_god.symbolic import analyze_binary

FIXTURE = r"""
#include <unistd.h>
__attribute__((noinline)) int accepted(void) { return 42; }
__attribute__((noinline)) int rejected(void) { return 3; }
__attribute__((noinline)) int route(unsigned char value) {
    if (value == 'A') return accepted();
    return rejected();
}
int main(void) {
    unsigned char value = 0;
    if (read(0, &value, 1) != 1) return 2;
    return route(value);
}
"""


class SymbolicInputTests(unittest.TestCase):
    def test_bounds_checked_before_loading(self):
        for argument in [{"max_functions": 0}, {"max_steps": 0}, {"max_states": 10000},
                         {"stdin_bytes": -1}, {"find_address": -1}, {"max_functions": True}]:
            with self.subTest(argument=argument):
                with self.assertRaises(ValueError):
                    analyze_binary("does-not-exist", "unused", **argument)

    def test_conflicting_goal_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "cannot also"):
            analyze_binary("does-not-exist", "unused", find_address=0x1000, avoid_addresses=[0x1000])


@unittest.skipUnless(importlib.util.find_spec("angr"), "Optional embedded angr is not installed")
class EmbeddedSymbolicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.source = cls.root / "fixture.c"
        cls.binary = cls.root / "fixture.elf"
        cls.source.write_text(FIXTURE)
        compiler = shutil.which("cc")
        if compiler is None:
            cls.temp.cleanup()
            raise RuntimeError("The native symbolic test fixture requires a C compiler.")
        subprocess.run([compiler, "-O0", "-fno-pie", "-no-pie", "-fno-stack-protector",
                        str(cls.source), "-o", str(cls.binary)], check=True, capture_output=True, timeout=30)
        import angr
        cls.project = angr.Project(str(cls.binary), auto_load_libs=False)
        cls.accepted = cls.project.loader.find_symbol("accepted").rebased_addr
        cls.rejected = cls.project.loader.find_symbol("rejected").rebased_addr

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_cfg_c_reconstruction_and_symbolic_witness(self):
        result = analyze_binary(self.binary, self.root / "full", max_functions=10, max_steps=50,
                                find_address=self.accepted, avoid_addresses=[self.rejected], stdin_bytes=1)
        self.assertNotEqual(result["status"], "failed", result.get("message"))
        self.assertTrue(result["cfg"]["nodes"])
        self.assertTrue(result["cfg"]["edges"])
        accepted = next(x for x in result["functions"] if x["name"] == "accepted")
        self.assertEqual(accepted["status"], "reconstructed")
        reconstructed = (self.root / "full" / accepted["source_path"]).read_text()
        self.assertIn("42", reconstructed)
        exploration = result["exploration"]
        self.assertEqual(exploration["status"], "model-path-found", exploration)
        self.assertEqual(exploration["witness"]["stdin_hex"], "41")
        self.assertLessEqual(exploration["steps"], 50)
        self.assertIn(self.accepted, exploration["witness"]["path_addresses"])

    def test_tiny_step_budget_is_not_a_claim_of_unreachability(self):
        result = analyze_binary(self.binary, self.root / "limited", max_functions=1, max_steps=1,
                                find_address=self.accepted, stdin_bytes=1)
        self.assertEqual(result["exploration"]["status"], "not-found-within-bounds")
        self.assertTrue(result["exploration"]["step_limit_reached"])
        self.assertIn("not proof", result["exploration"]["interpretation"])
        self.assertEqual(result["status"], "partial")

    def test_no_goal_does_not_start_exploration(self):
        result = analyze_binary(self.binary, self.root / "static", max_functions=2)
        self.assertEqual(result["exploration"]["status"], "not-requested")
        self.assertEqual(result["exploration"]["steps"], 0)


if __name__ == "__main__":
    unittest.main()
