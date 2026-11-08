import io
import json
import unittest
from contextlib import redirect_stdout

from phishlens.cli import main


class CliTests(unittest.TestCase):
    def run_cli(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_safe_url_exit_0(self):
        code, _ = self.run_cli(["check", "https://github.com"])
        self.assertEqual(code, 0)

    def test_phishing_exit_1_and_json(self):
        code, out = self.run_cli(["check", "--json", "http://paypa1-secure-login.xyz/verify"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)[0]["verdict"], "dangerous")

    def test_demo_runs(self):
        code, out = self.run_cli(["demo"])
        self.assertEqual(code, 1)
        self.assertIn("Aucune URL n'a été visitée", out)


if __name__ == "__main__":
    unittest.main()
