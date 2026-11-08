import unittest
from unittest.mock import patch

from phishlens.core import analyze, levenshtein, registered_domain, shannon_entropy


def rules(url):
    return {f.rule for f in analyze(url).findings}


class CoreTests(unittest.TestCase):
    def test_levenshtein(self):
        self.assertEqual(levenshtein("kitten", "sitting"), 3)
        self.assertEqual(levenshtein("google", "google"), 0)

    def test_registered_domain(self):
        self.assertEqual(registered_domain("a.b.example.com"), ("example", "example.com"))
        self.assertEqual(registered_domain("x.impots.gouv.fr"), ("impots", "impots.gouv.fr"))

    def test_legit_sites_are_ok(self):
        for url in ("https://www.google.com/search?q=test", "https://accounts.google.com/signin",
                    "https://github.com/anthropics", "https://impots.gouv.fr/accueil"):
            self.assertEqual(analyze(url).verdict, "ok", url)

    def test_leet_lookalike(self):
        self.assertIn("brand_lookalike", rules("http://paypa1-secure-login.xyz/verify"))

    def test_typosquat(self):
        self.assertIn("brand_lookalike", rules("https://goggle.com/"))

    def test_brand_on_third_party_domain(self):
        self.assertIn("brand_third_party", rules("https://login.microsoft.com.account-verify.top/"))
        self.assertIn("brand_third_party", rules("https://impots-gouv.fr/connexion"))

    def test_no_false_positive_on_short_brand(self):
        self.assertNotIn("brand_lookalike", rules("https://apply.com/"))

    def test_ip_userinfo_punycode_port(self):
        self.assertIn("ip_host", rules("http://192.168.1.10/login"))
        self.assertIn("userinfo", rules("https://google.com@evil.example/"))
        self.assertIn("punycode", rules("https://xn--pple-43d.com/"))
        self.assertIn("odd_port", rules("https://example.com:8080/"))

    def test_scheme_less_url_does_not_flag_http(self):
        self.assertNotIn("no_https", rules("example.com/path"))

    def test_dangerous_verdict(self):
        self.assertEqual(analyze("http://paypa1-secure-login.xyz/verify").verdict, "dangerous")

    def test_entropy(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertGreater(shannon_entropy("x7kq9zpw2m"), 3)

    def test_no_double_counting_or_noise(self):
        self.assertNotIn("random_domain", rules("http://paypa1-secure-login.xyz/verify"))
        self.assertNotIn("hyphens", rules("https://xn--pple-43d.com/"))
        keywords = [f for f in analyze("https://x.example/verify").findings if f.rule == "keywords"]
        self.assertEqual(keywords[0].points, 5)

    def test_never_touches_network(self):
        """Garantie légale/éthique : l'analyse ne doit ouvrir aucune connexion."""
        with patch("socket.socket", side_effect=AssertionError("accès réseau interdit")):
            analyze("http://paypa1-secure-login.xyz/verify")
            analyze("https://www.google.com")


if __name__ == "__main__":
    unittest.main()
