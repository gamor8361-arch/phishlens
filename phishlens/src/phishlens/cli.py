"""Interface en ligne de commande."""
from __future__ import annotations

import argparse
import json
import sys

from .core import Report, analyze

ICONS = {"ok": "🟢 Aucun signal fort", "suspect": "🟠 Suspect", "dangerous": "🔴 Très suspect"}
# Exemples fictifs et inoffensifs, uniquement pour la démonstration (jamais visités).
DEMO_URLS = [
    "https://www.google.com/search?q=test",
    "https://accounts.google.com/signin",
    "http://paypa1-secure-login.xyz/verify",
    "https://login.microsoft.com.account-verify.top/",
    "https://impots-gouv.fr/connexion",
    "http://192.168.1.10:8080/login",
    "https://xn--pple-43d.com/",
]


def render(report: Report) -> str:
    lines = [f"\n{report.url}", f"  {ICONS[report.verdict]}  (score {report.score}/100)"]
    lines += [f"   • {f.message}  [+{f.points}]" for f in report.findings if f.points]
    return "\n".join(lines)


def _collect(args: argparse.Namespace) -> list[str]:
    urls = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            urls += [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    if args.stdin:
        urls += [line.strip() for line in sys.stdin if line.strip()]
    return urls


def _run(urls: list[str], as_json: bool) -> int:
    reports = [analyze(u) for u in urls]
    if as_json:
        print(json.dumps([{"url": r.url, "score": r.score, "verdict": r.verdict,
                           "findings": [f.__dict__ for f in r.findings]} for r in reports],
                         ensure_ascii=False, indent=2))
    else:
        for r in reports:
            print(render(r))
        print("\nℹ️  Un score bas n'est PAS une garantie de sécurité. Aucune URL n'a été visitée.")
    return 1 if any(r.verdict != "ok" for r in reports) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phishlens", description="Explique pourquoi une URL est suspecte (hors ligne).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    check = sub.add_parser("check", help="analyser des URL")
    check.add_argument("urls", nargs="*")
    check.add_argument("-f", "--file", help="fichier contenant une URL par ligne")
    check.add_argument("--stdin", action="store_true")
    check.add_argument("--json", action="store_true")
    sub.add_parser("demo", help="exemples fictifs pour tester l'outil")
    args = parser.parse_args(argv)

    if args.cmd == "demo":
        return _run(DEMO_URLS, as_json=False)
    urls = _collect(args)
    if not urls:
        parser.error("aucune URL fournie")
    return _run(urls, args.json)
