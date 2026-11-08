"""Analyse heuristique d'URL. Aucun accès réseau : tout est calculé localement."""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlsplit

# Marque -> domaines officiels (domaine enregistrable). Liste volontairement courte et lisible.
BRANDS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com"}),
    "google": frozenset({"google.com", "google.fr", "gstatic.com", "youtube.com"}),
    "microsoft": frozenset({"microsoft.com", "live.com", "office.com", "microsoftonline.com"}),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "amazon": frozenset({"amazon.com", "amazon.fr", "amazon.co.uk", "amazonaws.com"}),
    "facebook": frozenset({"facebook.com", "fb.com"}),
    "instagram": frozenset({"instagram.com"}),
    "netflix": frozenset({"netflix.com"}),
    "github": frozenset({"github.com"}),
    "linkedin": frozenset({"linkedin.com"}),
    "dropbox": frozenset({"dropbox.com"}),
    "laposte": frozenset({"laposte.fr"}),
    "ameli": frozenset({"ameli.fr"}),
    "impots": frozenset({"impots.gouv.fr"}),
    "orange": frozenset({"orange.fr", "orange.com"}),
}
MULTI_SUFFIXES = frozenset({"co.uk", "com.au", "com.br", "gouv.fr", "co.ma", "gov.ma", "co.jp"})
SHORTENERS = frozenset({"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly"})
RISKY_TLDS = frozenset({"zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click"})
KEYWORDS = ("login", "signin", "verify", "verif", "secure", "account", "update", "confirm",
            "password", "wallet", "connexion", "bank")
LEET = str.maketrans("0134578", "oleasts")


@dataclass(frozen=True)
class Finding:
    rule: str
    points: int
    message: str


@dataclass(frozen=True)
class Report:
    url: str
    score: int
    verdict: str  # "ok" | "suspect" | "dangerous"
    findings: tuple[Finding, ...]


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def shannon_entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values()) if text else 0.0


def registered_domain(host: str) -> tuple[str, str]:
    """Retourne (étiquette principale, domaine enregistrable). Approximation sans liste publique."""
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return labels[-3], ".".join(labels[-3:])
    if len(labels) >= 2:
        return labels[-2], ".".join(labels[-2:])
    return host, host


def _brand_finding(host: str, registered: str) -> Finding | None:
    tokens = [t for t in re.split(r"[.\-_]", host) if t]
    for brand, official in BRANDS.items():
        if registered in official:
            continue
        for token in tokens:
            normalized = token.translate(LEET)
            if token == brand:
                return Finding("brand_third_party", 30,
                               f"Contient « {brand} » mais le domaine réel est {registered}")
            if normalized == brand:
                return Finding("brand_lookalike", 35,
                               f"« {token} » imite « {brand} » (chiffres à la place de lettres)")
            if len(brand) >= 6 and len(token) >= 6:
                limit = 1 if len(brand) < 7 else 2
                if 0 < levenshtein(normalized, brand) <= limit:
                    return Finding("brand_lookalike", 35, f"« {token} » ressemble à « {brand} » (faute volontaire ?)")
    return None


def analyze(url: str) -> Report:
    raw = url.strip()
    parts = urlsplit(raw if "//" in raw else "//" + raw)
    host = (parts.hostname or "").lower()
    findings: list[Finding] = []

    def add(rule: str, points: int, message: str) -> None:
        findings.append(Finding(rule, points, message))

    if not host:
        return Report(raw, 0, "ok", (Finding("unparsable", 0, "Aucun nom d'hôte détecté"),))

    if parts.scheme == "http":
        add("no_https", 10, "Connexion non chiffrée (http)")
    if parts.username is not None:
        add("userinfo", 25, "Contient « @ » : le vrai site est après le @, pas avant")
    try:
        ipaddress.ip_address(host)
        add("ip_host", 25, "Adresse IP à la place d'un nom de domaine")
    except ValueError:
        pass
    if any(label.startswith("xn--") for label in host.split(".")):
        add("punycode", 25, "Nom en punycode (xn--) : peut cacher des lettres d'un autre alphabet")
    elif any(ord(ch) > 127 for ch in host):
        add("non_ascii", 25, "Caractères non latins dans le domaine (attaque homographe possible)")
    try:
        if parts.port not in (None, 80, 443):
            add("odd_port", 10, f"Port inhabituel ({parts.port})")
    except ValueError:
        add("odd_port", 10, "Port invalide")

    sld, registered = registered_domain(host)
    if host in SHORTENERS or registered in SHORTENERS:
        add("shortener", 15, "Lien raccourci : la destination est masquée")
    if len(host.split(".")) > 4:
        add("deep_subdomain", 10, "Beaucoup de sous-domaines (technique pour brouiller la lecture)")
    if not sld.startswith("xn--") and sld.count("-") >= 3:
        add("hyphens", 10, "Domaine truffé de tirets")
    if host.rsplit(".", 1)[-1] in RISKY_TLDS:
        add("risky_tld", 10, f"Extension .{host.rsplit('.', 1)[-1]} fréquemment abusée (signal faible)")
    if "-" not in sld and len(sld) >= 10 and shannon_entropy(sld) > 3.4:
        add("random_domain", 10, "Nom de domaine à l'aspect aléatoire")

    brand = _brand_finding(host, registered)
    if brand:
        findings.append(brand)

    hits = [k for k in KEYWORDS if k in (host + parts.path).lower()]
    hits = [k for k in hits if not any(k != o and k in o for o in hits)]  # pas de double comptage
    if hits:
        add("keywords", min(15, 5 * len(hits)), "Mots incitant à agir : " + ", ".join(hits[:3]))
    if re.search(r"(url|redirect|next|goto)=https?", parts.query.lower()):
        add("open_redirect", 10, "Paramètre de redirection vers une autre URL")
    if len(raw) > 100:
        add("long_url", 5, "URL très longue")

    score = min(100, sum(f.points for f in findings))
    verdict = "ok" if score < 20 else "suspect" if score < 50 else "dangerous"
    return Report(raw, score, verdict, tuple(findings))
