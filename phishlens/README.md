# 🔍 phishlens

> Colle une URL, **comprends pourquoi** elle ressemble à du phishing. Hors ligne, sans jamais visiter le lien.

![CI](https://github.com/TON-PSEUDO/phishlens/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies](https://img.shields.io/badge/dépendances-0-brightgreen)
![License](https://img.shields.io/badge/licence-MIT-lightgrey)

## Pourquoi ce projet ?
Le phishing reste l'un des points d'entrée les plus courants des cyberattaques, et il vise surtout des gens non techniques. La plupart des outils répondent « dangereux / pas dangereux ». `phishlens` **explique** : il montre les indices, pour que chacun apprenne à les repérer seul.

## Exemple
```
$ phishlens check "http://paypa1-secure-login.xyz/verify"

http://paypa1-secure-login.xyz/verify
  🔴 Très suspect  (score 70/100)
   • Connexion non chiffrée (http)  [+10]
   • Extension .xyz fréquemment abusée (signal faible)  [+10]
   • « paypa1 » imite « paypal » (chiffres à la place de lettres)  [+35]
   • Mots incitant à agir : login, verify, secure  [+15]
```

## Ce qu'il détecte
| Signal | Exemple |
|---|---|
| Imitation de marque (leetspeak, faute volontaire) | `paypa1`, `goggle` |
| Marque sur un domaine tiers | `login.microsoft.com.account-verify.top` |
| Attaque homographe / punycode | `xn--pple-43d.com` |
| Astuce du `@` | `https://google.com@evil.example` |
| IP, port inhabituel, `http`, lien raccourci | `http://192.168.1.10:8080` |
| Sous-domaines en cascade, redirections ouvertes, mots incitatifs | `…?redirect=https://…` |

## Installation et utilisation
```bash
git clone https://github.com/TON-PSEUDO/phishlens.git && cd phishlens
pip install -e .

phishlens demo                         # exemples fictifs
phishlens check "https://exemple.com"
phishlens check -f liens.txt --json    # lot de liens, sortie pour scripts
```
Code de sortie : `0` aucun signal fort · `1` au moins un lien suspect.

## Architecture
```
src/phishlens/
├── core.py   # règles et scoring, fonctions pures, zéro réseau
└── cli.py    # interface, JSON, codes de sortie
tests/        # 16 tests, dont la preuve « aucun accès réseau »
docs/ETHICS_AND_LEGALITY.md
```
Chaque règle produit un `Finding` (identifiant, points, explication) : le score est la somme plafonnée à 100, donc **entièrement explicable et auditable**.

## Tests
```bash
python -m unittest discover -s tests -v
```

## Éthique et limites
Outil **défensif et passif** : il ne visite aucun lien, ne collecte rien et ne scanne rien. C'est une heuristique, pas une preuve : un score bas ne garantit pas la sécurité. Détails dans [ETHICS_AND_LEGALITY.md](docs/ETHICS_AND_LEGALITY.md).

## Pistes d'évolution
- [ ] Étendre la liste de marques (fichier de configuration)
- [ ] Utiliser la *Public Suffix List* complète
- [ ] Calibrer les poids sur un jeu de données ouvert, avec courbe précision/rappel
- [ ] Analyse d'en-têtes d'e-mails (SPF/DKIM/DMARC) fournis en local
- [ ] Extension de navigateur

## Licence
MIT
