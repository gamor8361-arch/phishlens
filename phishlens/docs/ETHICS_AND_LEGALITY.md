# Éthique et légalité

## Principe : analyser sans attaquer
`phishlens` est un outil **strictement défensif et passif**.

| Garantie | Comment elle est assurée |
|---|---|
| Ne visite jamais les URL | Analyse purement textuelle ; un test automatisé (`test_never_touches_network`) échoue si une connexion est ouverte |
| Ne collecte aucune donnée | Aucun fichier, journal, télémétrie ni envoi à un tiers |
| Aucun scan, aucune intrusion | Pas de requête DNS, pas de balayage de ports, pas d'interaction avec les serveurs analysés |
| Exemples inoffensifs | Les URL de démonstration sont fictives et ne sont jamais ouvertes |

Cela évite les risques classiques : exposer l'utilisateur à un site malveillant, ou toucher à des systèmes qui ne t'appartiennent pas.

## Usages prévus
- Apprendre à reconnaître les signaux d'un lien frauduleux (sensibilisation)
- Aider à trier des liens avant de cliquer
- Support pédagogique pour cours ou ateliers de cybersécurité

## Ce que l'outil n'est pas
- **Pas une preuve** : une heuristique peut se tromper (faux positifs comme faux négatifs).
- **Pas une garantie** : un score bas ne signifie pas qu'un lien est sûr. Un site de phishing parfaitement propre sur le plan syntaxique passera inaperçu.
- **Pas un remplaçant** des services spécialisés (navigateur, antivirus, Google Safe Browsing).

## Limites techniques assumées
- Liste de marques courte, à étendre.
- Domaine enregistrable approximé (pas de *Public Suffix List* complète).
- Pondérations choisies à la main, non calibrées sur un jeu de données réel.

## Si tu reçois un vrai phishing
Ne clique pas, ne réponds pas, et signale-le au service de ton pays (par exemple Signal Spam ou cybermalveillance.gouv.fr en France, maCERT au Maroc), ou au service concerné (banque, plateforme).

## Utilisation responsable
Ne l'utilise pas pour fabriquer des URL qui échappent à la détection : ce serait l'inverse de son objectif.
