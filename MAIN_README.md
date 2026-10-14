# 🍯 Honeypot AWS (Cowrie) — Carte des attaques en quasi temps réel

Un honeypot SSH **Cowrie** déployé sur AWS avec **Terraform**, qui capture les tentatives d'intrusion, les enrichit (GeoIP), les stocke, les analyse et les affiche sur un **globe 3D interactif** (d3.js).

Le projet est organisé en **phases successives**, chacune avec un objectif distinct.
Il s'agit de mes premiers déploiment sur le cloud, j'apprend donc à mesure que j'avance dans le projet.
Certaines phases prévues peuvent évoluer. Mon objectif n'est pas de tout prévoir à l'avance mais de découvrir au fûr et à mesure.

Aussi, l'objectif de ce repo n'est, pour l'instant, pas de vous permettre de déployer l'honeypot dans votre infra. 
Je m'en sers pour documenter mon travail, suivre mes différents choix techniques et pouvoir présenter mon projet clairement, je l'epsère.

## Vue d'ensemble

| Phase | Objectif | État |
|---|---|---|
| **1** | Prototype sous LocalStack | ✅ Terminée |
| **2.1** | Déploiement réel sur AWS, accès limité à mon IP | ✅ Terminée |
| **2.2** | Version 2 : pipeline incrémental + durcissement sécurité | 🟡 **En cours** |
| **3** | Mise en production (ouverture au trafic public) | ⏳ À venir |
| **4** | Analyse des résultats après plusieurs jours/semaines | ⏳ À venir |

## Détail des phases

### Phase 1 — LocalStack
Valider le pipeline de traitement des logs (capture, enrichissement GeoIP, stockage) **sans dépenser un centime** ni risquer de mauvaise configuration réseau/IAM en conditions réelles.
> Cette phase visait avant tout à prendre en main LocalStack. Elle ne correspond pas à l'architecture finale et n'a volontairement pas été réutilisée dans les phases suivantes (manque de temps).

### Phase 2.1 — Déploiement AWS de validation
Déployer le honeypot sur une vraie instance AWS, **accessible uniquement depuis mon IP**, pour valider le pipeline de bout en bout : *capture → enrichissement → stockage → analyse → visualisation*.
Objectif atteint, mais cette version n'est **pas prête pour un trafic public** : carte rafraîchie via Athena (coût et performances qui se dégradent avec le volume) et sécurité à renforcer.

### Phase 2.2 — Version 2 (en cours)
Corriger les défauts de la 2.1 **avant** l'ouverture publique, selon deux axes :

1. **Traitement des données** : remplacer le rafraîchissement de la carte via Athena par une **agrégation incrémentale** (Lambda + DynamoDB), à coût constant.
2. **Sécurité** (prioritaire) : rien ne sort du conteneur ni du VPC, les credentials de l'instance ne peuvent pas fuiter, et je suis alerté en cas d'incident ou de dérive de coût.

Elle est réalisée par étapes, chacune avec code, tests et validation :

| Étape | Contenu | État |
|---|---|---|
| 0 | Préparation (git, sauvegarde de l'état Terraform) | ✅ |
| 1 | Alertes SNS, budget 10 $/mois, logs Lambda, rôles IAM minimaux | ✅ |
| 2 | Durcissement EC2 : IMDSv2, iptables, test de sortie *fail-closed*, accès par SSM | ✅ |
| 3 | NACL dédié au sous-réseau | ✅ |
| 4 | Pipeline d'analyse : Lambda `processor`, DynamoDB, S3, Glue/Athena | ✅ |
| 5 | Pipeline de publication : Lambda `publisher`, EventBridge, CloudFront, carte | 🟡 Code prêt, déploiement en cours |
| 6 | Monitoring (dashboard, alarmes) + GuardDuty | ⏳ |
| 7 | Kill switch : infrastructure de quarantaine | ⏳ |
| 8 | Kill switch réel + exercice d'incident | ⏳ |

### Phase 3 — Mise en production
Ouvrir la version 2.2 au trafic public, corriger les bugs éventuels et affiner les paramètres.

### Phase 4 — Analyse des résultats
Exploiter les données collectées après plusieurs jours/semaines de production : origines, identifiants testés, commandes exécutées.

## Présentation succinte de l'architecure du repo

Le répertoire est organisé par phase d'avancement, c'est ce qui me parait être le plus logique. 
Vous trouverez un readme dans chaque phase, présentant clairement son objectif et l'architecture utilisée pour l'atteindre. 
