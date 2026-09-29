# Phase 1 — Validation locale (LocalStack)

## Objectif

Valider l'intégralité du pipeline de traitement des logs (capture,
enrichissement GeoIP, stockage) avant tout déploiement sur un vrai compte
AWS, sans dépenser un centime ni risquer de mauvaise configuration
réseau/IAM en conditions réelles.

## Schéma d'architecture

![Architecture Phase 1](Architecture.png)

##  Point essentiel : les logs ne viennent pas d'une vraie instance

Dans cette première phase, il ne m'est pas possible de tester le pipeline de donnée depuis l'instance EC2 directement. Car LocalStack Community (la version gratuite) **n'émule pas une vraie VM**.
Une ressource `aws_instance` y est simulée uniquement au niveau de l'API
**aucun système
d'exploitation ne démarre réellement**. Le honeypot Cowrie ne tourne donc
pas en local et je ne peux pas m'y connecter pour générer du traffic. 

Le bloc **"Ingestion de logs simulée"** sur le schéma représente donc
`log_generator.py` : un script Python qui écrit directement dans
CloudWatch Logs via `boto3` (`put_log_events`), en imitant le format
exact des événements que produirait un vrai Cowrie. Le honeypot est présent dans le schéma pour la
cohérence de l'architecture cible, mais **il n'émet rien lui-même dans ce
test** — la flèche en pointillés vers CloudWatch symbolise ce chemin
prévu pour les phases suivantes.

## Utilisation d'un cache à deux niveaux

Chaque IP source à l'origine de traffic sur l'honeypot doit être géolocalisée via un appel à une API externe
(ip-api.com). Sans cache, une IP qui revient plusieurs fois déclencherait
un appel API redondant à chaque fois. Ne sachant pas dutout à quel traffic m'attendre une fois l'honeypot déployé en production, j'ai fais le choix de mettre en place un cache à 2 niveaux pour éviter au maximum les échanges inutlies.

- **Niveau 1 (mémoire)** : un dictionnaire Python local, valable
  uniquement pendant l'exécution d'une fonction Lambda. Évite les
  appels redondants quand plusieurs logs du même lot (traités dans la même Lambda) concernent la même IP.
- **Niveau 2 (DynamoDB)** : une table avec un TTL court de 300 secondes, qui persiste **entre** deux invocations
  Lambda séparées. La Lambda vérifie elle-même le champ `expires_at`
  avant d'utiliser une entrée, plutôt que de se fier uniquement à la
  suppression automatique DynamoDB (qui n'est pas instantanée).

## Contraintes rencontrées

Deux limites propres à LocalStack Community ont façonné cette phase :

1. **Pas de vraie EC2** (expliqué ci-dessus) → d'où le recours à
   `log_generator.py` plutôt qu'à un vrai Cowrie.
2. **Pas d'Athena** (réservé à l'offre Pro de
   LocalStack) → l'étape d'analyse SQL n'est donc pas présente dans cette
   phase, elle ne sera testée qu'au déploiement en production fermée en Phase 2.
3. **Firehose non disponible dans le Free-Tier AWS** → Initialement, j'avais intégré Kinesis Data Firehose, qui faisait le pont entre CloudWatch et un bucket de réception des logs au format JSON. Cela m'aurait permis de contrôler explicitement le buffering (taille/durée) et donc d'invoquer la Lambda moins souvent, avec des lots plus gros. Le subscription filter natif de CloudWatch Logs vers Lambda assure bien le fonctionnement (les événements sont toujours regroupés avant invocation), mais ce regroupement est géré en interne par AWS, sans paramètre que je puisse ajuster — ce qui mène à des invocations plus fréquentes qu'avec Firehose. 

## Limite éventuelle à l'échelle et comment la parer

- **ip-api.com** (l'API de géolocalisation utilisée) limite gratuitement
  à 45 requêtes par minute. Le cache réduit fortement les appels sur les
  IP déjà vues, mais un afflux de nombreuses IP *différentes* en peu de
  temps pourrait potentiellemnt dépasser ce seuil, c'est à garder en tête. Ici, le fait que je ne puisse pas prédire l'IP qui sera attribuée à chaque lambda et par conséquent savoir si sa limite d'IP résolvable grâce à l'API est neuve, bloque un peu les solutions. 
  Je pense que commencer par diminuer mon besoin de résolution d'IP grâce au cache à double niveau est déjà un bon début.

## Résultats obtenus et ce qu'ils prouvent

Le fichier [`fonctionnement_ETL`](fonctionnement_ETL)
contient la sortie complète d'une exécution du scénario de test dédié au
cache (`run_cache_test_scenario()` dans `log_generator.py`), en 3 vagues :

| Vague | Ce qui est envoyé | Résultat observé | Ce que ça prouve |
|---|---|---|---|
| 1 | 5 logs, IP jamais vue | `[CACHE MISS]` puis 4x `[CACHE HIT][L1-memoire]` | Le cache mémoire (L1) évite bien les appels redondants au sein d'une même invocation |
| 2 (15s après) | 5 logs, même IP | `[CACHE HIT][L2-dynamodb]` puis 4x `[CACHE HIT][L1-memoire]` | Le cache DynamoDB (L2) persiste bien **entre deux invocations Lambda séparées**, dans la fenêtre du TTL |
| 3 (après expiration du TTL) | 5 logs, même IP | Un nouveau cycle miss/hit | Le TTL est correctement respecté : l'entrée expirée n'est plus réutilisée |

Chaque vague produit un fichier JSON dans le bucket `honeypot-enriched-logs`
(visible dans le log de preuve), contenant les événements enrichis avec un
champ `geoip` complet (`country`, `latitude`, `longitude`), confirmant que
le pipeline complet — capture, désérialisation, enrichissement, cache,
écriture S3 — fonctionne de bout en bout.

## Fichiers de cette phase

- [`main.tf`](main.tf) — infrastructure Terraform ciblant LocalStack
- [`log_generator.py`](log_generator.py) — générateur de logs simulés + scénario de test du cache
- [`Guide_Lancement.md`](Guide_Lancement.md.md) — déroulé complet pour reproduire ces tests
- [`Enriched_Logs_Content`](Enriched_Logs_Content/) — contenu des logs enrichis par la fonction lambda
- [`Lambda_Logs`](Lambda_Logs/) — contenu des logs crées par la lambda lors des test
