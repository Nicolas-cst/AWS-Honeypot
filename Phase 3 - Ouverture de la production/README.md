# Version 3.0.0 — Ouverture du honeypot au public

## Pourquoi cette version

La version 2.2 avait un honeypot complet, mais fermé : seule mon IP pouvait s'y
connecter. Le pipeline, la carte, la supervision et le kill switch étaient
construits et testés, mais aucun attaquant réel n'avait encore touché
l'instance. Cette version fait le dernier pas : **ouvrir le port 22 à Internet**.

À partir de cette version, le projet n'est plus découpé en phases mais en
**versions**. La 3.0.0 correspond à ce qui a été mis en production à l'issue de
la phase 3.

## Objectif

1. **Ouvrir le honeypot à tout Internet**, sans changer le reste de
   l'architecture.
2. **Pouvoir refermer aussitôt** si quelque chose tourne mal, avec une seule
   commande.
3. **Vérifier que le pipeline reçoit de vrais attaquants** : connexions, logins
   et commandes jusqu'à la carte.

## Ce qui change

Presque rien dans le code : l'ouverture se résume à deux couches réseau.

| Couche | Avant (version 2.2) | Maintenant |
|---|---|---|
| Security group | TCP 22 depuis mon IP (`admin_test_cidr`) | TCP 22 depuis `0.0.0.0/0` |
| NACL, entrée (règle 100) | TCP 22 depuis mon IP | TCP 22 depuis `0.0.0.0/0` |
| NACL, sortie (règle 110) | ports 1024-65535 vers mon IP | ports 1024-65535 vers `0.0.0.0/0` |

Le NACL est sans état : il faut donc ouvrir la **réponse** (la sortie vers les
ports éphémères) en plus de l'entrée, sinon les connexions entrantes ne
reçoivent jamais de réponse.

Tout le reste est inchangé : le security group garde sa sortie limitée à
HTTPS, DNS et au VPC, les règles `iptables` isolent toujours le conteneur, Cowrie refuse
toujours de démarrer si le test de sortie échoue, et l'administration passe
uniquement par Systems Manager. Le SSH réel de l'instance reste masqué.

## Une bascule en une commande

L'ouverture est pilotée par une seule variable Terraform, `open_to_internet`.
Si l'instance se comporte de façon suspecte, que le budget dérape ou que je veux
simplement couper, je referme tout avec :

```bash
terraform apply -var open_to_internet=false
```

Le security group et le NACL reviennent alors à mon IP seule, sans recréer
l'instance ni toucher au pipeline. Les connexions déjà établies sont coupées
par le NACL, puisqu'il est sans état. La même commande avec `=true` rouvre le
honeypot.

C'est un interrupteur volontairement manuel, à ne pas confondre avec le
*kill switch* : ce dernier réagit tout seul à un finding GuardDuty et isole
l'instance. L'interrupteur, lui, ferme l'accès entrant.

## Ce qui protège le honeypot une fois ouvert

L'ouverture n'a été faite qu'après la fin de la version 2.2, dont toutes les
protections restent actives :

- **Le conteneur ne peut ni sortir ni atteindre l'hôte ni IMDS**, vérifié avant
  chaque démarrage de Cowrie.
- **GuardDuty surveille l'instance** et le kill switch la met en quarantaine si
  elle attaque à son tour ou si ses credentials sont utilisés ailleurs.
- **Le budget mensuel de 10 $** prévient par email.
- **Les données des attaquants restent traitées comme non fiables** :
  liste blanche de commandes, validation du code pays, `textContent` dans la
  page.

## Premiers résultats

Quelques heures après l'ouverture, le trafic est faible, mais les premiers
scans sont arrivés jusqu'au pipeline. Voici les deux premières lignes
enregistrées pour une même session, telles que le *processor* les écrit dans le
bucket `processed_logs` :

```json
{
  "event_date": "2026-11-24",
  "ts": "2026-11-24T11:53:49.884893Z",
  "src_ip": "217.76.57.218",
  "session": "b4774fe20b43",
  "event": "connect",
  "country": "FR"
}
{
  "event_date": "2026-11-24",
  "ts": "2026-11-24T11:53:49.973870Z",
  "src_ip": "217.76.57.218",
  "session": "b4774fe20b43",
  "event": "login_success",
  "username": "root",
  "password": "ubuntu",
  "country": "FR"
}
{
  "event_date": "2026-11-24",
  "ts": "2026-11-24T11:54:03.758454Z",
  "src_ip": "217.76.57.218",
  "session": "b4774fe20b43",
  "event": "command",
  "command": "chmod",
  "command_raw": "chmod +x ./.4551250110790457338/sshd;nohup ./.4551250110790457338/sshd 103.161.16.196 179.61.154.138 117.137.24.4 8.217.239.169 82.157.172.140 46.101.196.16 43.226.53.45 117.156.168.201 101.132.83.252 15.235.193.26 117.89.254.46 121.224.5.228 116.162.182.2 202.107.164.75 169.58.231.6 123.180.188.162 51.15.19.10 210.16.103.246 202.104.14.68 221.194.148.34 27.0.135.12 101.59.102.62 173.249.63.116 13.53.193.69 45.55.30.94 101.36.114.181 160.191.89.7 49.72.111.25 101.36.228.201 128.14.232.142 39.175.51.58 101.91.114.194 103.186.97.118 114.111.21.42 3.137.165.118 111.45.29.88 80.221.46.82 49.84.226.110 159.203.108.2 117.68.104.171 118.122.147.195 203.189.196.168 112.28.209.199 49.115.217.143 218.98.97.7 220.168.118.133 43.206.235.180 180.163.67.45 96.125.137.54 158.51.96.38 54.253.205.92 &",
  "country": "FR"
}
```

La connexion et le login sont séparés de moins de 100 millisecondes : c'est un
outil automatique qui teste des identifiants courants (`root` / `ubuntu`).
Cowrie accepte volontairement ce type de login, ce qui permet à l'attaquant
d'aller plus loin et de taper des commandes.

## Ce que ces résultats montrent aussi

Le volume est trop faible pour des analyses intéressantes. Avec une seule
instance, donc une seule adresse IP, je ne vois qu'une petite partie de ce qui
scanne Internet. Il faudrait des semaines pour obtenir un échantillon
exploitable.

J'ai donc décidé de **multiplier les instances** plutôt que d'attendre.

## Les prochaines versions

| Version | Contenu |
|---|---|
| **3.0.0** | Ouverture au public (cette version) |
| **3.1.0** | Plusieurs instances EC2 en parallèle dans le même sous-réseau, toutes reliées au même pipeline de traitement, pour augmenter le trafic reçu |
| **3.2.0** | Utilisation de l'API AbuseIPDB et visualisation plus développée sur la carte interactive |

La 3.1.0 demande de repenser le kill switch : il ne devra plus passer par le
NACL du sous-réseau entier, pour n'isoler que l'instance à l'origine du finding
sans couper les autres.

## Fichiers de cette version

- [`main.tf`](main.tf) : toute l'infrastructure Terraform, avec la variable
  `open_to_internet`.
- [`index.html`](index.html/) : carte mise à jour
