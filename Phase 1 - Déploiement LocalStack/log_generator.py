import json
import random
import time
import boto3
from datetime import datetime, timezone

cw_logs = boto3.client(
    "logs",
    endpoint_url="http://localhost:4566",
    region_name="eu-west-3",
    aws_access_key_id="mock_access_key",
    aws_secret_access_key="mock_secret_key",
)

LOG_GROUP = "/aws/ec2/cowrie"
LOG_STREAM = "i-simulated-ec2-instance"

SAMPLE_IPS = [
    "8.8.8.8",
    "109.190.0.1",
    "185.220.101.5",
    "116.31.116.1",
    "185.156.177.10"
]

# IP volontairement réutilisées plus souvent, pour tester le cache GeoIP.
# La première apparition doit déclencher un appel réel à l'API GeoIP
# (cache miss), les suivantes doivent être servies depuis le cache
# DynamoDB (cache hit) tant que le TTL n'est pas expiré.
STICKY_IPS = ["185.220.101.5", "116.31.116.1"]

USERNAMES = ["root", "admin", "support", "ubuntu", "user"]
PASSWORDS = ["123456", "password", "admin123", "root", "1234"]

# Doit correspondre à la variable Terraform `geoip_cache_ttl_seconds`
# (valeur par défaut : 300s). Pour un test rapide, redéployer avec
# `terraform apply -var="geoip_cache_ttl_seconds=60"` et ajuster cette
# valeur en conséquence.
CACHE_TTL_SECONDS = 60


def ensure_log_stream_exists():
    try:
        cw_logs.create_log_stream(logGroupName=LOG_GROUP, logStreamName=LOG_STREAM)
    except cw_logs.exceptions.ResourceAlreadyExistsException:
        pass


def generate_cowrie_log(sticky_ratio=0.4, forced_ip=None):
    """
    Génère un log Cowrie simulé.

    sticky_ratio : probabilité (0-1) d'utiliser une IP de STICKY_IPS plutôt
    qu'une IP totalement aléatoire, pour provoquer volontairement des
    répétitions et pouvoir vérifier le comportement du cache.
    forced_ip : force une IP précise (utile pour un test ciblé et
    reproductible du cache, plutôt que de compter sur le hasard).
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    event_id = random.choice(["cowrie.login.failed", "cowrie.login.success", "cowrie.session.connect"])
    user = random.choice(USERNAMES)
    pwd = random.choice(PASSWORDS)

    if forced_ip:
        ip = forced_ip
    elif random.random() < sticky_ratio:
        ip = random.choice(STICKY_IPS)
    else:
        ip = random.choice(SAMPLE_IPS)

    port = random.randint(1024, 65535)

    # Message dynamique selon l'événement
    if event_id == "cowrie.login.failed":
        msg = f"Login attempt [{user}/{pwd}] failed"
    elif event_id == "cowrie.login.success":
        msg = f"login attempt [{user}/{pwd}] succeeded"
    else:  # cowrie.session.connect
        msg = f"New connection: {ip}:{port} ({random.randint(100000, 999999)}) [SSH connection]"

    payload = {
        "eventid": event_id,
        "timestamp": timestamp,
        "message": msg,
        "system": "cowrie.ssh.factory.CowrieSSHFactory",
        "isError": 0,
        "src_ip": ip,
        "src_port": port,
        "dst_port": 22,
        "session": random.randint(100000, 999999),
        "username": user,
        "password": pwd
    }
    return ip, json.dumps(payload)


def send_logs(count=15, sticky_ratio=0.4, forced_ip=None, label=""):
    """
    Envoie `count` logs simulés vers CloudWatch Logs.
    Affiche la répartition des IP envoyées, pour pouvoir facilement croiser
    ça avec les logs de la Lambda (cache hit/miss attendu par IP).
    """
    ensure_log_stream_exists()

    res = cw_logs.describe_log_streams(
        logGroupName=LOG_GROUP,
        logStreamNamePrefix=LOG_STREAM
    )
    token = res['logStreams'][0].get('uploadSequenceToken')

    now = int(time.time() * 1000)
    ips_sent = []
    log_events = []
    for i in range(count):
        ip, message = generate_cowrie_log(sticky_ratio=sticky_ratio, forced_ip=forced_ip)
        ips_sent.append(ip)
        log_events.append({'timestamp': now + i, 'message': message})

    kwargs = {
        'logGroupName': LOG_GROUP,
        'logStreamName': LOG_STREAM,
        'logEvents': log_events
    }
    if token:
        kwargs['sequenceToken'] = token

    cw_logs.put_log_events(**kwargs)

    tag = f"[{label}] " if label else ""
    print(f"{tag}Envoyé {count} logs à CloudWatch ({LOG_GROUP}/{LOG_STREAM})")
    print(f"{tag}IP envoyées : {ips_sent}")


def run_cache_test_scenario():
    """
    Scénario en 3 vagues pour vérifier manuellement le comportement du
    cache GeoIP (voir protocole de vérification associé) :

    Vague 1 : IP jamais vues -> la Lambda doit logguer [CACHE MISS] pour
              chacune (premier appel réel à l'API GeoIP).
    Vague 2 (peu après) : réutilise une IP de la vague 1, dans la fenêtre
              du TTL -> la Lambda doit logguer [CACHE HIT] pour cette IP.
    Vague 3 (après expiration du TTL) : réutilise la même IP -> la Lambda
              doit à nouveau logguer [CACHE MISS] (entrée expirée).
    """
    test_ip = STICKY_IPS[0]

    print("\n=== VAGUE 1 : première apparition (cache miss attendu) ===")
    send_logs(count=5, forced_ip=test_ip, label="VAGUE 1")

    pause_courte = 15  # largement < CACHE_TTL_SECONDS
    print(f"\nAttente de {pause_courte}s (temps que Firehose bufferise et que la Lambda traite la vague 1)...")
    time.sleep(pause_courte)

    print("\n=== VAGUE 2 : même IP, dans la fenêtre du TTL (cache hit attendu) ===")
    send_logs(count=5, forced_ip=test_ip, label="VAGUE 2")

    pause_longue = CACHE_TTL_SECONDS + 15  # > CACHE_TTL_SECONDS, pour dépasser l'expiration
    print(f"\nAttente de {pause_longue}s pour dépasser le TTL du cache ({CACHE_TTL_SECONDS}s)...")
    time.sleep(pause_longue)

    print("\n=== VAGUE 3 : même IP, après expiration du TTL (cache miss attendu) ===")
    send_logs(count=5, forced_ip=test_ip, label="VAGUE 3")

    print("\nScénario terminé. Consulter les logs CloudWatch de la Lambda "
          "(cowrie-geoip-enrichment) pour vérifier les [CACHE HIT]/[CACHE MISS].")


if __name__ == "__main__":
    # Envoi standard réduit (au lieu de 100), avec un taux de réutilisation
    # d'IP volontaire pour observer le cache en usage normal.
    #send_logs(count=15, sticky_ratio=0.4)

    # Décommenter pour lancer le scénario de test dédié au cache
    # (attention : dure ~ CACHE_TTL_SECONDS + 30 secondes au total)
    run_cache_test_scenario()