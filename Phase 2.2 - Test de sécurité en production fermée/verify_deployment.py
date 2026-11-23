#!/usr/bin/env python3
"""Vérifie le déploiement réel du honeypot, étape par étape (0 à 8).

Reprend les tests du plan de migration et les lance contre le compte AWS.
À lancer depuis le dossier qui contient main.tf (il lit `terraform output`) :

    python3 verify_deployment.py               # lecture seule, toutes les étapes
    python3 verify_deployment.py --phase 2 5   # seulement les étapes 2 et 5
    python3 verify_deployment.py --actif       # ajoute les tests qui écrivent
    python3 verify_deployment.py --sans-plan   # saute le terraform plan (lent)

Sans --actif, le script ne modifie rien. Il lance seulement, sur l'instance et
via Systems Manager, quelques commandes de contrôle (curl, iptables -C, docker run
d'un conteneur alpine éphémère).

Avec --actif, il ajoute des tests qui écrivent dans AWS et envoient des emails :
message SNS de test, alarmes forcées puis remises à OK, findings GuardDuty
d'exemple, invocations du processor et du publisher, requête Athena, connexion
au port 22. Les compteurs et objets créés par ces tests sont supprimés à la fin.

Le kill switch n'est jamais invoqué : son exercice réel reste une procédure
manuelle (runbook de restauration).

Prérequis : boto3, terraform, des identifiants AWS (profil) avec les droits
d'administration du projet. Code de sortie 1 si au moins un test échoue.
"""
import argparse
import base64
import gzip
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    sys.exit("boto3 est requis : pip install boto3")

ROOT = os.path.dirname(os.path.abspath(__file__))
REGION = 'eu-west-3'
BATCHES_TABLE = 'honeypot-batches'
LAMBDA_NAMES = ('honeypot-processor', 'honeypot-publisher', 'honeypot-kill-switch')
ALARMS = (
    'honeypot-cowrie-log-volume-high',
    'honeypot-processor-errors',
    'honeypot-kill-switch-errors',
    'honeypot-kill-switch-throttles',
    'honeypot-kill-switch-dlq-not-empty',
)
RULE_A = 'honeypot-killswitch-actor-activity'
RULE_B = 'honeypot-killswitch-credential-exfiltration'
RULE_C = 'honeypot-guardduty-findings-to-sns'
PUBLISHER_RULE = 'honeypot-publisher-refresh'

# Liste blanche du processor (89 commandes), utilisée pour le test du gros lot.
WHITELIST = (
    'ls cd pwd cat echo uname whoami id w who last uptime free df du ps top '
    'kill pkill killall env export unset history crontab sudo su sh bash '
    'busybox wget curl tftp ftp nc ncat netstat ss ifconfig ip ping ssh scp '
    'chmod chown mkdir rm rmdir cp mv touch ln tar gzip gunzip unzip grep '
    'egrep head tail wc sort uniq cut awk sed find which whereis lscpu lsmod '
    'dmesg mount umount dd nohup sleep python python3 perl php gcc make '
    'systemctl service passwd useradd adduser exit'
).split()


# =============================================================== affichage

class Rapport:
    def __init__(self):
        self.ok = 0
        self.echecs = []
        self.manuels = []

    def titre(self, texte):
        print(f"\n=== {texte} ===")

    def check(self, libelle, fn):
        """fn() renvoie True/False ou (bool, détail). Une exception = échec."""
        try:
            res = fn()
            ok, detail = res if isinstance(res, tuple) else (res, '')
        except ClientError as exc:
            ok, detail = False, f"{exc.response['Error'].get('Code')} : {exc.response['Error'].get('Message')}"
        except Exception as exc:
            ok, detail = False, f"{type(exc).__name__} : {exc}"
        if ok:
            self.ok += 1
            print(f"  OK     {libelle}" + (f" ({detail})" if detail else ''))
        else:
            self.echecs.append(libelle)
            print(f"  ECHEC  {libelle}" + (f" : {detail}" if detail else ''))
        return ok

    def manuel(self, libelle):
        self.manuels.append(libelle)
        print(f"  MANUEL {libelle}")

    def info(self, texte):
        print(f"         {texte}")


# =============================================================== contexte

class Contexte:
    def __init__(self, args):
        self.args = args
        self.out = self._terraform_outputs()
        s = boto3.session.Session(region_name=REGION)
        names = ('ec2', 'iam', 'logs', 'sns', 'lambda', 'dynamodb', 's3', 'glue', 'athena',
                 'events', 'cloudwatch', 'guardduty', 'sqs', 'ssm', 'sts')
        self.c = {n: s.client(n) for n in names}
        self.c['budgets'] = s.client('budgets', region_name='us-east-1')
        self.account = self.c['sts'].get_caller_identity()['Account']
        self.instance_id = self.out['ec2_instance_id']
        self._instance = None
        self._ssm_results = None

    @staticmethod
    def _terraform_outputs():
        try:
            raw = subprocess.run(['terraform', 'output', '-json'], cwd=ROOT, capture_output=True,
                                 text=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError) as exc:
            sys.exit(f"terraform output impossible depuis {ROOT} : {exc}")
        out = {k: v['value'] for k, v in json.loads(raw).items()}
        if not str(out.get('ec2_instance_id', '')).startswith('i-'):
            sys.exit(f"Aucun ID d'instance dans les outputs : lance le script depuis le dossier de main.tf ({ROOT}).")
        return out

    def instance(self):
        if self._instance is None:
            r = self.c['ec2'].describe_instances(InstanceIds=[self.instance_id])
            self._instance = r['Reservations'][0]['Instances'][0]
        return self._instance

    def arn_instance(self, iid=None):
        return f"arn:aws:ec2:{REGION}:{self.account}:instance/{iid or self.instance_id}"

    def lambda_conf(self, name):
        return self.c['lambda'].get_function_configuration(FunctionName=name)

    def role_name(self, function_name):
        return self.lambda_conf(function_name)['Role'].rsplit('/', 1)[-1]

    def scan_stats(self):
        items = {}
        pager = self.c['dynamodb'].get_paginator('scan')
        for page in pager.paginate(TableName=self.out['honeypot_stats_table_name']):
            for it in page['Items']:
                items[it['pk']['S']] = int(it.get('count', {}).get('N', '0'))
        return items


def sim(ctx, role_arn, action, resource, policy_arn=None):
    kw = dict(PolicySourceArn=role_arn, ActionNames=[action], ResourceArns=[resource])
    if policy_arn:
        kw['ContextEntries'] = [{'ContextKeyName': 'iam:PolicyARN', 'ContextKeyValues': [policy_arn],
                                 'ContextKeyType': 'string'}]
    return ctx.c['iam'].simulate_principal_policy(**kw)['EvaluationResults'][0]['EvalDecision']


def expect_sim(ctx, role_arn, action, resource, attendu, policy_arn=None):
    got = sim(ctx, role_arn, action, resource, policy_arn)
    ok = (got == 'allowed') if attendu == 'allowed' else (got != 'allowed')
    return ok, got


def http_get(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'verify-deployment'})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), b''


def policy_statements(doc):
    st = doc.get('Statement', [])
    return st if isinstance(st, list) else [st]


def as_list(v):
    return v if isinstance(v, list) else [v]


# =============================================================== étape 0

def etape_0(ctx, r):
    r.titre("Étape 0 - Préparation")
    if ctx.args.sans_plan:
        r.info("terraform plan ignoré (--sans-plan)")
    else:
        def plan():
            p = subprocess.run(['terraform', 'plan', '-detailed-exitcode', '-input=false', '-no-color',
                                '-lock=false'], cwd=ROOT, capture_output=True, text=True)
            if p.returncode == 0:
                return True, 'No changes'
            if p.returncode == 2:
                resume = [l for l in p.stdout.splitlines() if l.startswith('Plan:')]
                return False, (resume[0] if resume else 'des changements sont prévus')
            return False, (p.stderr.strip().splitlines() or ['erreur'])[-1]
        r.check("terraform plan : aucun changement", plan)

    def log_groups():
        resp = ctx.c['logs'].describe_log_groups(logGroupNamePrefix='/aws/lambda/')
        present = {g['logGroupName'] for g in resp['logGroups']}
        attendus = {f'/aws/lambda/{n}' for n in LAMBDA_NAMES}
        manquants = attendus - present
        anciens = sorted(g for g in present - attendus
                         if any(k in g for k in ('honeypot', 'enrich', 'map', 'athena', 'cowrie')))
        return not manquants and not anciens, (
            f"manquants {sorted(manquants)}, anciens {anciens}" if manquants or anciens
            else f"{len(attendus)} groupes, aucun reste de l'ancienne architecture")
    r.check("Groupes de logs Lambda : tous déclarés, aucun reste", log_groups)


# =============================================================== étape 1

def etape_1(ctx, r):
    r.titre("Étape 1 - Alertes et garde-fous financiers")
    topic = ctx.out['sns_alerts_topic_arn']

    def abonnement():
        subs = ctx.c['sns'].list_subscriptions_by_topic(TopicArn=topic)['Subscriptions']
        emails = [s for s in subs if s['Protocol'] == 'email']
        confirmes = [s for s in emails if s['SubscriptionArn'].startswith('arn:')]
        return bool(confirmes), f"{len(confirmes)}/{len(emails)} abonnement(s) email confirmé(s)"
    r.check("Abonnement email au topic confirmé", abonnement)

    def topic_policy():
        pol = json.loads(ctx.c['sns'].get_topic_attributes(TopicArn=topic)['Attributes']['Policy'])
        sids = {s.get('Sid') for s in policy_statements(pol)}
        attendus = {'AllowOwnerAccount', 'AllowBudgetsPublish', 'AllowEventBridgePublish',
                    'AllowCloudWatchAlarmsPublish'}
        return attendus <= sids, f"manquent : {sorted(attendus - sids)}" if attendus - sids else ''
    r.check("Policy du topic : propriétaire, Budgets, EventBridge, CloudWatch", topic_policy)

    def budget():
        b = ctx.c['budgets'].describe_budget(AccountId=ctx.account, BudgetName='honeypot-monthly-budget')['Budget']
        notes = ctx.c['budgets'].describe_notifications_for_budget(
            AccountId=ctx.account, BudgetName='honeypot-monthly-budget')['Notifications']
        seuils = sorted(int(float(n['Threshold'])) for n in notes)
        limite = float(b['BudgetLimit']['Amount'])
        return limite == 10 and seuils == [70, 100], f"{limite:g} {b['BudgetLimit']['Unit']}, alertes {seuils} %"
    r.check("Budget mensuel de 10 $ avec alertes à 70 % et 100 %", budget)

    def retention():
        noms = [f'/aws/lambda/{n}' for n in LAMBDA_NAMES] + ['/aws/ec2/cowrie']
        mauvais = []
        for n in noms:
            g = [x for x in ctx.c['logs'].describe_log_groups(logGroupNamePrefix=n)['logGroups']
                 if x['logGroupName'] == n]
            if not g or g[0].get('retentionInDays') != 14:
                mauvais.append(n)
        return not mauvais, f"hors 14 jours : {mauvais}" if mauvais else f"{len(noms)} groupes à 14 jours"
    r.check("Rétention des logs : 14 jours partout", retention)

    def roles_lambda():
        problemes = []
        for fn in LAMBDA_NAMES:
            role = ctx.role_name(fn)
            for pname in ctx.c['iam'].list_role_policies(RoleName=role)['PolicyNames']:
                doc = ctx.c['iam'].get_role_policy(RoleName=role, PolicyName=pname)['PolicyDocument']
                for st in policy_statements(doc):
                    actions = as_list(st.get('Action', []))
                    if 'logs:CreateLogGroup' in actions:
                        problemes.append(f"{fn} : logs:CreateLogGroup")
                    if '*' in as_list(st.get('Resource', [])) and actions != ['ec2:Describe*']:
                        problemes.append(f"{fn} : Resource * sur {actions}")
        return not problemes, '; '.join(problemes)
    r.check("Rôles Lambda : ni CreateLogGroup ni Resource * (sauf ec2:Describe*)", roles_lambda)

    def logs_recents():
        debut = int((time.time() - 300) * 1000)
        ev = ctx.c['logs'].filter_log_events(logGroupName='/aws/lambda/honeypot-publisher',
                                              startTime=debut, limit=1)['events']
        return bool(ev), 'log du publisher depuis moins de 5 minutes' if ev else 'aucun log depuis 5 minutes'
    r.check("Les Lambdas écrivent leurs logs sans CreateLogGroup", logs_recents)

    if ctx.args.actif:
        r.check("Message de test publié sur le topic (vérifie ta boîte mail)",
                lambda: (bool(ctx.c['sns'].publish(TopicArn=topic, Subject='Honeypot : test de verify_deployment',
                                                   Message='Message de test envoyé par verify_deployment.py.')
                              .get('MessageId')), ''))


# =============================================================== étape 2

SSM_SCRIPT = r"""
r() { echo "$1=$2"; }
code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 http://169.254.169.254/latest/meta-data/); r IMDS_SANS_JETON "$code"
tok=$(curl -s -m 3 -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')
code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 -H "X-aws-ec2-metadata-token: $tok" http://169.254.169.254/latest/meta-data/); r IMDS_AVEC_JETON "$code"
docker run --rm --network host alpine:3 nc -w 3 1.1.1.1 443 </dev/null >/dev/null 2>&1; r TEMOIN_HOTE $?
docker run --rm alpine:3 nc -w 3 1.1.1.1 443 </dev/null >/dev/null 2>&1; r CONTENEUR_INTERNET $?
docker run --rm alpine:3 nc -w 3 169.254.169.254 80 </dev/null >/dev/null 2>&1; r CONTENEUR_IMDS $?
aws logs describe-log-groups --region eu-west-3 2>&1 | grep -q AccessDenied; r HOTE_LOGS_REFUSE $?
aws s3 ls 2>&1 | grep -q AccessDenied; r HOTE_S3_REFUSE $?
iptables -C DOCKER-USER -d 169.254.169.254 -j DROP 2>/dev/null; r IPT_IMDS $?
iptables -C DOCKER-USER -i docker0 -m conntrack --ctstate NEW -j DROP 2>/dev/null; r IPT_FORWARD $?
iptables -C INPUT -i docker0 -m conntrack --ctstate NEW -j DROP 2>/dev/null; r IPT_INPUT $?
r COWRIE_ACTIF "$(systemctl is-active cowrie)"
r IPTABLES_ACTIF "$(systemctl is-active honeypot-iptables)"
r COWRIE_AU_DEMARRAGE "$(systemctl is-enabled cowrie)"
r IPTABLES_AU_DEMARRAGE "$(systemctl is-enabled honeypot-iptables)"
r SSHD "$(systemctl is-enabled sshd 2>/dev/null)"
r EGRESS_OK "$(journalctl -u cowrie --no-pager 2>/dev/null | grep -c 'EGRESS-TEST: OK')"
"""


def ssm_results(ctx):
    """Lance SSM_SCRIPT une fois sur l'instance et renvoie {clé: valeur}."""
    if ctx._ssm_results is None:
        ssm = ctx.c['ssm']
        cmd = ssm.send_command(InstanceIds=[ctx.instance_id], DocumentName='AWS-RunShellScript',
                               Parameters={'commands': [SSM_SCRIPT]}, TimeoutSeconds=120,
                               Comment='verify_deployment (controles en lecture)')
        cid = cmd['Command']['CommandId']
        fin = time.time() + 180
        while True:
            time.sleep(3)
            try:
                inv = ssm.get_command_invocation(CommandId=cid, InstanceId=ctx.instance_id)
            except ClientError as exc:
                if exc.response['Error']['Code'] == 'InvocationDoesNotExist' and time.time() < fin:
                    continue
                raise
            if inv['Status'] not in ('Pending', 'InProgress', 'Delayed') or time.time() > fin:
                break
        res = {}
        for line in inv.get('StandardOutputContent', '').splitlines():
            if '=' in line:
                k, _, v = line.partition('=')
                res[k.strip()] = v.strip()
        if not res:
            raise RuntimeError(f"commande SSM en {inv['Status']} : {inv.get('StandardErrorContent', '')[:200]}")
        ctx._ssm_results = res
    return ctx._ssm_results


def etape_2(ctx, r):
    r.titre("Étape 2 - Durcissement de l'instance EC2")

    def etat():
        i = ctx.instance()
        tags = {t['Key']: t['Value'] for t in i.get('Tags', [])}
        ok = i['State']['Name'] == 'running' and 'Quarantine' not in tags
        return ok, f"{i['State']['Name']}, tag Quarantine {'présent' if 'Quarantine' in tags else 'absent'}"
    r.check("Instance en marche, hors quarantaine", etat)

    def imds():
        m = ctx.instance()['MetadataOptions']
        return (m['HttpTokens'] == 'required' and m['HttpPutResponseHopLimit'] == 1,
                f"HttpTokens={m['HttpTokens']}, hop limit={m['HttpPutResponseHopLimit']}")
    r.check("IMDSv2 obligatoire, hop limit 1", imds)

    def role_instance():
        role = ctx.out['honeypot_ec2_role_name']
        att = {p['PolicyName'] for p in ctx.c['iam'].list_attached_role_policies(RoleName=role)['AttachedPolicies']}
        inline = ctx.c['iam'].list_role_policies(RoleName=role)['PolicyNames']
        attendu = {'ec2-cowrie-logs-minimal', 'AmazonSSMManagedInstanceCore'}
        return att == attendu and not inline, f"attachées {sorted(att)}, inline {inline}"
    r.check("Rôle de l'instance : logs Cowrie + SSM seulement, aucune policy inline", role_instance)

    def policy_logs():
        arn = f"arn:aws:iam::{ctx.account}:policy/ec2-cowrie-logs-minimal"
        v = ctx.c['iam'].get_policy(PolicyArn=arn)['Policy']['DefaultVersionId']
        doc = ctx.c['iam'].get_policy_version(PolicyArn=arn, VersionId=v)['PolicyVersion']['Document']
        st = policy_statements(doc)
        actions = sorted(a for s in st for a in as_list(s['Action']))
        ressources = [x for s in st for x in as_list(s['Resource'])]
        ok = actions == ['logs:CreateLogStream', 'logs:PutLogEvents'] and all('/aws/ec2/cowrie' in x for x in ressources)
        return ok, f"{actions} sur {ressources}"
    r.check("Policy de l'instance limitée à /aws/ec2/cowrie", policy_logs)

    def ssm_online():
        info = ctx.c['ssm'].describe_instance_information(
            Filters=[{'Key': 'InstanceIds', 'Values': [ctx.instance_id]}])['InstanceInformationList']
        return bool(info) and info[0]['PingStatus'] == 'Online', info[0]['PingStatus'] if info else 'inconnue de SSM'
    r.check("Systems Manager joint l'instance", ssm_online)

    def sur_instance(cle, attendu, explication):
        def f():
            v = ssm_results(ctx).get(cle)
            ok = attendu(v) if callable(attendu) else v == attendu
            return ok, f"{cle}={v}"
        r.check(explication, f)

    sur_instance('IMDS_SANS_JETON', '401', "Hôte : IMDS sans jeton refusé (401)")
    sur_instance('IMDS_AVEC_JETON', '200', "Hôte : IMDS avec jeton IMDSv2 accepté (200)")
    sur_instance('TEMOIN_HOTE', '0', "Témoin : l'hôte peut sortir en HTTPS")
    sur_instance('CONTENEUR_INTERNET', lambda v: v not in (None, '0'), "Conteneur : sortie vers Internet bloquée")
    sur_instance('CONTENEUR_IMDS', lambda v: v not in (None, '0'), "Conteneur : IMDS injoignable")
    sur_instance('HOTE_LOGS_REFUSE', '0', "Hôte : aws logs describe-log-groups refusé (AccessDenied)")
    sur_instance('HOTE_S3_REFUSE', '0', "Hôte : aws s3 ls refusé (AccessDenied)")
    sur_instance('IPT_IMDS', '0', "iptables : règle DOCKER-USER vers IMDS présente")
    sur_instance('IPT_FORWARD', '0', "iptables : règle DOCKER-USER docker0 NEW présente")
    sur_instance('IPT_INPUT', '0', "iptables : règle INPUT docker0 NEW présente")
    sur_instance('COWRIE_ACTIF', 'active', "Service cowrie actif")
    sur_instance('IPTABLES_ACTIF', 'active', "Service honeypot-iptables actif")
    sur_instance('COWRIE_AU_DEMARRAGE', 'enabled', "Cowrie relancé au démarrage")
    sur_instance('IPTABLES_AU_DEMARRAGE', 'enabled', "Règles iptables reposées au démarrage")
    sur_instance('SSHD', 'masked', "Vrai sshd masqué")
    sur_instance('EGRESS_OK', lambda v: v not in (None, '', '0'), "Test de sortie passé avant le démarrage de Cowrie")

    def logs_cowrie():
        st = ctx.c['logs'].describe_log_streams(logGroupName='/aws/ec2/cowrie', orderBy='LastEventTime',
                                                 descending=True, limit=1)['logStreams']
        if not st or 'lastEventTimestamp' not in st[0]:
            return False, 'aucun log'
        dernier = datetime.fromtimestamp(st[0]['lastEventTimestamp'] / 1000, tz=timezone.utc)
        ok = dernier >= ctx.instance()['LaunchTime']
        return ok, f"dernier log {dernier:%Y-%m-%d %H:%M} UTC"
    r.check("Les logs Cowrie arrivent dans CloudWatch depuis le démarrage", logs_cowrie)

    if ctx.args.actif:
        def banniere():
            with socket.create_connection((ctx.out['honeypot_public_ip'], 22), timeout=5) as sock:
                data = sock.recv(64)
            return data.startswith(b'SSH-'), data.split(b'\r')[0].decode('ascii', 'replace')
        r.check("Connexion depuis ton IP vers Cowrie (port 22)", banniere)

    r.manuel("Reboot de l'instance : règles iptables présentes et Cowrie redémarré seul")
    r.manuel("Règle iptables retirée volontairement : Cowrie refuse de démarrer")
    r.manuel("Dans le shell Cowrie, un wget échoue et le compteur de la règle DOCKER-USER augmente")


# =============================================================== étape 3

def etape_3(ctx, r):
    r.titre("Étape 3 - NACL dédié")
    nacl_id = ctx.out['honeypot_nacl_id']
    nacl = ctx.c['ec2'].describe_network_acls(NetworkAclIds=[nacl_id])['NetworkAcls'][0]
    subnet = ctx.instance()['SubnetId']
    sg = ctx.c['ec2'].describe_security_groups(
        GroupIds=[g['GroupId'] for g in ctx.instance()['SecurityGroups']])['SecurityGroups']
    admin = sorted({ip['CidrIp'] for g in sg for p in g['IpPermissions'] for ip in p.get('IpRanges', [])})

    r.check("Le sous-réseau de l'instance utilise ce NACL",
            lambda: (subnet in [a['SubnetId'] for a in nacl['Associations']], subnet))

    def libres():
        pris = sorted(e['RuleNumber'] for e in nacl['Entries'] if 1 <= e['RuleNumber'] <= 9)
        return not pris, f"règles 1 à 9 occupées : {pris}" if pris else 'règles 1 à 9 libres'
    r.check("Numéros 1 à 9 libres pour le kill switch", libres)

    def regles():
        def trouve(num, egress, cidr, de, a):
            for e in nacl['Entries']:
                if (e['RuleNumber'] == num and e['Egress'] == egress and e['RuleAction'] == 'allow'
                        and e['Protocol'] == '6' and e.get('CidrBlock') == cidr
                        and e.get('PortRange', {}).get('From') == de and e.get('PortRange', {}).get('To') == a):
                    return True
            return False
        cidr = admin[0] if len(admin) == 1 else None
        attendu = {
            'entrée 100 : TCP 22 depuis ton IP': trouve(100, False, cidr, 22, 22),
            'entrée 110 : éphémères depuis Internet': trouve(110, False, '0.0.0.0/0', 1024, 65535),
            'sortie 100 : TCP 443': trouve(100, True, '0.0.0.0/0', 443, 443),
            'sortie 110 : éphémères vers ton IP': trouve(110, True, cidr, 1024, 65535),
        }
        manquants = [k for k, v in attendu.items() if not v]
        return not manquants, f"manquantes : {manquants}" if manquants else f"4 règles, IP {cidr}"
    r.check("Règles 100 et 110 en entrée et en sortie", regles)

    def sg_ferme():
        ouvert = [ip['CidrIp'] for g in sg for p in g['IpPermissions'] for ip in p.get('IpRanges', [])
                  if ip['CidrIp'] == '0.0.0.0/0']
        return not ouvert and len(admin) == 1, f"entrée autorisée : {admin}"
    r.check("Security group : port 22 ouvert à ton IP seulement", sg_ferme)

    r.manuel("Depuis une autre IP (téléphone en 4G) : la connexion SSH expire")


# =============================================================== étape 4

def cw_payload(lines, ts_ms):
    """Construit un événement CloudWatch Logs comme celui du subscription filter."""
    body = json.dumps({
        'messageType': 'DATA_MESSAGE', 'owner': '000000000000', 'logGroup': '/aws/ec2/cowrie',
        'logStream': f'verify-deployment-{uuid.uuid4()}', 'subscriptionFilters': ['verify-deployment'],
        'logEvents': [{'id': str(i), 'timestamp': ts_ms, 'message': m} for i, m in enumerate(lines)],
    }).encode('utf-8')
    event = {'awslogs': {'data': base64.b64encode(gzip.compress(body)).decode('ascii')}}
    return event, hashlib.sha256(body).hexdigest()


def invoke(ctx, name, event):
    resp = ctx.c['lambda'].invoke(FunctionName=name, Payload=json.dumps(event).encode('utf-8'))
    payload = resp['Payload'].read().decode('utf-8', 'replace')
    if resp.get('FunctionError'):
        raise RuntimeError(f"{name} en erreur : {payload[:200]}")
    return json.loads(payload) if payload else {}


def etape_4(ctx, r):
    r.titre("Étape 4 - Lambda processor")
    proc = ctx.out['processor_function_name']

    def fonctions():
        noms = []
        for page in ctx.c['lambda'].get_paginator('list_functions').paginate():
            noms += [f['FunctionName'] for f in page['Functions']]
        projet = sorted(n for n in noms if any(k in n.lower() for k in ('honeypot', 'enrich', 'athena', 'map')))
        return projet == sorted(LAMBDA_NAMES), f"{projet}"
    r.check("Seules les 3 Lambdas du projet existent (ancien pipeline supprimé)", fonctions)

    def config():
        c = ctx.lambda_conf(proc)
        env = c.get('Environment', {}).get('Variables', {})
        manquent = [k for k in ('PROCESSED_BUCKET', 'STATS_TABLE', 'BATCHES_TABLE', 'CACHE_TABLE',
                                'GEOIP_API_URL', 'GEOIP_TTL_SECONDS') if not env.get(k)]
        return c['Timeout'] == 30 and not manquent, f"timeout {c['Timeout']} s, {c['Runtime']}" + (
            f", variables manquantes {manquent}" if manquent else '')
    r.check("Processor : timeout 30 s et variables d'environnement", config)

    def abonnement():
        f = ctx.c['logs'].describe_subscription_filters(logGroupName='/aws/ec2/cowrie')['subscriptionFilters']
        cibles = [x['destinationArn'].rsplit(':', 1)[-1] for x in f]
        return cibles == [proc], f"cibles {cibles}"
    r.check("Les logs Cowrie ont un seul destinataire : le processor", abonnement)

    def ttl(table, attr):
        def f():
            d = ctx.c['dynamodb'].describe_time_to_live(TableName=table)['TimeToLiveDescription']
            return d.get('TimeToLiveStatus') == 'ENABLED' and d.get('AttributeName') == attr, \
                f"{d.get('TimeToLiveStatus')} sur {d.get('AttributeName')}"
        return f
    r.check("Table honeypot-batches : TTL actif", ttl(BATCHES_TABLE, 'expires_at'))
    r.check("Table geoip-cache : TTL actif", ttl(ctx.out['geoip_cache_table_name'], 'expires_at'))
    r.check("Table honeypot-stats présente",
            lambda: (ctx.c['dynamodb'].describe_table(TableName=ctx.out['honeypot_stats_table_name'])
                     ['Table']['TableStatus'] == 'ACTIVE', ''))

    def pab(bucket):
        def f():
            c = ctx.c['s3'].get_public_access_block(Bucket=bucket)['PublicAccessBlockConfiguration']
            return all(c.values()), ''
        return f
    r.check("Bucket processed-logs : accès public bloqué", pab(ctx.out['processed_logs_bucket_name']))

    def glue():
        tables = [t['Name'] for t in ctx.c['glue'].get_tables(DatabaseName=ctx.out['athena_database_name'])['TableList']]
        return tables == ['cowrie_processed_events'], f"tables {tables}"
    r.check("Glue : seule la table cowrie_processed_events existe", glue)

    def requetes():
        ids = ctx.c['athena'].list_named_queries(WorkGroup=ctx.out['athena_workgroup_name'])['NamedQueryIds']
        return len(ids) == 4, f"{len(ids)} requêtes nommées"
    r.check("Athena : 4 requêtes nommées", requetes)

    def planifiees():
        regles = []
        for page in ctx.c['events'].get_paginator('list_rules').paginate():
            regles += [x['Name'] for x in page['Rules'] if x.get('ScheduleExpression')]
        return regles == [PUBLISHER_RULE], f"règles planifiées : {regles}"
    r.check("Aucune requête Athena planifiée (seul le publisher est planifié)", planifiees)

    if ctx.args.actif:
        try:
            tests_processor(ctx, r, proc)
        except Exception as exc:
            r.echecs.append('tests du processor')
            print(f"  ECHEC  tests du processor interrompus : {type(exc).__name__} : {exc}")
        def athena():
            a = ctx.c['athena']
            qid = a.start_query_execution(QueryString='SELECT COUNT(*) FROM cowrie_processed_events',
                                          QueryExecutionContext={'Database': ctx.out['athena_database_name']},
                                          WorkGroup=ctx.out['athena_workgroup_name'])['QueryExecutionId']
            for _ in range(40):
                st = a.get_query_execution(QueryExecutionId=qid)['QueryExecution']['Status']
                if st['State'] not in ('QUEUED', 'RUNNING'):
                    break
                time.sleep(2)
            return st['State'] == 'SUCCEEDED', st['State'] + (f" {st.get('StateChangeReason', '')}" if st['State'] != 'SUCCEEDED' else '')
        r.check("Athena : une requête sur le bucket processed-logs aboutit", athena)

    r.manuel("Panne d'ip-api : variable processor_geoip_api_url invalide, apply, le pays devient Unknown")
    r.manuel("Bout en bout : connexion SSH à Cowrie, quelques commandes, compteurs en hausse en moins d'une minute")


def tests_processor(ctx, r, proc):
    """Invoque le vrai processor avec des lignes Cowrie fabriquées, puis annule
    exactement ce qu'elles ont compté. Les dates 2001-01-xx isolent les compteurs
    DATE#, et chaque lot porte un identifiant unique."""
    ddb, s3 = ctx.c['dynamodb'], ctx.c['s3']
    stats, cache = ctx.out['honeypot_stats_table_name'], ctx.out['geoip_cache_table_name']
    bucket = ctx.out['processed_logs_bucket_name']
    ip = '8.8.8.8'
    ts_ms = int(datetime(2001, 1, 1, 12, tzinfo=timezone.utc).timestamp() * 1000)
    line = lambda d, msg, sess='a1b2c3d4': f"2001-01-{d:02d}T12:00:00.000000Z [HoneyPotSSHTransport,{sess},{ip}] {msg}"
    lots = []          # batch_ids créés, pour le nettoyage
    a_annuler = {}     # compteurs ajoutés par les tests

    def lot(lignes):
        event, bid = cw_payload(lignes, ts_ms)
        lots.append(bid)
        return event, bid

    def evenements(bid):
        body = s3.get_object(Bucket=bucket, Key=f"events/{bid}.json")['Body'].read().decode('utf-8')
        return [json.loads(l) for l in body.splitlines() if l.strip()]

    def compter(evs, fois=1):
        for e in evs:
            for k in (f"COUNTRY#{e['country']}", f"DATE#{e['event_date']}") + (
                    (f"CMD#{e['command']}",) if e['event'] == 'command' else ()):
                a_annuler[k] = a_annuler.get(k, 0) + fois

    def diff(avant, apres, cles):
        return {k: apres.get(k, 0) - avant.get(k, 0) for k in cles}

    try:
        ddb.delete_item(TableName=cache, Key={'ip': {'S': ip}})
        avant = ctx.scan_stats()

        # 1) Normalisation et premier comptage
        lignes = [
            line(1, 'New connection: 8.8.8.8:51234 (10.0.1.10:2222) [session: a1b2c3d4]'),
            line(1, 'login attempt [root/123456] failed'),
            line(1, 'CMD: ls -la'),
            line(1, 'CMD: /bin/busybox wget http://exemple.invalid/x'),
            line(1, 'CMD: <script>alert(1)</script>'),
            line(1, 'CMD: ' + 'A' * 10000),
            line(1, 'CMD: héhé漢字'),
            line(1, 'CMD: cat /etc/passwd'),
            line(1, 'ligne de bruit sans rapport'),
        ]
        event1, bid1 = lot(lignes)
        invoke(ctx, proc, event1)
        evs = evenements(bid1)
        compter(evs)
        apres1 = ctx.scan_stats()

        def normalisation():
            cmds = [e['command'] for e in evs if e['event'] == 'command']
            attendu = ['ls', 'busybox', 'other', 'other', 'other', 'cat']
            types = sorted(e['event'] for e in evs)
            ok = cmds == attendu and types.count('connect') == 1 and types.count('login_failed') == 1
            return ok, f"commandes {cmds}, {len(evs)} événements (bruit ignoré)"
        r.check("Normalisation : ls -la→ls, busybox, <script>→other, 10 000 car.→other, unicode→other", normalisation)

        def comptage():
            d = diff(avant, apres1, a_annuler)
            return all(d[k] == v for k, v in a_annuler.items()), f"{len(a_annuler)} compteurs incrémentés"
        r.check("Premier lot : compteurs incrémentés et objet S3 créé", comptage)

        def date_evenement():
            dates = {e['event_date'] for e in evs}
            return dates == {'2001-01-01'}, f"dates {sorted(dates)}"
        r.check("Date issue de la ligne, pas de l'heure de traitement", date_evenement)

        def geoip_ttl():
            it = ddb.get_item(TableName=cache, Key={'ip': {'S': ip}}).get('Item')
            if not it:
                return False, 'IP absente du cache'
            code = it['country_code']['S']
            reste = int(it['expires_at']['N']) - int(time.time())
            ttl = int(ctx.lambda_conf(proc)['Environment']['Variables']['GEOIP_TTL_SECONDS'])
            return code != 'Unknown' and ttl - 600 <= reste <= ttl, f"{ip} → {code}, expire dans {reste / 3600:.1f} h"
        r.check("GeoIP : pays valide, mis en cache pour 72 h", geoip_ttl)
        cache_1 = ddb.get_item(TableName=cache, Key={'ip': {'S': ip}}).get('Item', {})

        # 2) Rejeu du même lot
        invoke(ctx, proc, event1)
        apres2 = ctx.scan_stats()
        r.check("Rejeu du même lot : compteurs inchangés, même clé S3",
                lambda: (diff(apres1, apres2, a_annuler) == {k: 0 for k in a_annuler}
                         and s3.head_object(Bucket=bucket, Key=f"events/{bid1}.json") is not None, ''))

        # 3) Deux lots différents en parallèle sur les mêmes clés
        ev_a, bid_a = lot([line(1, 'CMD: ls', 'b1'), line(1, 'CMD: ls', 'b1')])
        ev_b, bid_b = lot([line(1, 'CMD: ls', 'c1'), line(1, 'CMD: ls', 'c1')])
        erreurs = []

        def lance(ev):
            try:
                invoke(ctx, proc, ev)
            except Exception as exc:
                erreurs.append(exc)
        t = [threading.Thread(target=lance, args=(e,)) for e in (ev_a, ev_b)]
        [x.start() for x in t]
        [x.join() for x in t]
        evs_ab = evenements(bid_a) + evenements(bid_b)
        compter(evs_ab)
        apres3 = ctx.scan_stats()
        r.check("Deux lots simultanés sur les mêmes clés : les deux sont comptés",
                lambda: (not erreurs and diff(apres2, apres3, ['CMD#ls'])['CMD#ls'] == 4,
                         f"CMD#ls +{diff(apres2, apres3, ['CMD#ls'])['CMD#ls']} (4 attendus)"))
        r.check("Même IP dans un second lot : aucun nouvel appel à ip-api (cache inchangé)",
                lambda: (ddb.get_item(TableName=cache, Key={'ip': {'S': ip}}).get('Item', {})
                         .get('expires_at') == cache_1.get('expires_at'), ''))

        # 4) Gros lot : 89 commandes + 20 dates + 1 pays = 110 clés, donc 2 transactions
        gros = [line(1 + i % 20, f'CMD: {c}') for i, c in enumerate(WHITELIST)]
        gros += [line(d, 'CMD: ls') for d in range(1, 21)]
        ev_g, bid_g = lot(gros)
        invoke(ctx, proc, ev_g)
        compter(evenements(bid_g))

        def gros_lot():
            m = [ddb.get_item(TableName=BATCHES_TABLE, Key={'pk': {'S': f"{bid_g}#{i}"}}).get('Item') for i in (0, 1)]
            return all(m), '110 clés découpées en 2 transactions'
        r.check("Gros lot : découpé sous la limite de 100 éléments par transaction", gros_lot)
    finally:
        # Nettoyage : on retire exactement ce que les tests ont ajouté.
        for k, n in a_annuler.items():
            try:
                res = ddb.update_item(TableName=stats, Key={'pk': {'S': k}}, UpdateExpression='ADD #c :n',
                                      ExpressionAttributeNames={'#c': 'count'},
                                      ExpressionAttributeValues={':n': {'N': str(-n)}}, ReturnValues='UPDATED_NEW')
                if int(res['Attributes']['count']['N']) <= 0:
                    ddb.delete_item(TableName=stats, Key={'pk': {'S': k}})
            except ClientError as exc:
                r.info(f"nettoyage {k} impossible : {exc}")
        for bid in lots:
            for i in range(3):
                ddb.delete_item(TableName=BATCHES_TABLE, Key={'pk': {'S': f"{bid}#{i}"}})
            s3.delete_object(Bucket=bucket, Key=f"events/{bid}.json")
        ddb.delete_item(TableName=cache, Key={'ip': {'S': ip}})
        r.info(f"nettoyage : {len(a_annuler)} compteurs remis à leur valeur, {len(lots)} lots supprimés")


# =============================================================== étape 5

def etape_5(ctx, r):
    r.titre("Étape 5 - Publisher et carte")
    pub = ctx.out['publisher_function_name']
    bucket = ctx.out['attack_map_bucket_name']
    url = ctx.out['attack_map_url'].rstrip('/')
    role_arn = ctx.lambda_conf(pub)['Role']

    def planification():
        regle = ctx.c['events'].describe_rule(Name=PUBLISHER_RULE)
        cibles = [t['Arn'].rsplit(':', 1)[-1] for t in ctx.c['events'].list_targets_by_rule(Rule=PUBLISHER_RULE)['Targets']]
        ok = regle['State'] == 'ENABLED' and regle.get('ScheduleExpression') == 'rate(1 minute)' and cibles == [pub]
        return ok, f"{regle.get('ScheduleExpression')}, {regle['State']}, cible {cibles}"
    r.check("Publisher planifié chaque minute", planification)

    r.check("Publisher autorisé à écrire data.json",
            lambda: expect_sim(ctx, role_arn, 's3:PutObject', f"arn:aws:s3:::{bucket}/data.json", 'allowed'))
    r.check("Publisher refusé en écriture sur index.html",
            lambda: expect_sim(ctx, role_arn, 's3:PutObject', f"arn:aws:s3:::{bucket}/index.html", 'denied'))

    def data_json():
        code, headers, body = http_get(f"{url}/data.json")
        if code != 200:
            return False, f"HTTP {code}"
        d = json.loads(body)
        cles = {'generated_at', 'total', 'since', 'Country', 'Date', 'Command'}
        age = time.time() - datetime.strptime(d['generated_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
        ok = cles <= set(d) and age < 180 and len(body) < 100_000
        return ok, f"{len(body)} octets, généré il y a {int(age)} s, {len(d['Country'])} pays"
    r.check("data.json via CloudFront : schéma conforme, récent, taille bornée", data_json)

    def sans_cache():
        _, h1, _ = http_get(f"{url}/data.json")
        _, h2, _ = http_get(f"{url}/data.json")
        h = {k.lower(): v for k, v in h2.items()}
        ok = 'no-store' in h.get('cache-control', '') and not h.get('x-cache', '').startswith('Hit')
        return ok, f"Cache-Control: {h.get('cache-control')}, X-Cache: {h.get('x-cache')}"
    r.check("data.json jamais servi depuis le cache CloudFront", sans_cache)

    def s3_direct():
        code, _, _ = http_get(f"https://{bucket}.s3.{REGION}.amazonaws.com/data.json")
        return code == 403, f"HTTP {code}"
    r.check("Bucket de la carte inaccessible en direct (403)", s3_direct)

    def inner_html():
        local = next((p for p in (os.path.join(ROOT, 'index.html'), os.path.join(ROOT, 'map', 'index.html'))
                      if os.path.exists(p)), None)
        code, _, servi = http_get(f"{url}/")
        textes = {'servi par CloudFront': servi.decode('utf-8', 'replace')}
        if local:
            textes['local'] = open(local, encoding='utf-8').read()
        fautifs = [k for k, t in textes.items() if 'innerHTML' in t]
        ok = code == 200 and not fautifs and all('textContent' in t for t in textes.values())
        return ok, f"aucun innerHTML ({', '.join(textes)})" if ok else f"innerHTML dans {fautifs}, HTTP {code}"
    r.check("index.html : textContent partout, jamais innerHTML", inner_html)

    if ctx.args.actif:
        def xss():
            stats = ctx.out['honeypot_stats_table_name']
            cle = 'CMD#<img src=x onerror=alert(1)>'
            ddb = ctx.c['dynamodb']
            ddb.put_item(TableName=stats, Item={'pk': {'S': cle}, 'count': {'N': '999999'}})
            try:
                invoke(ctx, pub, {})
                _, _, body = http_get(f"{url}/data.json")
                cmds = [c['command'] for c in json.loads(body)['Command']]
                return '<img src=x onerror=alert(1)>' in cmds, 'libellé transmis tel quel, affiché en texte par la page'
            finally:
                ddb.delete_item(TableName=stats, Key={'pk': {'S': cle}})
                invoke(ctx, pub, {})
        r.check("Défense XSS : un libellé piégé reste du texte dans data.json", xss)
        r.manuel("Navigateur : le libellé piégé s'affiche littéralement et rien ne s'exécute")
    r.manuel("Navigateur : le globe affiche les pays et les compteurs se mettent à jour")


# =============================================================== étape 6

def etape_6(ctx, r):
    r.titre("Étape 6 - Supervision et GuardDuty")
    topic = ctx.out['sns_alerts_topic_arn']
    det = ctx.out['guardduty_detector_id']

    def dashboard():
        body = json.loads(ctx.c['cloudwatch'].get_dashboard(DashboardName='honeypot')['DashboardBody'])
        w = body.get('widgets', [])
        cf = [x for x in w if x.get('properties', {}).get('region') == 'us-east-1']
        return len(w) >= 11 and len(cf) == 2, f"{len(w)} widgets, {len(cf)} CloudFront en us-east-1"
    r.check("Dashboard honeypot complet (widgets CloudFront en us-east-1)", dashboard)

    def alarmes():
        a = {x['AlarmName']: x for x in ctx.c['cloudwatch'].describe_alarms(AlarmNames=list(ALARMS))['MetricAlarms']}
        problemes = [n for n in ALARMS if n not in a or topic not in a[n]['AlarmActions']
                     or a[n].get('TreatMissingData') != 'notBreaching']
        en_alarme = [n for n, x in a.items() if x['StateValue'] == 'ALARM']
        ok = not problemes and not en_alarme
        return ok, (f"mal configurées {problemes}, en ALARM {en_alarme}" if not ok
                    else f"{len(a)} alarmes vers SNS, notBreaching, aucune en ALARM")
    r.check("5 alarmes branchées sur le topic, aucune déclenchée", alarmes)

    def guardduty():
        d = ctx.c['guardduty'].get_detector(DetectorId=det)
        return d['Status'] == 'ENABLED' and d['FindingPublishingFrequency'] == 'FIFTEEN_MINUTES', \
            f"{d['Status']}, {d['FindingPublishingFrequency']}"
    r.check("Détecteur GuardDuty actif", guardduty)

    def regle_c():
        regle = ctx.c['events'].describe_rule(Name=RULE_C)
        t = ctx.c['events'].list_targets_by_rule(Rule=RULE_C)['Targets']
        ok = regle['State'] == 'ENABLED' and [x['Arn'] for x in t] == [topic] and 'InputTransformer' in t[0]
        return ok, f"{regle['State']}, cible {[x['Arn'].rsplit(':', 1)[-1] for x in t]}"
    r.check("Tous les findings GuardDuty partent par email (message lisible)", regle_c)

    if ctx.args.actif:
        r.info("Chaque alarme passe en ALARM puis revient à OK : attends-toi à 10 emails.")
        for nom in ALARMS:
            def force(nom=nom):
                cw = ctx.c['cloudwatch']
                cw.set_alarm_state(AlarmName=nom, StateValue='ALARM', StateReason='verify_deployment : test')
                time.sleep(3)
                cw.set_alarm_state(AlarmName=nom, StateValue='OK', StateReason='verify_deployment : fin du test')
                return True, 'email attendu'
            r.check(f"Alarme {nom} forcée puis remise à OK", force)

        def sample():
            t = 'Recon:EC2/PortProbeUnprotectedPort'
            ctx.c['guardduty'].create_sample_findings(DetectorId=det, FindingTypes=[t])
            return True, f"finding d'exemple {t} créé, email attendu"
        r.check("Finding GuardDuty d'exemple (un seul type)", sample)
        r.manuel("Boîte mail : un email par alarme et un pour le finding d'exemple")


# =============================================================== étape 7

def etape_7(ctx, r):
    r.titre("Étape 7 - Kill switch : infrastructure")
    ks = ctx.out['kill_switch_function_name']
    conf = ctx.lambda_conf(ks)
    role_arn = conf['Role']
    deny = ctx.out['quarantine_deny_policy_arn']
    evid = ctx.out['evidence_bucket_name']

    def sg_vide():
        g = ctx.c['ec2'].describe_security_groups(GroupIds=[ctx.out['quarantine_sg_id']])['SecurityGroups'][0]
        return not g['IpPermissions'] and not g['IpPermissionsEgress'], \
            f"{len(g['IpPermissions'])} entrée(s), {len(g['IpPermissionsEgress'])} sortie(s)"
    r.check("Security group de quarantaine sans aucune règle", sg_vide)

    def policy_deny():
        v = ctx.c['iam'].get_policy(PolicyArn=deny)['Policy']['DefaultVersionId']
        doc = ctx.c['iam'].get_policy_version(PolicyArn=deny, VersionId=v)['PolicyVersion']['Document']
        st = policy_statements(doc)
        roles = ctx.c['iam'].list_entities_for_policy(PolicyArn=deny)['PolicyRoles']
        ok = len(st) == 1 and st[0]['Effect'] == 'Deny' and st[0]['Action'] == '*' and not roles
        return ok, f"attachée à {[x['RoleName'] for x in roles]}" if roles else 'Deny *, attachée à aucun rôle'
    r.check("Policy Deny * prête, attachée à aucun rôle", policy_deny)

    def bucket_preuves():
        s3 = ctx.c['s3']
        pab = all(s3.get_public_access_block(Bucket=evid)['PublicAccessBlockConfiguration'].values())
        sse = s3.get_bucket_encryption(Bucket=evid)['ServerSideEncryptionConfiguration']['Rules'][0][
            'ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
        jours = [x.get('Expiration', {}).get('Days') for x in s3.get_bucket_lifecycle_configuration(Bucket=evid)['Rules']]
        https = 'DenyInsecureTransport' in s3.get_bucket_policy(Bucket=evid)['Policy']
        return pab and sse == 'AES256' and any(jours) and https, \
            f"privé {pab}, chiffrement {sse}, expiration {jours} j, HTTPS obligatoire {https}"
    r.check("Bucket de preuves privé, chiffré, avec expiration", bucket_preuves)

    def lambda_conf():
        env = conf.get('Environment', {}).get('Variables', {})
        attendu = {'INSTANCE_ID': ctx.instance_id, 'QUARANTINE_SG_ID': ctx.out['quarantine_sg_id'],
                   'NACL_ID': ctx.out['honeypot_nacl_id'], 'EVIDENCE_BUCKET': evid,
                   'DENY_POLICY_ARN': deny, 'DRY_RUN': 'false'}
        ecarts = {k: env.get(k) for k, v in attendu.items() if env.get(k) != v}
        hors_vpc = not conf.get('VpcConfig', {}).get('VpcId')
        return not ecarts and hors_vpc, f"écarts {ecarts}" if ecarts else 'mode réel (DRY_RUN=false), hors VPC'
    r.check("Lambda kill switch : bonne instance, mode réel, hors VPC", lambda_conf)

    def retries():
        c = ctx.c['lambda'].get_function_event_invoke_config(FunctionName=ks)
        return c.get('MaximumRetryAttempts') == 0, f"{c.get('MaximumRetryAttempts')} nouvelle tentative"
    r.check("Aucune nouvelle tentative asynchrone", retries)

    def dlq():
        a = ctx.c['sqs'].get_queue_attributes(QueueUrl=ctx.out['kill_switch_dlq_url'], AttributeNames=['All'])['Attributes']
        ok = a.get('SqsManagedSseEnabled') == 'true' and 'rule/honeypot-killswitch-*' in a.get('Policy', '')
        return ok, f"chiffrée {a.get('SqsManagedSseEnabled')}, {a.get('ApproximateNumberOfMessages')} message(s)"
    r.check("File d'erreurs chiffrée, réservée aux règles honeypot-killswitch-*", dlq)

    role_ec2 = ctx.c['iam'].get_role(RoleName=ctx.out['honeypot_ec2_role_name'])['Role']['Arn']
    eni = ctx.instance()['NetworkInterfaces'][0]['NetworkInterfaceId']
    a = f"arn:aws:ec2:{REGION}:{ctx.account}"
    droits = [
        ("Peut attacher la policy Deny au rôle de l'instance", 'iam:AttachRolePolicy', role_ec2, 'allowed', deny),
        ("Ne peut pas attacher AdministratorAccess", 'iam:AttachRolePolicy', role_ec2, 'denied',
         'arn:aws:iam::aws:policy/AdministratorAccess'),
        ("Peut arrêter le honeypot", 'ec2:StopInstances', ctx.arn_instance(), 'allowed', None),
        ("Ne peut pas arrêter une autre instance", 'ec2:StopInstances', ctx.arn_instance('i-00000000000000000'), 'denied', None),
        ("Ne peut pas supprimer le honeypot", 'ec2:TerminateInstances', ctx.arn_instance(), 'denied', None),
        ("Peut changer le security group de l'interface", 'ec2:ModifyNetworkInterfaceAttribute',
         f"{a}:network-interface/{eni}", 'allowed', None),
        ("Peut poser des règles dans le NACL", 'ec2:CreateNetworkAclEntry',
         f"{a}:network-acl/{ctx.out['honeypot_nacl_id']}", 'allowed', None),
        ("Peut écrire une preuve", 's3:PutObject', f"arn:aws:s3:::{evid}/incidents/test.json", 'allowed', None),
        ("Ne peut pas écrire hors du bucket de preuves", 's3:PutObject',
         f"arn:aws:s3:::{ctx.out['processed_logs_bucket_name']}/x", 'denied', None),
    ]
    for libelle, action, ressource, attendu, pol in droits:
        r.check(f"Droits : {libelle}", lambda a=action, res=ressource, att=attendu, p=pol:
                expect_sim(ctx, role_arn, a, res, att, p))

    r.manuel("Simulation (DRY_RUN=true) puis exercice réel : runbook de restauration")


# =============================================================== étape 8

def finding(ftype, iid, role='ACTOR', severity=8):
    return {
        'version': '0', 'id': str(uuid.uuid4()), 'detail-type': 'GuardDuty Finding',
        'source': 'aws.guardduty', 'account': '000000000000', 'time': '2026-01-01T00:00:00Z',
        'region': REGION, 'resources': [],
        'detail': {'type': ftype, 'severity': severity,
                   'resource': {'instanceDetails': {'instanceId': iid}},
                   'service': {'resourceRole': role}},
    }


def etape_8(ctx, r):
    r.titre("Étape 8 - Déclencheurs du kill switch")
    ev = ctx.c['events']
    ks_arn = ctx.lambda_conf(ctx.out['kill_switch_function_name'])['FunctionArn']
    dlq_arn = ctx.c['sqs'].get_queue_attributes(QueueUrl=ctx.out['kill_switch_dlq_url'],
                                                AttributeNames=['QueueArn'])['Attributes']['QueueArn']

    for nom in (RULE_A, RULE_B):
        def regle(nom=nom):
            d = ev.describe_rule(Name=nom)
            t = ev.list_targets_by_rule(Rule=nom)['Targets']
            ok = (d['State'] == 'ENABLED' and ctx.instance_id in d['EventPattern'] and len(t) == 1
                  and t[0]['Arn'] == ks_arn and t[0].get('DeadLetterConfig', {}).get('Arn') == dlq_arn
                  and t[0].get('RetryPolicy', {}).get('MaximumRetryAttempts') == 2)
            return ok, f"{d['State']}, filtrée sur {ctx.instance_id}, file d'erreurs, 2 nouvelles tentatives"
        r.check(f"Règle {nom} active et branchée sur le kill switch", regle)

    def permissions():
        pol = json.loads(ctx.c['lambda'].get_policy(FunctionName=ks_arn)['Policy'])
        sources = json.dumps(pol)
        manque = [n for n in (RULE_A, RULE_B) if f"rule/{n}" not in sources]
        return not manque, f"manque {manque}" if manque else 'les 2 règles peuvent invoquer la Lambda'
    r.check("Permissions d'invocation de la Lambda", permissions)

    motifs = {n: ev.describe_rule(Name=n)['EventPattern'] for n in (RULE_A, RULE_B, RULE_C)}
    autre = 'i-0000000000000000a'
    exfil = 'UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS'
    me = ctx.instance_id
    cas = [
        ('A : malware, honeypot ACTOR', RULE_A, finding('Backdoor:EC2/C&CActivity.B', me), True),
        ('A : minage, honeypot ACTOR', RULE_A, finding('CryptoCurrency:EC2/BitcoinTool.B!DNS', me), True),
        ('A : scan de ports, honeypot ACTOR', RULE_A, finding('Recon:EC2/Portscan', me), True),
        ('A : malware, honeypot CIBLE', RULE_A, finding('Backdoor:EC2/C&CActivity.B', me, 'TARGET'), False),
        ('A : malware, autre instance', RULE_A, finding('Backdoor:EC2/C&CActivity.B', autre), False),
        ('A : brute force SSH (type non retenu)', RULE_A, finding('UnauthorizedAccess:EC2/SSHBruteForce', me), False),
        ('B : exfiltration des credentials', RULE_B, finding(exfil, me, 'TARGET'), True),
        ('B : exfiltration, autre instance', RULE_B, finding(exfil, autre), False),
        ('B : malware (mauvais type)', RULE_B, finding('Backdoor:EC2/C&CActivity.B', me), False),
    ]
    for libelle, regle, event, attendu in cas:
        def test(regle=regle, event=event, attendu=attendu):
            got = ev.test_event_pattern(EventPattern=motifs[regle], Event=json.dumps(event))['Result']
            return got == attendu, 'déclenche' if got else 'ignore'
        r.check(f"Motif {libelle}", test)

    def regle_c_tout():
        res = [ev.test_event_pattern(EventPattern=motifs[RULE_C], Event=json.dumps(e))['Result'] for _, _, e, _ in cas]
        return all(res), f"{sum(res)}/{len(res)} cas notifiés"
    r.check("La notification par email couvre tous les cas", regle_c_tout)

    if ctx.args.actif:
        def champ_instance():
            gd, det = ctx.c['guardduty'], ctx.out['guardduty_detector_id']
            gd.create_sample_findings(DetectorId=det, FindingTypes=[exfil])
            for _ in range(15):
                ids = gd.list_findings(DetectorId=det, FindingCriteria={'Criterion': {'type': {'Eq': [exfil]}}},
                                       SortCriteria={'AttributeName': 'updatedAt', 'OrderBy': 'DESC'},
                                       MaxResults=1)['FindingIds']
                if ids:
                    f = gd.get_findings(DetectorId=det, FindingIds=ids)['Findings'][0]
                    iid = f.get('Resource', {}).get('InstanceDetails', {}).get('InstanceId')
                    return bool(iid) and iid != me, f"instanceId présent ({iid}), kill switch non déclenché"
                time.sleep(2)
            return False, 'finding introuvable'
        r.check("Finding d'exemple B : le champ d'instance existe, la règle l'ignore", champ_instance)

    r.manuel("Exercice d'incident réel puis restauration selon le runbook")


# =============================================================== main

ETAPES = [etape_0, etape_1, etape_2, etape_3, etape_4, etape_5, etape_6, etape_7, etape_8]


def main():
    p = argparse.ArgumentParser(description="Vérifie le déploiement réel du honeypot (étapes 0 à 8).")
    p.add_argument('--phase', type=int, nargs='+', choices=range(9), metavar='N',
                   help="étapes à vérifier (0 à 8), toutes par défaut")
    p.add_argument('--actif', action='store_true',
                   help="ajoute les tests qui écrivent dans AWS ou envoient des emails")
    p.add_argument('--sans-plan', action='store_true', help="ne lance pas terraform plan")
    args = p.parse_args()

    ctx = Contexte(args)
    r = Rapport()
    print(f"Compte {ctx.account}, région {REGION}, instance {ctx.instance_id}"
          f"{' - mode actif' if args.actif else ' - lecture seule'}")
    for n in (args.phase or range(9)):
        try:
            ETAPES[n](ctx, r)
        except Exception as exc:
            r.echecs.append(f"étape {n}")
            print(f"  ECHEC  étape {n} interrompue : {type(exc).__name__} : {exc}")

    print(f"\n=== Bilan : {r.ok} OK, {len(r.echecs)} en échec, {len(r.manuels)} à vérifier à la main ===")
    for e in r.echecs:
        print(f"  ECHEC  {e}")
    sys.exit(1 if r.echecs else 0)


if __name__ == '__main__':
    main()
