# ==============================================================================
# HONEYPOT AWS - PHASE 2 : PRODUCTION FERMÉE (AWS réel)
# ==============================================================================
# Architecture : Cowrie -> CloudWatch Logs -> (subscription filter direct,
# sans Firehose, ADR-015) -> Lambda (enrichissement GeoIP, cache 2 niveaux,
# ADR-010) -> S3 enrichi -> Athena (ADR-006/008)
#
# Sécurité Phase 2 (ADR-011/012) :
# - Honeypot accessible uniquement depuis une IP personnelle (admin_test_cidr)
# - Egress limité au strict nécessaire (HTTPS, DNS, trafic interne au VPC)
# - Administration via AWS Systems Manager (pas de second port SSH)
# - État Terraform local, pas de CI/CD activée pour l'instant (ADR-014)

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# Suffixe aléatoire ajouté aux noms de bucket S3 : ces noms sont uniques
# à l'échelle mondiale (pas seulement dans ton compte), un nom codé en
# dur risquerait une collision avec un bucket existant ailleurs. Généré
# une fois, stable ensuite (ne change pas à chaque apply).
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# Provider AWS réel (credentials via AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
# ou un profil `aws configure` de l'environnement, jamais en dur ici)
provider "aws" {
  region = "eu-west-3" # Paris
}

# ------------------------------------------------------------------------------
# Variable : durée du cache GeoIP (TTL DynamoDB, en secondes)
# ------------------------------------------------------------------------------
variable "geoip_cache_ttl_seconds" {
  description = "Durée de vie (TTL) des entrées du cache GeoIP dans DynamoDB, en secondes."
  type        = number
  default     = 300
}

# NB : pas de réservation de concurrence sur la Lambda d'enrichissement
# (reserved_concurrent_executions). Le quota de concurrence total de ce
# compte AWS est de 10, et AWS exige toujours au moins 10 exécutions non
# réservées disponibles pour le reste du compte - réserver quoi que ce
# soit ferait donc passer ce quota sous son minimum obligatoire. La
# Lambda tourne donc sans plafond explicite, ce qui reste sans risque en
# pratique : elle continue de puiser dans le pool non réservé du compte
# (10 exécutions en parallèle actuellement), et CloudWatch Logs invoque
# la Lambda de façon asynchrone - en cas de throttling, les invocations
# en trop sont retentées automatiquement pendant plusieurs heures,
# jamais perdues immédiatement. Voir CONTRAINTES.md.

# ------------------------------------------------------------------------------
# Variable : IP publique personnelle autorisée à tester le honeypot
# ------------------------------------------------------------------------------
variable "admin_test_cidr" {
  description = "CIDR de l'IP personnelle autorisée à se connecter au honeypot en phase de production fermée (ex: 82.123.45.67/32)."
  type        = string

  validation {
    condition     = var.admin_test_cidr != "0.0.0.0/0"
    error_message = "admin_test_cidr ne doit pas être 0.0.0.0/0 en phase de production fermée : indique ton IP publique personnelle au format CIDR (ex: 82.123.45.67/32)."
  }
}

# ------------------------------------------------------------------------------
# Résolution de l'AMI Amazon Linux 2023 la plus récente
# ------------------------------------------------------------------------------
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ==============================================================================
# ÉTAPE 1 : RÉSEAU (VPC)
# ==============================================================================

resource "aws_vpc" "honeypot_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "VPC-Honeypot"
  }
}

resource "aws_internet_gateway" "honeypot_igw" {
  vpc_id = aws_vpc.honeypot_vpc.id

  tags = {
    Name = "IGW-Honeypot"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.honeypot_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "Public-Subnet-Honeypot"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.honeypot_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.honeypot_igw.id
  }

  tags = {
    Name = "RT-Public-Honeypot"
  }
}

resource "aws_route_table_association" "public_rt_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# Security Group — Phase 2 : accès restreint à l'IP personnelle uniquement
# (ADR-011). L'ouverture à 0.0.0.0/0 est repoussée à la Phase 3.
resource "aws_security_group" "honeypot_sg" {
  name        = "honeypot-sg"
  description = "Security group pour l instance honeypot - phase 2 : acces restreint a l IP personnelle"
  vpc_id      = aws_vpc.honeypot_vpc.id

  ingress {
    description = "Acces test au honeypot Cowrie - IP personnelle uniquement (phase 2)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_test_cidr]
  }

  egress {
    description = "HTTPS sortant (Docker Hub, CloudWatch, SSM)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS sortant (resolution de noms)"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Tout trafic sortant restreint au VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.honeypot_vpc.cidr_block]
  }

  tags = {
    Name = "SG-Honeypot"
  }
}

# ==============================================================================
# ÉTAPE 2 : INSTANCE EC2 (HONEYPOT)
# ==============================================================================

resource "aws_iam_role" "ec2_cloudwatch_role" {
  name = "ec2-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cw_policy_attach" {
  role       = aws_iam_role.ec2_cloudwatch_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Permet d'administrer l'instance via AWS Systems Manager Session Manager
# plutôt que par un vrai serveur SSH exposé (ADR-012).
resource "aws_iam_role_policy_attachment" "ssm_policy_attach" {
  role       = aws_iam_role.ec2_cloudwatch_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-cloudwatch-profile"
  role = aws_iam_role.ec2_cloudwatch_role.name
}

resource "aws_instance" "honeypot_ec2" {
  ami                  = data.aws_ami.amazon_linux_2023.id
  instance_type        = "t3.micro"
  subnet_id            = aws_subnet.public_subnet.id
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  vpc_security_group_ids = [aws_security_group.honeypot_sg.id]

  # Amazon Linux 2023 embarque l'agent SSM pré-installé et démarré par
  # défaut ; combiné à la policy AmazonSSMManagedInstanceCore attachée
  # plus haut, Session Manager fonctionne sans étape supplémentaire ici.
  # Le vrai sshd de l'OS est désactivé : il occuperait sinon le port 22
  # avant Docker (conflit de port), et n'a aucune utilité puisque
  # l'administration se fait via SSM, pas par SSH réel (ADR-012).
  #
  # Le conteneur Cowrie utilise le driver de logging Docker "awslogs" :
  # sa sortie standard est envoyée directement à CloudWatch Logs par
  # Docker lui-même. Par défaut, cette sortie est le log texte humain de
  # Cowrie, pas son log JSON structuré (qui reste écrit dans un fichier
  # interne au conteneur) - les tentatives de récupérer le JSON
  # directement (redirection vers /dev/stdout, puis conteneur "shipper"
  # séparé) ont chacune buté sur un nouveau problème sans jamais aboutir
  # rapidement ; repli volontaire sur cette version simple, fonctionnelle,
  # en attendant une solution plus fiable pour le JSON (voir DECISIONS.md).
  user_data_base64 = base64encode(<<-EOF
    #!/bin/bash
    systemctl stop sshd
    systemctl disable sshd
    dnf install -y docker
    systemctl start docker
    systemctl enable docker
    docker run -d -p 22:2222 --name cowrie \
      --log-driver=awslogs \
      --log-opt awslogs-region=eu-west-3 \
      --log-opt awslogs-group=/aws/ec2/cowrie \
      cowrie/cowrie:latest
  EOF
  )

  tags = {
    Name = "Honeypot-Cowrie"
  }
}

resource "aws_eip" "honeypot_eip" {
  instance = aws_instance.honeypot_ec2.id
  domain   = "vpc"

  tags = {
    Name = "EIP-Honeypot"
  }
}

# ==============================================================================
# ÉTAPE 3 : CAPTURE DES LOGS (CLOUDWATCH LOGS)
# ==============================================================================

resource "aws_cloudwatch_log_group" "cowrie_log_group" {
  name              = "/aws/ec2/cowrie"
  retention_in_days = 14

  tags = {
    Name = "CloudWatch-Cowrie-Logs"
  }
}

# ==============================================================================
# ÉTAPE 4 : CACHE GEOIP (DYNAMODB, TTL COURT)
# ==============================================================================

resource "aws_dynamodb_table" "geoip_cache" {
  name         = "geoip-cache"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "ip"

  attribute {
    name = "ip"
    type = "S"
  }

  ttl {
    enabled        = true
    attribute_name = "expires_at"
  }

  tags = {
    Name = "DynamoDB-GeoIP-Cache"
  }
}

# ==============================================================================
# ÉTAPE 5 : BUCKET S3 ENRICHI
# ==============================================================================

resource "aws_s3_bucket" "enriched_logs_bucket" {
  bucket        = "honeypot-enriched-logs-${random_id.bucket_suffix.hex}"
  force_destroy = true

  tags = {
    Name        = "S3-Enriched-Logs"
    Environment = "Production"
  }
}

resource "aws_s3_bucket_public_access_block" "enriched_logs_bucket_pab" {
  bucket                  = aws_s3_bucket.enriched_logs_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ==============================================================================
# ÉTAPE 6 : LAMBDA D'ENRICHISSEMENT (DÉCLENCHÉE DIRECTEMENT PAR CLOUDWATCH LOGS)
# ==============================================================================

resource "aws_iam_role" "lambda_geoip_role" {
  name = "lambda-geoip-enrichment-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_geoip_policy" {
  name = "lambda-geoip-enrichment-policy"
  role = aws_iam_role.lambda_geoip_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.enriched_logs_bucket.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem"]
        Resource = aws_dynamodb_table.geoip_cache.arn
      }
    ]
  })
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_function.zip"

  source {
    content  = <<EOF
import json
import gzip
import base64
import re
import time
import urllib.request
import os
import boto3

s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')

ENRICHED_BUCKET = os.environ.get('ENRICHED_BUCKET')
CACHE_TABLE_NAME = os.environ.get('CACHE_TABLE')
CACHE_TTL_SECONDS = int(os.environ.get('CACHE_TTL_SECONDS', '300'))

cache_table = dynamodb.Table(CACHE_TABLE_NAME)

def get_geoip_from_api(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,lat,lon"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', 'Unknown'),
                    'latitude': data.get('lat', 0.0),
                    'longitude': data.get('lon', 0.0)
                }
    except Exception as e:
        print(f"[GEOIP][ERREUR] {ip}: {str(e)}")

    return {'country': 'Unknown', 'latitude': 0.0, 'longitude': 0.0}

def get_geoip_cached(ip, local_cache):
    now = int(time.time())

    if ip in local_cache:
        print(f"[CACHE HIT][L1-memoire] {ip}")
        return local_cache[ip]

    try:
        response = cache_table.get_item(Key={'ip': ip})
        item = response.get('Item')
        if item and int(item.get('expires_at', 0)) > now:
            geoip_data = {
                'country': item['country'],
                'latitude': float(item['latitude']),
                'longitude': float(item['longitude'])
            }
            print(f"[CACHE HIT][L2-dynamodb] {ip}")
            local_cache[ip] = geoip_data
            return geoip_data
        elif item:
            print(f"[CACHE EXPIRED][L2-dynamodb] {ip}")
    except Exception as e:
        print(f"[CACHE][ERREUR LECTURE] {ip}: {str(e)}")

    print(f"[CACHE MISS] {ip} - appel à l'API GeoIP")
    geoip_data = get_geoip_from_api(ip)

    try:
        cache_table.put_item(Item={
            'ip': ip,
            'country': geoip_data['country'],
            'latitude': str(geoip_data['latitude']),
            'longitude': str(geoip_data['longitude']),
            'expires_at': now + CACHE_TTL_SECONDS
        })
    except Exception as e:
        print(f"[CACHE][ERREUR ECRITURE] {ip}: {str(e)}")

    local_cache[ip] = geoip_data
    return geoip_data

def parse_cowrie_text_log(message_str):
    """
    Extrait src_ip et un eventid approximatif depuis le format texte de
    Cowrie (ex: "2026-09-22T17:02:00Z [ssh,session,1.2.3.4] CMD: ls -la"),
    faute d'avoir pu récupérer son log JSON natif (tentatives Docker
    successives infructueuses - conflit de seek, permissions, boucle de
    crash au démarrage - voir DECISIONS.md). Solution de repli simple :
    on retrouve par regex ce que le JSON structuré aurait donné
    directement, sans toucher à l'infra Docker/Cowrie elle-même.
    Retourne None si la ligne ne correspond pas à ce format (ex: lignes
    de démarrage/erreur sans IP), auquel cas on retombe sur raw_message.
    """
    match = re.match(
        r'^(?P<timestamp>\S+)\s+\[(?P<component>[^,]+),(?P<session>[^,]+),'
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\]\s+(?P<msg>.*)$',
        message_str
    )
    if not match:
        return None

    ip = match.group('ip')
    msg = match.group('msg')
    parsed = {
        'timestamp': match.group('timestamp'),
        'src_ip': ip,
        'session': match.group('session'),
        'raw_message': message_str,
    }

    if msg.startswith('CMD:'):
        parsed['eventid'] = 'cowrie.command.input'
        parsed['input'] = msg[len('CMD:'):].strip()
    elif 'login attempt' in msg:
        cred_match = re.search(r'\[(?P<user>[^/]*)/(?P<pwd>[^\]]*)\]', msg)
        parsed['eventid'] = 'cowrie.login.success' if 'succeeded' in msg else 'cowrie.login.failed'
        if cred_match:
            parsed['username'] = cred_match.group('user')
            parsed['password'] = cred_match.group('pwd')
    elif msg.startswith('New connection'):
        parsed['eventid'] = 'cowrie.session.connect'
    else:
        parsed['eventid'] = 'cowrie.other'

    return parsed

def lambda_handler(event, context):
    local_cache = {}

    cw_data = event['awslogs']['data']
    compressed_payload = base64.b64decode(cw_data)
    payload = json.loads(gzip.decompress(compressed_payload))

    log_group = payload.get('logGroup', 'unknown').strip('/').replace('/', '-')
    log_events = payload.get('logEvents', [])

    enriched_records = []
    for entry in log_events:
        message_str = entry.get('message', '')
        try:
            if isinstance(message_str, str) and message_str.strip().startswith('{'):
                cowrie_payload = json.loads(message_str)
            else:
                cowrie_payload = parse_cowrie_text_log(message_str) or {'raw_message': message_str}
        except Exception as e:
            print(f"Erreur de parsing du message: {str(e)}")
            continue

        src_ip = cowrie_payload.get('src_ip')
        if src_ip:
            cowrie_payload['geoip'] = get_geoip_cached(src_ip, local_cache)

        enriched_records.append(json.dumps(cowrie_payload))

    if enriched_records:
        enriched_body = '\n'.join(enriched_records)
        timestamp_ms = int(time.time() * 1000)
        enriched_key = f"enriched-cowrie-logs/{log_group}-{timestamp_ms}.json"

        s3_client.put_object(
            Bucket=ENRICHED_BUCKET,
            Key=enriched_key,
            Body=enriched_body.encode('utf-8'),
            ContentType='application/json'
        )
        print(f"Fichier enrichi enregistré sous : {enriched_key}")

    return {'statusCode': 200, 'body': 'Enrichissement réussi'}
EOF
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "geoip_enrichment" {
  function_name    = "cowrie-geoip-enrichment"
  role             = aws_iam_role.lambda_geoip_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 128
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      ENRICHED_BUCKET   = aws_s3_bucket.enriched_logs_bucket.id
      CACHE_TABLE       = aws_dynamodb_table.geoip_cache.name
      CACHE_TTL_SECONDS = tostring(var.geoip_cache_ttl_seconds)
    }
  }
}

resource "aws_lambda_permission" "allow_cloudwatch_logs" {
  statement_id  = "AllowExecutionFromCloudWatchLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.geoip_enrichment.function_name
  principal     = "logs.eu-west-3.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.cowrie_log_group.arn}:*"
}

resource "aws_cloudwatch_log_subscription_filter" "cowrie_to_lambda" {
  name            = "cowrie-logs-to-lambda"
  log_group_name  = aws_cloudwatch_log_group.cowrie_log_group.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.geoip_enrichment.arn

  depends_on = [aws_lambda_permission.allow_cloudwatch_logs]
}

# ==============================================================================
# ÉTAPE 7 : TRAITEMENT ANALYTIQUE (AMAZON ATHENA)
# ==============================================================================

resource "aws_glue_catalog_database" "honeypot_db" {
  name = "honeypot_analytics_db"
}

resource "aws_glue_catalog_table" "cowrie_enriched_table" {
  name          = "cowrie_enriched_logs"
  database_name = aws_glue_catalog_database.honeypot_db.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    classification           = "json"
    "skip.header.line.count" = "0"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.enriched_logs_bucket.id}/enriched-cowrie-logs/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "cowrie-json-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "ignore.malformed.json" = "true"
      }
    }

    columns {
      name = "src_ip"
      type = "string"
    }
    columns {
      name = "timestamp"
      type = "string"
    }
    columns {
      name = "eventid"
      type = "string"
    }
    columns {
      name = "username"
      type = "string"
    }
    columns {
      name = "password"
      type = "string"
    }
    columns {
      name = "input"
      type = "string"
    }
    columns {
      name = "geoip"
      type = "struct<country:string,latitude:double,longitude:double>"
    }
    # Rend interrogeable le contenu actuellement capturé en texte brut
    # (repli temporaire le temps de retrouver un vrai JSON structuré,
    # voir DECISIONS.md) - sans cette colonne, ces lignes seraient
    # invisibles pour Athena malgré leur présence réelle dans S3.
    columns {
      name = "raw_message"
      type = "string"
    }
    columns {
      name = "session"
      type = "string"
    }
  }
}

resource "aws_s3_bucket" "athena_results_bucket" {
  bucket        = "honeypot-athena-query-results-${random_id.bucket_suffix.hex}"
  force_destroy = true

  tags = {
    Name        = "S3-Athena-Query-Results"
    Environment = "Production"
  }
}

resource "aws_s3_bucket_public_access_block" "athena_results_bucket_pab" {
  bucket                  = aws_s3_bucket.athena_results_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_athena_workgroup" "honeypot_wg" {
  name = "honeypot-analytics-wg"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results_bucket.id}/results/"
    }
  }
}

resource "aws_athena_named_query" "top10_source_ips" {
  name      = "top10-source-ips"
  database  = aws_glue_catalog_database.honeypot_db.name
  workgroup = aws_athena_workgroup.honeypot_wg.id

  query = <<-SQL
    SELECT src_ip, COUNT(*) AS nb_tentatives
    FROM cowrie_enriched_logs
    GROUP BY src_ip
    ORDER BY nb_tentatives DESC
    LIMIT 10;
  SQL
}

resource "aws_athena_named_query" "attacks_by_country" {
  name      = "attacks-by-country"
  database  = aws_glue_catalog_database.honeypot_db.name
  workgroup = aws_athena_workgroup.honeypot_wg.id

  query = <<-SQL
    SELECT geoip.country AS pays, COUNT(*) AS nb_attaques
    FROM cowrie_enriched_logs
    WHERE geoip.country IS NOT NULL
    GROUP BY geoip.country
    ORDER BY nb_attaques DESC;
  SQL
}

resource "aws_athena_named_query" "top_credentials" {
  name      = "top-credentials-testees"
  database  = aws_glue_catalog_database.honeypot_db.name
  workgroup = aws_athena_workgroup.honeypot_wg.id

  query = <<-SQL
    SELECT username, password, COUNT(*) AS nb_tentatives
    FROM cowrie_enriched_logs
    WHERE eventid = 'cowrie.login.failed'
    GROUP BY username, password
    ORDER BY nb_tentatives DESC
    LIMIT 10;
  SQL
}

resource "aws_athena_named_query" "top_commands" {
  name      = "top-commandes-executees"
  database  = aws_glue_catalog_database.honeypot_db.name
  workgroup = aws_athena_workgroup.honeypot_wg.id

  query = <<-SQL
    SELECT input, COUNT(*) AS nb_occurrences
    FROM cowrie_enriched_logs
    WHERE eventid = 'cowrie.command.input'
    GROUP BY input
    ORDER BY nb_occurrences DESC
    LIMIT 10;
  SQL
}

# ==============================================================================
# ÉTAPE 8 : CARTE DES ATTAQUES (S3 + CLOUDFRONT)
# ==============================================================================
# Page statique auto-hébergée (pas de service qui tourne en continu comme
# Streamlit aurait exigé). Une Lambda planifiée régénère périodiquement un
# instantané JSON depuis Athena ; la page le recharge côté client toutes
# les 60s pour un rendu "quasi temps réel" (ADR-008), sans jamais exposer
# de credentials AWS au visiteur.

# 1. Bucket S3 du site - privé, jamais public directement (CloudFront y
# accède via Origin Access Control, pas via un accès public classique).
resource "aws_s3_bucket" "map_site_bucket" {
  bucket        = "honeypot-attack-map-${random_id.bucket_suffix.hex}"
  force_destroy = true

  tags = {
    Name = "S3-Attack-Map-Site"
  }
}

resource "aws_s3_bucket_public_access_block" "map_site_bucket_pab" {
  bucket                  = aws_s3_bucket.map_site_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 2. La page elle-même, uploadée depuis le fichier local
resource "aws_s3_object" "map_index_html" {
  bucket       = aws_s3_bucket.map_site_bucket.id
  key          = "index.html"
  source       = "${path.module}/map/index.html"
  content_type = "text/html"
  etag         = filemd5("${path.module}/map/index.html")
}

# 3. Origin Access Control : seul CloudFront peut lire ce bucket,
# jamais un accès direct au bucket depuis Internet.
resource "aws_cloudfront_origin_access_control" "map_oac" {
  name                              = "honeypot-map-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "map_cdn" {
  enabled             = true
  default_root_object = "index.html"
  price_class         = "PriceClass_100" # Amérique du Nord + Europe, le moins cher

  origin {
    domain_name              = aws_s3_bucket.map_site_bucket.bucket_regional_domain_name
    origin_id                = "map-s3-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.map_oac.id
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods          = ["GET", "HEAD"]
    target_origin_id       = "map-s3-origin"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    # TTL normal pour la page elle-meme (HTML/JS/CSS) : change rarement,
    # pas besoin de revalider a chaque visite.
    min_ttl     = 0
    default_ttl = 60
    max_ttl     = 300
  }

  # Comportement dedie pour data.json, sans mise en cache CloudFront du
  # tout : sans ca, le bouton "Rafraichir" (et le sondage automatique)
  # pouvaient resservir une copie vieille de plusieurs minutes malgre un
  # fetch() cote navigateur en "no-store" - ce dernier n'a aucun effet
  # sur le cache CloudFront, seulement sur celui du navigateur. Avec
  # min/default/max_ttl a 0, CloudFront revalide systematiquement aupres
  # de S3 : la seule fraicheur qui compte desormais est celle du cycle de
  # regeneration de la Lambda (5 min), plus aucune couche de lenteur
  # supplementaire ajoutee par CloudFront.
  ordered_cache_behavior {
    path_pattern            = "/data.json"
    allowed_methods         = ["GET", "HEAD"]
    cached_methods           = ["GET", "HEAD"]
    target_origin_id        = "map-s3-origin"
    viewer_protocol_policy  = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 0
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  # Certificat HTTPS par défaut de CloudFront (*.cloudfront.net) -
  # suffisant pour un lien à partager, pas besoin de domaine personnalisé
  # ni de certificat ACM pour ce projet.
  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Name = "CDN-Attack-Map"
  }
}

resource "aws_s3_bucket_policy" "map_site_policy" {
  bucket = aws_s3_bucket.map_site_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "cloudfront.amazonaws.com" }
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.map_site_bucket.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.map_cdn.arn
          }
        }
      }
    ]
  })
}

# 4. Lambda planifiée : interroge Athena, écrit data.json dans le bucket
resource "aws_iam_role" "map_data_lambda_role" {
  name = "map-data-generator-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy" "map_data_lambda_policy" {
  name = "map-data-generator-policy"
  role = aws_iam_role.map_data_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["glue:GetTable", "glue:GetDatabase"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"]
        Resource = ["${aws_s3_bucket.enriched_logs_bucket.arn}", "${aws_s3_bucket.enriched_logs_bucket.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"]
        Resource = ["${aws_s3_bucket.athena_results_bucket.arn}", "${aws_s3_bucket.athena_results_bucket.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.map_site_bucket.arn}/*"
      }
    ]
  })
}

data "archive_file" "map_data_lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/map_data_lambda.zip"

  source {
    content  = <<EOF
import json
import time
import os
import boto3

athena_client = boto3.client('athena')
s3_client = boto3.client('s3')

DATABASE = "honeypot_analytics_db"
WORKGROUP = "honeypot-analytics-wg"
MAP_BUCKET = os.environ.get('MAP_BUCKET')

def query_countries():
    return """
    SELECT geoip.country AS country, geoip.latitude AS lat, geoip.longitude AS lon, COUNT(*) AS cnt
    FROM cowrie_enriched_logs
    WHERE geoip.country IS NOT NULL AND geoip.country != 'Unknown' AND geoip.latitude IS NOT NULL
      AND geoip.latitude != 0.0 AND eventid = 'cowrie.command.input'
    GROUP BY geoip.country, geoip.latitude, geoip.longitude
    ORDER BY cnt DESC
    """

def query_credentials():
    return """
    SELECT username, password, COUNT(*) AS cnt
    FROM cowrie_enriched_logs
    WHERE eventid IN ('cowrie.login.failed', 'cowrie.login.success') AND username IS NOT NULL
    GROUP BY username, password
    ORDER BY cnt DESC
    LIMIT 5
    """

def query_commands():
    return """
    SELECT input, COUNT(*) AS cnt
    FROM cowrie_enriched_logs
    WHERE eventid = 'cowrie.command.input' AND input IS NOT NULL
    GROUP BY input
    ORDER BY cnt DESC
    LIMIT 5
    """

def query_earliest_timestamp():
    return """
    SELECT MIN(timestamp) AS earliest
    FROM cowrie_enriched_logs
    WHERE eventid = 'cowrie.command.input' AND timestamp IS NOT NULL
    """

def run_query(sql):
    response = athena_client.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={'Database': DATABASE},
        WorkGroup=WORKGROUP
    )
    query_id = response['QueryExecutionId']

    state = 'RUNNING'
    for _ in range(20):
        status = athena_client.get_query_execution(QueryExecutionId=query_id)
        state = status['QueryExecution']['Status']['State']
        if state in ('SUCCEEDED', 'FAILED', 'CANCELLED'):
            break
        time.sleep(2)

    if state != 'SUCCEEDED':
        reason = status['QueryExecution']['Status'].get('StateChangeReason', 'raison inconnue')
        raise Exception(f"Requete Athena non aboutie ({state}): {reason}")

    return query_id

def fetch_all_rows(query_id):
    rows = []
    next_token = None
    while True:
        kwargs = {'QueryExecutionId': query_id}
        if next_token:
            kwargs['NextToken'] = next_token
        result = athena_client.get_query_results(**kwargs)
        rows.extend(result['ResultSet']['Rows'])
        next_token = result.get('NextToken')
        if not next_token:
            break
    return rows

def rows_to_values(rows):
    """Ignore la premiere ligne (en-tete des colonnes) et extrait les valeurs brutes."""
    out = []
    for row in rows[1:]:
        out.append([c.get('VarCharValue') for c in row['Data']])
    return out

def build_countries(values):
    countries = []
    total = 0
    for v in values:
        if len(v) < 4 or not all(v):
            continue
        try:
            country, lat, lon, cnt = v[0], float(v[1]), float(v[2]), int(v[3])
        except (ValueError, TypeError):
            continue
        countries.append({'country': country, 'lat': lat, 'lon': lon, 'count': cnt})
        total += cnt
    countries.sort(key=lambda c: c['count'], reverse=True)
    return countries, total

def build_credentials(values):
    out = []
    for v in values:
        if len(v) < 3:
            continue
        user, pwd, cnt = v[0], v[1], v[2]
        if not user or not cnt:
            continue
        try:
            cnt = int(cnt)
        except (ValueError, TypeError):
            continue
        out.append({'username': user, 'password': pwd or '', 'count': cnt})
    return out

def build_commands(values):
    out = []
    for v in values:
        if len(v) < 2 or not v[0] or not v[1]:
            continue
        try:
            cnt = int(v[1])
        except (ValueError, TypeError):
            continue
        out.append({'command': v[0], 'count': cnt})
    return out

def generate_payload():
    countries_values = rows_to_values(fetch_all_rows(run_query(query_countries())))
    credentials_values = rows_to_values(fetch_all_rows(run_query(query_credentials())))
    commands_values = rows_to_values(fetch_all_rows(run_query(query_commands())))
    earliest_values = rows_to_values(fetch_all_rows(run_query(query_earliest_timestamp())))

    countries, total = build_countries(countries_values)
    top_credentials = build_credentials(credentials_values)
    top_commands = build_commands(commands_values)
    earliest_timestamp = earliest_values[0][0] if earliest_values and earliest_values[0] and earliest_values[0][0] else None

    return {
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'earliest_timestamp': earliest_timestamp,
        'total': total,
        'countries': countries,
        'top_credentials': top_credentials,
        'top_commands': top_commands
    }

def lambda_handler(event, context):
    # Un seul mode desormais : declenchee par EventBridge (toutes les 5
    # min), regenere systematiquement data.json avec l'ensemble des
    # donnees disponibles depuis le debut de la capture. Plus de mode API
    # ni de filtre de periode (simplifie volontairement, voir DECISIONS.md
    # - l'analyse par periode sera reprise plus en profondeur en Phase 4).
    payload = generate_payload()
    s3_client.put_object(
        Bucket=MAP_BUCKET,
        Key='data.json',
        Body=json.dumps(payload).encode('utf-8'),
        ContentType='application/json',
        CacheControl='no-cache'
    )

    print(f"data.json regenere : {len(payload['countries'])} pays, {payload['total']} evenements, "
          f"{len(payload['top_credentials'])} identifiants, {len(payload['top_commands'])} commandes")
    return {'statusCode': 200, 'body': 'OK'}
EOF
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "map_data_generator" {
  function_name    = "honeypot-map-data-generator"
  role             = aws_iam_role.map_data_lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 240
  memory_size      = 128
  filename         = data.archive_file.map_data_lambda_zip.output_path
  source_code_hash = data.archive_file.map_data_lambda_zip.output_base64sha256

  environment {
    variables = {
      MAP_BUCKET = aws_s3_bucket.map_site_bucket.id
    }
  }
}

# 5. Planification : régénère data.json toutes les minutes. Un seul état
# affiché (toutes les données depuis le début de la capture), un seul
# mécanisme de mise à jour (ce cron + le sondage côté page toutes les
# 60s) - pas de bouton de rafraîchissement manuel, simplifié
# volontairement (voir DECISIONS.md ; l'analyse par période sera reprise
# plus en profondeur en Phase 4).
resource "aws_cloudwatch_event_rule" "map_data_schedule" {
  name                = "honeypot-map-data-refresh"
  schedule_expression = "rate(1 minute)"
}

resource "aws_cloudwatch_event_target" "map_data_schedule_target" {
  rule      = aws_cloudwatch_event_rule.map_data_schedule.name
  target_id = "map-data-generator"
  arn       = aws_lambda_function.map_data_generator.arn
}

resource "aws_lambda_permission" "allow_eventbridge_map_data" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.map_data_generator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.map_data_schedule.arn
}

# ==============================================================================
# OUTPUTS
# ==============================================================================

output "honeypot_public_ip" {
  description = "IP publique de l'instance honeypot"
  value       = aws_eip.honeypot_eip.public_ip
}

output "enriched_logs_bucket_name" {
  description = "Nom du bucket S3 des logs enrichis"
  value       = aws_s3_bucket.enriched_logs_bucket.id
}

output "lambda_function_name" {
  description = "Nom de la fonction Lambda d'enrichissement"
  value       = aws_lambda_function.geoip_enrichment.function_name
}

output "geoip_cache_table_name" {
  description = "Nom de la table DynamoDB utilisée comme cache GeoIP (TTL court)"
  value       = aws_dynamodb_table.geoip_cache.name
}

output "athena_database_name" {
  description = "Nom de la base Glue/Athena"
  value       = aws_glue_catalog_database.honeypot_db.name
}

output "athena_workgroup_name" {
  description = "Nom du workgroup Athena"
  value       = aws_athena_workgroup.honeypot_wg.name
}

output "ec2_instance_id" {
  description = "ID de l'instance EC2, pour la connexion via SSM"
  value       = aws_instance.honeypot_ec2.id
}

output "attack_map_url" {
  description = "URL HTTPS de la carte des attaques (CloudFront)"
  value       = "https://${aws_cloudfront_distribution.map_cdn.domain_name}"
}
