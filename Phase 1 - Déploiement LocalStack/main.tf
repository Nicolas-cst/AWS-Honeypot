# ==============================================================================
# HONEYPOT AWS - VERSION LOCALSTACK (test local uniquement)
# ==============================================================================
# Architecture : Cowrie -> CloudWatch Logs -> Lambda -> S3 enrichi

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
  }
}

# Provider AWS pointant vers LocalStack
provider "aws" {
  region                      = "eu-west-3"
  access_key                  = "mock_access_key"
  secret_key                  = "mock_secret_key"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true

  endpoints {
    ec2      = "http://localhost:4566"
    iam      = "http://localhost:4566"
    s3       = "http://localhost:4566"
    logs     = "http://localhost:4566"
    lambda   = "http://localhost:4566"
    dynamodb = "http://localhost:4566"
  }
}

# ------------------------------------------------------------------------------
# Variables
# ------------------------------------------------------------------------------

variable "geoip_cache_ttl_seconds" {
  description = "Durée de vie (TTL) des entrées du cache GeoIP dans DynamoDB, en secondes."
  type        = number
  default     = 300
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

# Security Group — test LocalStack : ingress large, sans conséquence réelle
# (rien n'est exposé sur Internet en local). La restriction stricte à une
# IP personnelle est appliquée dans le fichier de production réelle.
resource "aws_security_group" "honeypot_sg" {
  name        = "honeypot-sg"
  description = "Security group pour l instance honeypot - test LocalStack"
  vpc_id      = aws_vpc.honeypot_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "SG-Honeypot-LocalStack"
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

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-cloudwatch-profile"
  role = aws_iam_role.ec2_cloudwatch_role.name
}

resource "aws_instance" "honeypot_ec2" {
  ami                  = "ami-00000000"
  instance_type        = "t3.micro"
  subnet_id            = aws_subnet.public_subnet.id
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  vpc_security_group_ids = [aws_security_group.honeypot_sg.id]

  # - sshd désactivé avant Docker : libère le port 22 pour Cowrie (ADR-017).
  # - Le conteneur Cowrie utilise le driver de logging Docker "awslogs" :
  #   ses logs (stdout) sont envoyés directement à CloudWatch Logs par
  #   Docker lui-même, sans dépendre d'un agent CloudWatch séparé à
  #   configurer. C'est ce qui manquait dans les versions précédentes du
  #   user_data (l'agent était installé mais jamais configuré ni démarré).
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
    Name = "Honeypot-Cowrie-LocalStack"
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
# Le groupe de logs doit exister avant que le conteneur Cowrie ne démarre
# (le driver awslogs peut le créer lui-même si absent, mais le déclarer
# ici garantit qu'il existe dès le déploiement Terraform, notamment pour
# que le subscription filter puisse s'y attacher).

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
  bucket        = "honeypot-enriched-logs"
  force_destroy = true

  tags = {
    Name        = "S3-Enriched-Logs"
    Environment = "LocalStack-Test"
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
    """Interroge ip-api.com pour obtenir la géolocalisation d'une IP."""
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
    """
    Cache à deux niveaux (ADR-010) :
    - L1 : dictionnaire en mémoire, valable pour l'invocation en cours.
    - L2 : table DynamoDB, valable entre invocations, TTL court.
    Le TTL est vérifié manuellement (champ expires_at) plutôt que de se
    fier uniquement à la suppression automatique DynamoDB.
    """
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

def lambda_handler(event, context):
    """
    Déclenchée directement par un subscription filter CloudWatch Logs
    (ADR-015). Contrairement à un fichier déposé par Firehose sur S3, le
    payload arrive compressé en gzip et encodé en base64 dans
    event['awslogs']['data'] : il faut le décompresser avant de le parser.
    """
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
                cowrie_payload = {'raw_message': message_str}
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

# Autorise le service CloudWatch Logs (logs.amazonaws.com) à invoquer
# directement cette Lambda. Sans cette permission, le subscription filter
# ci-dessous échouerait silencieusement à déclencher la fonction.
resource "aws_lambda_permission" "allow_cloudwatch_logs" {
  statement_id  = "AllowExecutionFromCloudWatchLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.geoip_enrichment.function_name
  principal     = "logs.eu-west-3.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.cowrie_log_group.arn}:*"
}

# Le subscription filter : remplace Firehose, invoque la Lambda directement
# à chaque batch de logs (regroupement géré par CloudWatch, pas configurable
# explicitement comme l'était le buffering Firehose).
resource "aws_cloudwatch_log_subscription_filter" "cowrie_to_lambda" {
  name            = "cowrie-logs-to-lambda"
  log_group_name  = aws_cloudwatch_log_group.cowrie_log_group.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.geoip_enrichment.arn

  depends_on = [aws_lambda_permission.allow_cloudwatch_logs]
}

# ==============================================================================
# OUTPUTS
# ==============================================================================

output "honeypot_public_ip" {
  description = "IP publique (simulée) de l'instance honeypot"
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
