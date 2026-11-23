# ==============================================================================
# HONEYPOT AWS (COWRIE)
# ==============================================================================
# Chaîne de données : Cowrie -> CloudWatch Logs -> Lambda processor (lecture du
# log texte, pays via ip-api avec cache, comptage idempotent) -> compteurs
# DynamoDB + événements S3 -> Lambda publisher (chaque minute) -> data.json ->
# CloudFront -> carte. Athena sert aux requêtes manuelles sur les événements S3.
#
# Sécurité :
# - honeypot joignable uniquement depuis admin_test_cidr, pas encore depuis Internet ;
# - instance durcie (IMDSv2, iptables, test de sortie avant chaque démarrage de
#   Cowrie) et administrée par Systems Manager, sans vrai serveur SSH ;
# - NACL dédié au sous-réseau, en plus du security group ;
# - alertes par email, budget, dashboard, alarmes et GuardDuty ;
# - kill switch : mise en quarantaine automatique de l'instance sur certains
#   findings GuardDuty.
#
# L'état Terraform est local.

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

# Suffixe commun aux noms de bucket : un nom de bucket est unique au niveau
# mondial. Il est tiré une fois puis reste stable.
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# Identifiants lus dans l'environnement (profil AWS CLI), jamais écrits ici.
provider "aws" {
  region = "eu-west-3" # Paris
}

# ------------------------------------------------------------------------------
# Variables
# ------------------------------------------------------------------------------
variable "processor_geoip_ttl_seconds" {
  description = "TTL du cache GeoIP de la Lambda processor, en secondes (259200 = 72 h)."
  type        = number
  default     = 259200
}

# Une URL invalide permet de simuler une panne d'ip-api : le pays devient Unknown.
variable "processor_geoip_api_url" {
  description = "URL de base de l'API GeoIP (ip-api gratuit est en HTTP)."
  type        = string
  default     = "http://ip-api.com/json"
}

# Aucune concurrence réservée sur les Lambdas : avec un quota de 10 exécutions,
# AWS n'en laisse aucune à réserver. Les invocations sont asynchrones : en cas
# de throttling, elles sont retentées pendant plusieurs heures, pas perdues.

variable "admin_test_cidr" {
  description = "CIDR de l'IP personnelle autorisée à se connecter au honeypot (ex : 82.123.45.67/32)."
  type        = string

  validation {
    condition     = var.admin_test_cidr != "0.0.0.0/0"
    error_message = "admin_test_cidr ne doit pas être 0.0.0.0/0 tant que le honeypot n'est pas ouvert au public : indique ton IP publique au format CIDR (ex : 82.123.45.67/32)."
  }
}

# AMI Amazon Linux 2023 standard la plus récente.
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    # Motif strict : un motif plus large peut tomber sur les variantes
    # "ecs" ou "minimal" d'Amazon Linux 2023.
    values = ["al2023-ami-2023.*-kernel-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ==============================================================================
# ALERTES ET BUDGET
# ==============================================================================
# Toutes les alertes du projet arrivent par email via le topic honeypot-alerts.

variable "alert_email" {
  description = "Adresse email qui reçoit les alertes (SNS honeypot-alerts). Un email de confirmation est envoyé : il faut cliquer sur le lien pour activer l'abonnement."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email doit être une adresse email valide."
  }
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "honeypot_alerts" {
  name = "honeypot-alerts"

  tags = {
    Name = "SNS-Honeypot-Alerts"
  }
}

# L'abonnement reste en attente tant que le lien du mail de confirmation n'a
# pas été cliqué.
resource "aws_sns_topic_subscription" "alerts_email" {
  topic_arn = aws_sns_topic.honeypot_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Cette policy remplace celle par défaut : la première déclaration la reprend
# (propriétaire du compte), les suivantes ouvrent la publication à Budgets,
# EventBridge et aux alarmes CloudWatch de ce compte.
resource "aws_sns_topic_policy" "honeypot_alerts" {
  arn = aws_sns_topic.honeypot_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowOwnerAccount"
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action = [
          "SNS:GetTopicAttributes",
          "SNS:SetTopicAttributes",
          "SNS:AddPermission",
          "SNS:RemovePermission",
          "SNS:DeleteTopic",
          "SNS:Subscribe",
          "SNS:ListSubscriptionsByTopic",
          "SNS:Publish"
        ]
        Resource  = aws_sns_topic.honeypot_alerts.arn
        Condition = { StringEquals = { "AWS:SourceOwner" = data.aws_caller_identity.current.account_id } }
      },
      {
        Sid       = "AllowBudgetsPublish"
        Effect    = "Allow"
        Principal = { Service = "budgets.amazonaws.com" }
        Action    = "SNS:Publish"
        Resource  = aws_sns_topic.honeypot_alerts.arn
        Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
      },
      {
        Sid       = "AllowEventBridgePublish"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "SNS:Publish"
        Resource  = aws_sns_topic.honeypot_alerts.arn
        Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
      },
      {
        Sid       = "AllowCloudWatchAlarmsPublish"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "SNS:Publish"
        Resource  = aws_sns_topic.honeypot_alerts.arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
          ArnLike      = { "aws:SourceArn" = "arn:aws:cloudwatch:eu-west-3:${data.aws_caller_identity.current.account_id}:alarm:*" }
        }
      }
    ]
  })
}

# Alerte à 70 % puis à 100 % de 10 $ par mois. Un budget prévient mais ne
# bloque aucune dépense.
resource "aws_budgets_budget" "honeypot_monthly" {
  name         = "honeypot-monthly-budget"
  budget_type  = "COST"
  limit_amount = "10"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 70
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.honeypot_alerts.arn]
  }

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.honeypot_alerts.arn]
  }

  depends_on = [aws_sns_topic_policy.honeypot_alerts]
}

# Les groupes de logs des Lambdas sont déclarés ici pour fixer leur rétention.
# S'il existe déjà (créé automatiquement par AWS), l'importer avant l'apply.
resource "aws_cloudwatch_log_group" "lambda_processor_logs" {
  name              = "/aws/lambda/honeypot-processor"
  retention_in_days = 14

  tags = {
    Name = "CloudWatch-Lambda-Processor-Logs"
  }
}

resource "aws_cloudwatch_log_group" "lambda_publisher_logs" {
  name              = "/aws/lambda/honeypot-publisher"
  retention_in_days = 14

  tags = {
    Name = "CloudWatch-Lambda-Publisher-Logs"
  }
}

# ==============================================================================
# RÉSEAU
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

# Le port 22 (Cowrie) n'est ouvert qu'à admin_test_cidr. La description du
# groupe n'est pas modifiée : la changer recréerait le security group.
resource "aws_security_group" "honeypot_sg" {
  name        = "honeypot-sg"
  description = "Security group pour l instance honeypot - phase 2 : acces restreint a l IP personnelle"
  vpc_id      = aws_vpc.honeypot_vpc.id

  ingress {
    description = "Cowrie (SSH) - IP personnelle uniquement"
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
# NACL DU SOUS-RÉSEAU
# ==============================================================================
# Règles séparées, numérotées à partir de 100 : les numéros 1 à 9 restent
# libres pour le kill switch, dont les refus passent ainsi avant tout le reste.
# Un NACL est sans état, les réponses (ports éphémères) doivent donc être
# autorisées explicitement. Le DNS du VPC et IMDS ne sont pas filtrés par un NACL.

resource "aws_network_acl" "honeypot_nacl" {
  vpc_id = aws_vpc.honeypot_vpc.id

  # Association faite plus bas, une fois toutes les règles créées : un NACL
  # vide refuse tout et couperait l'instance pendant l'apply.

  tags = {
    Name = "NACL-Honeypot"
  }
}

# ---- Entrée ----

resource "aws_network_acl_rule" "in_ssh_admin" {
  network_acl_id = aws_network_acl.honeypot_nacl.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = var.admin_test_cidr
  from_port      = 22
  to_port        = 22
}

# Réponses aux connexions HTTPS de l'hôte (Docker Hub, CloudWatch, SSM, dnf).
resource "aws_network_acl_rule" "in_ephemeral" {
  network_acl_id = aws_network_acl.honeypot_nacl.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

# ---- Sortie ----

resource "aws_network_acl_rule" "out_https" {
  network_acl_id = aws_network_acl.honeypot_nacl.id
  rule_number    = 100
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

# Réponses SSH vers l'IP d'administration uniquement.
resource "aws_network_acl_rule" "out_ephemeral_admin" {
  network_acl_id = aws_network_acl.honeypot_nacl.id
  rule_number    = 110
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = var.admin_test_cidr
  from_port      = 1024
  to_port        = 65535
}

# ---- Association au sous-réseau ----

resource "aws_network_acl_association" "honeypot_nacl_assoc" {
  network_acl_id = aws_network_acl.honeypot_nacl.id
  subnet_id      = aws_subnet.public_subnet.id

  depends_on = [
    aws_network_acl_rule.in_ssh_admin,
    aws_network_acl_rule.in_ephemeral,
    aws_network_acl_rule.out_https,
    aws_network_acl_rule.out_ephemeral_admin,
  ]
}

# ==============================================================================
# INSTANCE EC2
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

# Rôle minimal : écrire dans /aws/ec2/cowrie, rien d'autre. Des credentials
# volés ne permettraient que d'y écrire de faux logs, que le processor valide.
#
# Policies attachées par des ressources séparées, jamais par inline_policy ni
# managed_policy_arns : ces deux attributs sont exclusifs, et un apply
# retirerait la policy Deny * posée par le kill switch.
resource "aws_iam_policy" "ec2_cowrie_logs" {
  name        = "ec2-cowrie-logs-minimal"
  description = "Ecriture des logs Cowrie dans /aws/ec2/cowrie uniquement"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.cowrie_log_group.arn}:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cowrie_logs_attach" {
  role       = aws_iam_role.ec2_cloudwatch_role.name
  policy_arn = aws_iam_policy.ec2_cowrie_logs.arn
}

# Administration par Systems Manager plutôt que par un vrai serveur SSH.
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

  # IMDSv2 obligatoire et hop limit 1 : les réponses IMDS n'atteignent pas le
  # conteneur, qui ne peut donc pas lire les credentials du rôle. Les règles
  # iptables du user_data ajoutent une seconde barrière.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # Le user_data ne s'exécute qu'au premier démarrage : le modifier recrée donc
  # l'instance. L'EIP se réassocie, l'IP publique ne change pas.
  user_data_replace_on_change = true

  # Une nouvelle AMI ne doit pas remplacer l'instance à chaque apply. Pour la
  # mettre à jour : terraform apply -replace=aws_instance.honeypot_ec2
  lifecycle {
    ignore_changes = [ami]
  }

  # Le groupe de logs doit exister avant le premier démarrage de Cowrie.
  depends_on = [aws_cloudwatch_log_group.cowrie_log_group]

  # L'agent SSM est déjà installé sur Amazon Linux 2023. Le vrai sshd est
  # masqué : il prendrait sinon le port 22 avant Cowrie.
  #
  # Cowrie écrit son log texte sur la sortie standard, que Docker envoie à
  # CloudWatch Logs (driver awslogs). Le log JSON de Cowrie reste interne au
  # conteneur.
  user_data_base64 = base64encode(<<-EOF
    #!/bin/bash
    # mask plutôt que disable : un service masqué ne peut plus démarrer du tout.
    systemctl mask --now sshd sshd.socket
    dnf install -y docker iptables-nft
    systemctl enable --now docker

    # ---- Règles iptables : isolent le conteneur de l'hôte et d'IMDS ----
    # Seules les nouvelles connexions qui partent de docker0 sont bloquées :
    # les attaques entrantes et leurs réponses passent. -C évite les doublons.
    cat > /usr/local/sbin/honeypot-iptables.sh <<'SCRIPT'
    #!/bin/bash
    set -e
    iptables -C DOCKER-USER -d 169.254.169.254 -j DROP 2>/dev/null || iptables -I DOCKER-USER -d 169.254.169.254 -j DROP
    iptables -C DOCKER-USER -i docker0 -m conntrack --ctstate NEW -j DROP 2>/dev/null || iptables -I DOCKER-USER -i docker0 -m conntrack --ctstate NEW -j DROP
    iptables -C INPUT -i docker0 -m conntrack --ctstate NEW -j DROP 2>/dev/null || iptables -I INPUT -i docker0 -m conntrack --ctstate NEW -j DROP
    SCRIPT
    chmod 750 /usr/local/sbin/honeypot-iptables.sh

    # ---- Test de sortie : Cowrie ne démarre que si un conteneur ne peut pas sortir ----
    # Le témoin (réseau hôte) doit réussir, sinon le test ne prouve rien.
    # En réseau bridge, comme Cowrie, la connexion doit échouer.
    cat > /usr/local/sbin/honeypot-egress-test.sh <<'SCRIPT'
    #!/bin/bash
    IMG=alpine:3
    docker pull -q "$IMG" >/dev/null || { echo "EGRESS-TEST: pull de $IMG impossible, demarrage refuse"; exit 1; }
    docker run --rm --network host "$IMG" nc -w 5 1.1.1.1 443 </dev/null >/dev/null 2>&1 || { echo "EGRESS-TEST: temoin en echec, demarrage refuse"; exit 1; }
    if docker run --rm "$IMG" nc -w 5 1.1.1.1 443 </dev/null >/dev/null 2>&1; then
      echo "EGRESS-TEST: le conteneur peut sortir vers Internet, demarrage refuse"; exit 1
    fi
    if docker run --rm "$IMG" nc -w 5 169.254.169.254 80 </dev/null >/dev/null 2>&1; then
      echo "EGRESS-TEST: le conteneur atteint IMDS, demarrage refuse"; exit 1
    fi
    echo "EGRESS-TEST: OK, le conteneur ne peut pas sortir"
    SCRIPT
    chmod 750 /usr/local/sbin/honeypot-egress-test.sh

    # ---- Unité systemd des règles iptables (après docker, avant Cowrie) ----
    cat > /etc/systemd/system/honeypot-iptables.service <<'UNIT'
    [Unit]
    Description=Regles iptables du honeypot (conteneur isole de l hote et d IMDS)
    After=docker.service
    Requires=docker.service

    [Service]
    Type=oneshot
    RemainAfterExit=yes
    ExecStart=/usr/local/sbin/honeypot-iptables.sh

    [Install]
    WantedBy=multi-user.target
    UNIT

    # ---- Unité systemd de Cowrie, avec le test de sortie avant chaque démarrage ----
    # Sans les règles iptables, Cowrie ne démarre pas. StartLimitIntervalSec=0 :
    # systemd ne renonce jamais à le relancer.
    cat > /etc/systemd/system/cowrie.service <<'UNIT'
    [Unit]
    Description=Conteneur Cowrie (honeypot SSH)
    After=docker.service honeypot-iptables.service
    Requires=docker.service honeypot-iptables.service
    StartLimitIntervalSec=0

    [Service]
    TimeoutStartSec=600
    Restart=on-failure
    RestartSec=15
    # Résultat du test de sortie : journalctl -u cowrie.
    StandardOutput=journal
    ExecStartPre=-/usr/bin/docker rm -f cowrie
    ExecStartPre=-/usr/bin/docker pull cowrie/cowrie:latest
    ExecStartPre=/usr/local/sbin/honeypot-egress-test.sh
    ExecStart=/usr/bin/docker run --rm --name cowrie -p 22:2222 --log-driver=awslogs --log-opt awslogs-region=eu-west-3 --log-opt awslogs-group=/aws/ec2/cowrie cowrie/cowrie:latest
    ExecStop=/usr/bin/docker stop cowrie

    [Install]
    WantedBy=multi-user.target
    UNIT

    systemctl daemon-reload
    systemctl enable honeypot-iptables.service cowrie.service
    systemctl start --no-block honeypot-iptables.service cowrie.service
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
# LOGS COWRIE
# ==============================================================================

resource "aws_cloudwatch_log_group" "cowrie_log_group" {
  name              = "/aws/ec2/cowrie"
  retention_in_days = 14

  tags = {
    Name = "CloudWatch-Cowrie-Logs"
  }
}

# ==============================================================================
# CACHE GEOIP
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
# LAMBDA PROCESSOR
# ==============================================================================
# Lit les lignes Cowrie, trouve le pays de chaque IP, puis met à jour les
# compteurs DynamoDB et écrit les événements normalisés dans S3. Un même lot
# rejoué n'est jamais compté deux fois.

# Compteurs : COUNTRY#<code ISO>, DATE#<AAAA-MM-JJ>, CMD#<commande>.
resource "aws_dynamodb_table" "honeypot_stats" {
  name         = "honeypot-stats"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  tags = {
    Name = "DynamoDB-Honeypot-Stats"
  }
}

# Marqueurs des lots déjà traités. Les rejeux n'arrivent que dans les heures
# qui suivent : 7 jours suffisent.
resource "aws_dynamodb_table" "honeypot_batches" {
  name         = "honeypot-batches"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  ttl {
    enabled        = true
    attribute_name = "expires_at"
  }

  tags = {
    Name = "DynamoDB-Honeypot-Batches"
  }
}

resource "aws_s3_bucket" "processed_logs_bucket" {
  bucket        = "processed-logs-${random_id.bucket_suffix.hex}"
  force_destroy = true

  tags = {
    Name = "S3-Processed-Logs"
  }
}

resource "aws_s3_bucket_public_access_block" "processed_logs_bucket_pab" {
  bucket                  = aws_s3_bucket.processed_logs_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_role" "lambda_processor_role" {
  name = "lambda-honeypot-processor-role"

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

# Ses logs, events/ dans S3, son cache et les deux tables. Une transaction
# exige PutItem et UpdateItem sur chaque table touchée.
resource "aws_iam_role_policy" "lambda_processor_policy" {
  name = "lambda-honeypot-processor-policy"
  role = aws_iam_role.lambda_processor_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.lambda_processor_logs.arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.processed_logs_bucket.arn}/events/*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem"]
        Resource = aws_dynamodb_table.geoip_cache.arn
      },
      {
        Effect = "Allow"
        Action = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = [
          aws_dynamodb_table.honeypot_stats.arn,
          aws_dynamodb_table.honeypot_batches.arn,
        ]
      }
    ]
  })
}

data "archive_file" "processor_zip" {
  type        = "zip"
  output_path = "${path.module}/processor_function.zip"

  source {
    content  = <<EOF
import base64
import gzip
import hashlib
import json
import os
import random
import re
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

PROCESSED_BUCKET = os.environ.get('PROCESSED_BUCKET', '')
STATS_TABLE = os.environ.get('STATS_TABLE', '')
BATCHES_TABLE = os.environ.get('BATCHES_TABLE', '')
CACHE_TABLE = os.environ.get('CACHE_TABLE', '')
GEOIP_API_URL = os.environ.get('GEOIP_API_URL', 'http://ip-api.com/json').rstrip('/')
GEOIP_TTL_SECONDS = int(os.environ.get('GEOIP_TTL_SECONDS', '259200'))

UNKNOWN_TTL_SECONDS = 300          # un echec geoip n'est memorise que 5 min
BATCH_MARKER_TTL_SECONDS = 7 * 86400
MAX_TX_ITEMS = 100                 # limite DynamoDB : 100 elements / transaction
MAX_GEOIP_CALLS = 10               # appels ip-api max par invocation
MIN_REMAINING_MS = 8000            # sous ce seuil : plus d'appel ip-api
MAX_CMD_LEN = 256
MAX_CRED_LEN = 64

s3 = boto3.client('s3')
ddb = boto3.client('dynamodb')

CC_RE = re.compile(r'^[A-Z]{2}$')
IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
LINE_RE = re.compile(
    r'^(?P<timestamp>\S+)\s+\[(?P<component>[^,\]]+),(?P<session>[^,\]]+),'
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\]\s+(?P<msg>.*)$'
)

# Liste blanche : tout premier mot hors liste devient "other". Aucune valeur
# issue de l'attaquant ne devient donc une cle DynamoDB ou du texte de la carte.
ALLOWED_COMMANDS = frozenset((
    'ls cd pwd cat echo uname whoami id w who last uptime free df du ps top '
    'kill pkill killall env export unset history crontab sudo su sh bash '
    'busybox wget curl tftp ftp nc ncat netstat ss ifconfig ip ping ssh scp '
    'chmod chown mkdir rm rmdir cp mv touch ln tar gzip gunzip unzip grep '
    'egrep head tail wc sort uniq cut awk sed find which whereis lscpu lsmod '
    'dmesg mount umount dd nohup sleep python python3 perl php gcc make '
    'systemctl service passwd useradd adduser exit'
).split())


def normalize_command(raw):
    """Premier mot de la commande, en minuscules, sans chemin ; 'other' si
    hors liste blanche. La chaine est tronquee avant tout traitement."""
    if not isinstance(raw, str):
        return 'other'
    parts = raw[:MAX_CMD_LEN].strip().split(None, 1)
    if not parts:
        return 'other'
    word = parts[0].lower().rsplit('/', 1)[-1]
    return word if word in ALLOWED_COMMANDS else 'other'


def event_date(line_ts, cw_ts_ms):
    """Date (UTC, YYYY-MM-DD) de l'evenement, jamais celle du traitement."""
    try:
        return datetime.strptime(line_ts[:10], '%Y-%m-%d').strftime('%Y-%m-%d')
    except (ValueError, TypeError):
        pass
    try:
        return datetime.fromtimestamp(int(cw_ts_ms) / 1000, tz=timezone.utc).strftime('%Y-%m-%d')
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def parse_line(message, cw_ts_ms):
    """Ligne texte Cowrie -> evenement normalise, ou None si la ligne n'est
    pas un evenement d'attaque (connexion, tentative de login, commande)."""
    if not isinstance(message, str):
        return None
    m = LINE_RE.match(message)
    if not m:
        return None
    ip = m.group('ip')
    if not IP_RE.match(ip) or any(int(p) > 255 for p in ip.split('.')):
        return None
    msg = m.group('msg')
    date = event_date(m.group('timestamp'), cw_ts_ms)
    if date is None:
        return None

    ev = {'event_date': date, 'ts': m.group('timestamp')[:40], 'src_ip': ip,
          'session': m.group('session')[:32]}
    if msg.startswith('CMD:'):
        ev['event'] = 'command'
        ev['command'] = normalize_command(msg[4:])
    elif 'login attempt' in msg:
        ev['event'] = 'login_success' if 'succeeded' in msg else 'login_failed'
        c = re.search(r'\[(?P<u>[^/]*)/(?P<p>[^\]]*)\]', msg)
        if c:
            ev['username'] = c.group('u')[:MAX_CRED_LEN]
            ev['password'] = c.group('p')[:MAX_CRED_LEN]
    elif msg.startswith('New connection'):
        ev['event'] = 'connect'
    else:
        return None
    return ev


def _fetch_country_code(ip):
    """Appel ip-api (HTTP, gratuit). Reponse non fiable a priori : le code
    n'est accepte que s'il valide ^[A-Z]{2}$. None en cas d'echec."""
    try:
        url = f"{GEOIP_API_URL}/{ip}?fields=status,countryCode"
        req = urllib.request.Request(url, headers={'User-Agent': 'honeypot-processor'})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read(4096).decode('utf-8', 'replace'))
        code = data.get('countryCode') if data.get('status') == 'success' else None
        return code if isinstance(code, str) and CC_RE.match(code) else None
    except Exception as exc:
        print(f"geoip: echec appel ({type(exc).__name__})")
        return None


def lookup_country(ip, memo, state, context):
    if ip in memo:
        return memo[ip]
    now = int(time.time())
    key = {'ip': {'S': ip}}
    try:
        item = ddb.get_item(TableName=CACHE_TABLE, Key=key).get('Item')
        if item and int(item['expires_at']['N']) > now:
            code = item['country_code']['S']
            memo[ip] = code if (code == 'Unknown' or CC_RE.match(code)) else 'Unknown'
            return memo[ip]
    except Exception as exc:
        print(f"cache: erreur lecture ({type(exc).__name__})")

    out_of_budget = (state['calls'] >= MAX_GEOIP_CALLS
                     or context.get_remaining_time_in_millis() < MIN_REMAINING_MS)
    if out_of_budget:
        memo[ip] = 'Unknown'          # non memorise en base : sera retente plus tard
        return 'Unknown'

    state['calls'] += 1
    code = _fetch_country_code(ip)
    ttl = GEOIP_TTL_SECONDS if code else UNKNOWN_TTL_SECONDS
    try:
        ddb.put_item(TableName=CACHE_TABLE, Item={
            'ip': key['ip'],
            'country_code': {'S': code or 'Unknown'},
            'expires_at': {'N': str(now + ttl)},
        })
    except Exception as exc:
        print(f"cache: erreur ecriture ({type(exc).__name__})")
    memo[ip] = code or 'Unknown'
    return memo[ip]


def _backoff(attempt):
    time.sleep(min(0.05 * (2 ** attempt), 1.0) + random.random() * 0.05)


def commit_chunk(marker_id, items):
    """Une transaction : marqueur de lot (Put conditionnel) + ADD par cle.
    Retourne 'done' ou 'duplicate' (lot deja traite)."""
    now = int(time.time())
    tx = [{'Put': {
        'TableName': BATCHES_TABLE,
        'Item': {'pk': {'S': marker_id},
                 'expires_at': {'N': str(now + BATCH_MARKER_TTL_SECONDS)}},
        'ConditionExpression': 'attribute_not_exists(pk)',
    }}]
    for key, n in items:
        tx.append({'Update': {
            'TableName': STATS_TABLE,
            'Key': {'pk': {'S': key}},
            'UpdateExpression': 'ADD #c :n',
            'ExpressionAttributeNames': {'#c': 'count'},
            'ExpressionAttributeValues': {':n': {'N': str(n)}},
        }})
    retryable_reasons = {'TransactionConflict', 'ThrottlingError', 'ProvisionedThroughputExceeded'}
    retryable_codes = {'TransactionInProgressException', 'ThrottlingException',
                       'ProvisionedThroughputExceededException', 'InternalServerError',
                       'RequestLimitExceeded'}
    for attempt in range(6):
        try:
            ddb.transact_write_items(TransactItems=tx)
            return 'done'
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'TransactionCanceledException':
                reasons = [r.get('Code') for r in exc.response.get('CancellationReasons', [])]
                if reasons and reasons[0] == 'ConditionalCheckFailed':
                    return 'duplicate'               # lot deja traite : succes
                if any(r in retryable_reasons for r in reasons):
                    _backoff(attempt)                # deux processors sur la meme cle
                    continue
                raise
            if code in retryable_codes:
                _backoff(attempt)
                continue
            raise
    raise RuntimeError('transaction: trop de conflits')


def lambda_handler(event, context):
    raw = gzip.decompress(base64.b64decode(event['awslogs']['data']))
    payload = json.loads(raw)
    if payload.get('messageType') != 'DATA_MESSAGE':
        return {'statusCode': 200, 'body': 'ignore'}

    batch_id = hashlib.sha256(raw).hexdigest()       # deterministe : meme payload, meme id
    memo, state = {}, {'calls': 0}
    events = []
    for entry in payload.get('logEvents', []):
        ev = parse_line(entry.get('message'), entry.get('timestamp'))
        if ev:
            ev['country'] = lookup_country(ev['src_ip'], memo, state, context)
            events.append(ev)

    if not events:
        print(f"lot {batch_id[:8]} : aucun evenement")
        return {'statusCode': 200, 'body': 'vide'}

    # Objet S3 : cle derivee du batch_id -> reecriture idempotente en cas de retry.
    s3.put_object(
        Bucket=PROCESSED_BUCKET,
        Key=f"events/{batch_id}.json",
        Body='\n'.join(json.dumps(e, separators=(',', ':')) for e in events).encode('utf-8'),
        ContentType='application/json',
    )

    counts = Counter()
    for ev in events:
        counts['COUNTRY#' + ev['country']] += 1
        counts['DATE#' + ev['event_date']] += 1
        if ev['event'] == 'command':
            counts['CMD#' + ev['command']] += 1

    # Limite DynamoDB : 100 elements/transaction (marqueur inclus). Chaque
    # morceau a son propre marqueur -> rejeu idempotent morceau par morceau.
    keys = sorted(counts)
    size = MAX_TX_ITEMS - 1
    done = dup = 0
    for i in range(0, len(keys), size):
        chunk = [(k, counts[k]) for k in keys[i:i + size]]
        if commit_chunk(f"{batch_id}#{i // size}", chunk) == 'done':
            done += 1
        else:
            dup += 1
    print(f"lot {batch_id[:8]} : {len(events)} evenements, {len(keys)} cles, "
          f"{done} transaction(s) appliquee(s), {dup} deja traitee(s)")
    return {'statusCode': 200, 'body': 'OK'}
EOF
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "processor" {
  function_name    = "honeypot-processor"
  role             = aws_iam_role.lambda_processor_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30 # court, pour libérer vite les exécutions
  memory_size      = 128
  filename         = data.archive_file.processor_zip.output_path
  source_code_hash = data.archive_file.processor_zip.output_base64sha256

  depends_on = [
    aws_cloudwatch_log_group.lambda_processor_logs,
    aws_iam_role_policy.lambda_processor_policy,
  ]

  environment {
    variables = {
      PROCESSED_BUCKET  = aws_s3_bucket.processed_logs_bucket.id
      STATS_TABLE       = aws_dynamodb_table.honeypot_stats.name
      BATCHES_TABLE     = aws_dynamodb_table.honeypot_batches.name
      CACHE_TABLE       = aws_dynamodb_table.geoip_cache.name
      GEOIP_API_URL     = var.processor_geoip_api_url
      GEOIP_TTL_SECONDS = tostring(var.processor_geoip_ttl_seconds)
    }
  }
}

resource "aws_lambda_permission" "allow_cloudwatch_logs_processor" {
  statement_id  = "AllowExecutionFromCloudWatchLogsProcessor"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.processor.function_name
  principal     = "logs.eu-west-3.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.cowrie_log_group.arn}:*"
}

resource "aws_cloudwatch_log_subscription_filter" "cowrie_to_processor" {
  name            = "cowrie-logs-to-processor"
  log_group_name  = aws_cloudwatch_log_group.cowrie_log_group.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.processor.arn

  depends_on = [aws_lambda_permission.allow_cloudwatch_logs_processor]
}

# Table Glue des événements normalisés (une ligne JSON par événement).
resource "aws_glue_catalog_table" "cowrie_processed_table" {
  name          = "cowrie_processed_events"
  database_name = aws_glue_catalog_database.honeypot_db.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    classification = "json"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.processed_logs_bucket.id}/events/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "cowrie-processed-json-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "ignore.malformed.json" = "true"
      }
    }

    columns {
      name = "event_date"
      type = "string"
    }
    columns {
      name = "ts"
      type = "string"
    }
    columns {
      name = "src_ip"
      type = "string"
    }
    columns {
      name = "session"
      type = "string"
    }
    columns {
      name = "event"
      type = "string"
    }
    columns {
      name = "country"
      type = "string"
    }
    columns {
      name = "command"
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
  }
}

# ==============================================================================
# ATHENA (REQUÊTES MANUELLES)
# ==============================================================================
# Rien n'est planifié : ces requêtes se lancent à la main, la carte n'en a pas besoin.

resource "aws_glue_catalog_database" "honeypot_db" {
  name = "honeypot_analytics_db"
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
    SELECT src_ip, COUNT(*) AS nb_evenements
    FROM cowrie_processed_events
    GROUP BY src_ip
    ORDER BY nb_evenements DESC
    LIMIT 10;
  SQL
}

resource "aws_athena_named_query" "attacks_by_country" {
  name      = "attacks-by-country"
  database  = aws_glue_catalog_database.honeypot_db.name
  workgroup = aws_athena_workgroup.honeypot_wg.id

  query = <<-SQL
    SELECT country AS pays, COUNT(*) AS nb_evenements
    FROM cowrie_processed_events
    GROUP BY country
    ORDER BY nb_evenements DESC;
  SQL
}

resource "aws_athena_named_query" "top_credentials" {
  name      = "top-credentials-testes"
  database  = aws_glue_catalog_database.honeypot_db.name
  workgroup = aws_athena_workgroup.honeypot_wg.id

  query = <<-SQL
    SELECT username, password, COUNT(*) AS nb_tentatives
    FROM cowrie_processed_events
    WHERE event = 'login_failed'
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
    SELECT command, COUNT(*) AS nb_occurrences
    FROM cowrie_processed_events
    WHERE event = 'command'
    GROUP BY command
    ORDER BY nb_occurrences DESC
    LIMIT 10;
  SQL
}

# ==============================================================================
# CARTE (S3 + CLOUDFRONT)
# ==============================================================================
# Une page statique qui relit data.json toutes les 60 secondes. Le visiteur
# ne reçoit jamais de credentials AWS.

# Bucket privé : seul CloudFront peut le lire (Origin Access Control).
resource "aws_s3_bucket" "map_site_bucket" {
  bucket        = "attack-map-${random_id.bucket_suffix.hex}"
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

resource "aws_s3_object" "map_index_html" {
  bucket       = aws_s3_bucket.map_site_bucket.id
  key          = "index.html"
  source       = "${path.module}/map/index.html"
  content_type = "text/html"
  etag         = filemd5("${path.module}/map/index.html")
}

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

    # La page change rarement : cache court.
    min_ttl     = 0
    default_ttl = 60
    max_ttl     = 300
  }

  # data.json n'est jamais mis en cache par CloudFront : sinon la carte pourrait
  # afficher des données vieilles de plusieurs minutes. Le no-store du
  # navigateur ne suffit pas, il ne concerne pas le cache de CloudFront.
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

  # Certificat par défaut (*.cloudfront.net) : pas de domaine personnalisé.
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

# ==============================================================================
# LAMBDA PUBLISHER
# ==============================================================================
# Chaque minute, lit les compteurs et réécrit data.json (Country, Date,
# Command, generated_at). Elle ne peut écrire que data.json : même compromise,
# elle ne pourrait pas modifier index.html.

resource "aws_iam_role" "lambda_publisher_role" {
  name = "lambda-honeypot-publisher-role"

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

resource "aws_iam_role_policy" "lambda_publisher_policy" {
  name = "lambda-honeypot-publisher-policy"
  role = aws_iam_role.lambda_publisher_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.lambda_publisher_logs.arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:Scan"]
        Resource = aws_dynamodb_table.honeypot_stats.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.map_site_bucket.arn}/data.json"
      }
    ]
  })
}

data "archive_file" "publisher_zip" {
  type        = "zip"
  output_path = "${path.module}/publisher_function.zip"

  source {
    content  = <<EOF
import json
import os
import re
from datetime import datetime, timedelta, timezone

import boto3

STATS_TABLE = os.environ.get('STATS_TABLE', '')
MAP_BUCKET = os.environ.get('MAP_BUCKET', '')
DATA_KEY = 'data.json'          # seul objet que cette Lambda a le droit d'ecrire

TOP_COMMANDS = 10
DATE_WINDOW_DAYS = 30           # nombre de jours affiches dans "Date"
MAX_LABEL_LEN = 64              # troncature des libelles de commande

CC_RE = re.compile(r'^[A-Z]{2}$')
DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')

ddb = boto3.client('dynamodb')
s3 = boto3.client('s3')


def scan_all():
    """Lit toute la table honeypot-stats (quelques centaines de cles au plus :
    pays, jours et commandes de la liste blanche)."""
    items, start_key = [], None
    while True:
        kwargs = {
            'TableName': STATS_TABLE,
            'ProjectionExpression': 'pk, #c',
            'ExpressionAttributeNames': {'#c': 'count'},
        }
        if start_key:
            kwargs['ExclusiveStartKey'] = start_key
        resp = ddb.scan(**kwargs)
        items.extend(resp.get('Items', []))
        start_key = resp.get('LastEvaluatedKey')
        if not start_key:
            return items


def _count(item):
    try:
        n = int(item['count']['N'])
    except (KeyError, ValueError, TypeError):
        return 0
    return n if n > 0 else 0


def _valid_date(s):
    if not DATE_RE.match(s):
        return False
    try:
        datetime.strptime(s, '%Y-%m-%d')
        return True
    except ValueError:
        return False


def build_payload(items, now=None):
    """Compteurs DynamoDB -> contenu de data.json. Format :
    {generated_at, total, since, Country:[{code,count}], Date:[{date,count}],
     Command:[{command,count}]}.
    Les libelles de commande sont conserves tels quels (tronques) : c'est le
    navigateur qui doit les afficher en texte brut (textContent), jamais en HTML."""
    now = now or datetime.now(timezone.utc)
    countries, dates, commands = {}, {}, {}
    for item in items:
        pk = item.get('pk', {}).get('S', '')
        n = _count(item)
        if not n or '#' not in pk:
            continue
        kind, _, value = pk.partition('#')
        if kind == 'COUNTRY' and (CC_RE.match(value) or value == 'Unknown'):
            countries[value] = n
        elif kind == 'DATE' and _valid_date(value):
            dates[value] = n
        elif kind == 'CMD' and value:
            commands[value[:MAX_LABEL_LEN]] = commands.get(value[:MAX_LABEL_LEN], 0) + n

    first_day = (now - timedelta(days=DATE_WINDOW_DAYS - 1)).strftime('%Y-%m-%d')
    recent = sorted((d, c) for d, c in dates.items() if d >= first_day)
    top_cmds = sorted(commands.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_COMMANDS]
    top_countries = sorted(countries.items(), key=lambda kv: (-kv[1], kv[0]))

    return {
        'generated_at': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'total': sum(countries.values()),
        'since': min(dates) if dates else None,
        'Country': [{'code': k, 'count': v} for k, v in top_countries],
        'Date': [{'date': d, 'count': c} for d, c in recent],
        'Command': [{'command': k, 'count': v} for k, v in top_cmds],
    }


def lambda_handler(event, context):
    payload = build_payload(scan_all())
    body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    s3.put_object(
        Bucket=MAP_BUCKET,
        Key=DATA_KEY,
        Body=body,
        ContentType='application/json',
        CacheControl='no-store',
    )
    print(f"data.json : {len(payload['Country'])} pays, {len(payload['Command'])} commandes, "
          f"total {payload['total']}, {len(body)} octets")
    return {'statusCode': 200, 'body': 'OK'}
EOF
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "publisher" {
  function_name    = "honeypot-publisher"
  role             = aws_iam_role.lambda_publisher_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 20
  memory_size      = 128
  filename         = data.archive_file.publisher_zip.output_path
  source_code_hash = data.archive_file.publisher_zip.output_base64sha256

  depends_on = [
    aws_cloudwatch_log_group.lambda_publisher_logs,
    aws_iam_role_policy.lambda_publisher_policy,
  ]

  environment {
    variables = {
      STATS_TABLE = aws_dynamodb_table.honeypot_stats.name
      MAP_BUCKET  = aws_s3_bucket.map_site_bucket.id
    }
  }
}

# Planification : une exécution par minute.
resource "aws_cloudwatch_event_rule" "publisher_schedule" {
  name                = "honeypot-publisher-refresh"
  schedule_expression = "rate(1 minute)"
}

resource "aws_cloudwatch_event_target" "publisher_schedule_target" {
  rule      = aws_cloudwatch_event_rule.publisher_schedule.name
  target_id = "publisher"
  arn       = aws_lambda_function.publisher.arn
}

resource "aws_lambda_permission" "allow_eventbridge_publisher" {
  statement_id  = "AllowExecutionFromEventBridgePublisher"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.publisher.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.publisher_schedule.arn
}

# ==============================================================================
# SUPERVISION ET GUARDDUTY
# ==============================================================================
# Un dashboard, des alarmes et GuardDuty. Toutes les alertes partent vers le
# topic honeypot-alerts. Les alarmes ignorent l'absence de données
# (notBreaching) : sans trafic, il n'y a rien à mesurer.

locals {
  # Défini ici car le dashboard et la Lambda du kill switch l'utilisent tous les deux.
  kill_switch_function_name = "honeypot-kill-switch"
}

variable "cowrie_log_alarm_bytes_per_hour" {
  description = "Seuil de l'alarme de volume de logs Cowrie : octets ingérés par heure dans /aws/ec2/cowrie (10485760 = 10 Mio/h). Première estimation, à recalibrer après quelques jours en production."
  type        = number
  default     = 10485760
}

variable "guardduty_notify_min_severity" {
  description = "Sévérité GuardDuty minimale pour recevoir un email (0 = tous les findings, 4 = moyenne et plus). Utile si le volume d'emails devient excessif une fois le honeypot ouvert."
  type        = number
  default     = 0

  validation {
    condition     = var.guardduty_notify_min_severity >= 0 && var.guardduty_notify_min_severity <= 10
    error_message = "guardduty_notify_min_severity doit être compris entre 0 et 10."
  }
}

# ---- Alarme : volume de logs Cowrie (dérive de coût ou attaque massive) ----
resource "aws_cloudwatch_metric_alarm" "cowrie_log_volume" {
  alarm_name          = "honeypot-cowrie-log-volume-high"
  alarm_description   = "Volume de logs Cowrie ingere sur 1 heure superieur au seuil (derive de cout ou attaque massive)."
  namespace           = "AWS/Logs"
  metric_name         = "IncomingBytes"
  dimensions          = { LogGroupName = aws_cloudwatch_log_group.cowrie_log_group.name }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = var.cowrie_log_alarm_bytes_per_hour
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.honeypot_alerts.arn]
  ok_actions    = [aws_sns_topic.honeypot_alerts.arn]

  depends_on = [aws_sns_topic_policy.honeypot_alerts]
}

# ---- Alarme : erreurs du processor (au moins une sur 5 minutes) ----
resource "aws_cloudwatch_metric_alarm" "processor_errors" {
  alarm_name          = "honeypot-processor-errors"
  alarm_description   = "La Lambda honeypot-processor a echoue au moins une fois sur 5 minutes."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.processor.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.honeypot_alerts.arn]
  ok_actions    = [aws_sns_topic.honeypot_alerts.arn]

  depends_on = [aws_sns_topic_policy.honeypot_alerts]
}

# ---- Dashboard ----
# CloudFront publie ses métriques en us-east-1 : ses widgets lisent cette région.
resource "aws_cloudwatch_dashboard" "honeypot" {
  dashboard_name = "honeypot"

  dashboard_body = jsonencode({
    widgets = [
      # ---- Ligne 1 : Lambda processor ----
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Processor : invocations, erreurs, throttles"
          region = "eu-west-3"
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.processor.function_name],
            ["AWS/Lambda", "Errors", "FunctionName", aws_lambda_function.processor.function_name],
            ["AWS/Lambda", "Throttles", "FunctionName", aws_lambda_function.processor.function_name],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Processor : durée (ms)"
          region = "eu-west-3"
          view   = "timeSeries"
          period = 300
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.processor.function_name, { stat = "Average" }],
            ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.processor.function_name, { stat = "Maximum" }],
          ]
          annotations = {
            horizontal = [{ label = "Timeout", value = aws_lambda_function.processor.timeout * 1000 }]
          }
        }
      },
      # ---- Ligne 2 : publisher, kill switch, volume de logs ----
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "Publisher : invocations, erreurs"
          region = "eu-west-3"
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.publisher.function_name],
            ["AWS/Lambda", "Errors", "FunctionName", aws_lambda_function.publisher.function_name],
          ]
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "Kill switch : invocations, erreurs, throttles"
          region = "eu-west-3"
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", local.kill_switch_function_name],
            ["AWS/Lambda", "Errors", "FunctionName", local.kill_switch_function_name],
            ["AWS/Lambda", "Throttles", "FunctionName", local.kill_switch_function_name],
          ]
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "Logs Cowrie : octets ingérés"
          region = "eu-west-3"
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/Logs", "IncomingBytes", "LogGroupName", aws_cloudwatch_log_group.cowrie_log_group.name],
          ]
        }
      },
      # ---- Ligne 3 : DynamoDB honeypot-stats ----
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "DynamoDB honeypot-stats : unités d'écriture consommées"
          region = "eu-west-3"
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/DynamoDB", "ConsumedWriteCapacityUnits", "TableName", aws_dynamodb_table.honeypot_stats.name],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "DynamoDB honeypot-stats : requêtes throttlées (TransactWriteItems)"
          region = "eu-west-3"
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/DynamoDB", "ThrottledRequests", "TableName", aws_dynamodb_table.honeypot_stats.name, "Operation", "TransactWriteItems"],
          ]
        }
      },
      # ---- Ligne 4 : EC2 ----
      {
        type   = "metric"
        x      = 0
        y      = 18
        width  = 8
        height = 6
        properties = {
          title  = "EC2 : CPU (%)"
          region = "eu-west-3"
          view   = "timeSeries"
          stat   = "Average"
          period = 300
          metrics = [
            ["AWS/EC2", "CPUUtilization", "InstanceId", aws_instance.honeypot_ec2.id],
          ]
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 18
        width  = 8
        height = 6
        properties = {
          title  = "EC2 : trafic sortant (octets)"
          region = "eu-west-3"
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/EC2", "NetworkOut", "InstanceId", aws_instance.honeypot_ec2.id],
          ]
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 18
        width  = 8
        height = 6
        properties = {
          title  = "EC2 : échecs de status check"
          region = "eu-west-3"
          view   = "timeSeries"
          stat   = "Maximum"
          period = 300
          metrics = [
            ["AWS/EC2", "StatusCheckFailed", "InstanceId", aws_instance.honeypot_ec2.id],
          ]
        }
      },
      # ---- Ligne 5 : CloudFront (métriques en us-east-1) ----
      {
        type   = "metric"
        x      = 0
        y      = 24
        width  = 12
        height = 6
        properties = {
          title  = "CloudFront : requêtes"
          region = "us-east-1"
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/CloudFront", "Requests", "DistributionId", aws_cloudfront_distribution.map_cdn.id, "Region", "Global"],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 24
        width  = 12
        height = 6
        properties = {
          title  = "CloudFront : octets téléchargés"
          region = "us-east-1"
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/CloudFront", "BytesDownloaded", "DistributionId", aws_cloudfront_distribution.map_cdn.id, "Region", "Global"],
          ]
        }
      },
    ]
  })
}

# ---- GuardDuty ----
# Un seul détecteur par compte et par région : s'il existe déjà, l'importer.
# Nécessite un compte en plan payant. FIFTEEN_MINUTES ne concerne que les mises
# à jour d'un finding : un nouveau finding part tout de suite.
resource "aws_guardduty_detector" "honeypot" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = {
    Name = "GuardDuty-Honeypot"
  }
}

# ---- Tous les findings GuardDuty par email ----
# Aucune action automatique ici. Sert aussi de filet si le kill switch échoue.
resource "aws_cloudwatch_event_rule" "guardduty_findings_to_sns" {
  name        = "honeypot-guardduty-findings-to-sns"
  description = "Tous les findings GuardDuty vers le topic SNS honeypot-alerts (notification seulement)."

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.guardduty_notify_min_severity] }]
    }
  })
}

# Message lisible plutôt que le JSON brut, construit uniquement avec des champs
# présents dans tous les findings.
resource "aws_cloudwatch_event_target" "guardduty_findings_to_sns_target" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings_to_sns.name
  target_id = "sns-alerts"
  arn       = aws_sns_topic.honeypot_alerts.arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      type        = "$.detail.type"
      title       = "$.detail.title"
      description = "$.detail.description"
      region      = "$.detail.region"
      resource    = "$.detail.resource.resourceType"
      id          = "$.detail.id"
      time        = "$.time"
    }
    input_template = "\"GuardDuty (severite <severity>) : <type>\\n\\n<title>\\n<description>\\n\\nRessource : <resource>\\nDate : <time>\\nFinding : https://<region>.console.aws.amazon.com/guardduty/home?region=<region>#/findings?search=id%3D<id>\""
  }

  depends_on = [aws_sns_topic_policy.honeypot_alerts]
}

# ==============================================================================
# KILL SWITCH
# ==============================================================================
# Met l'instance en quarantaine, dans cet ordre, chaque étape étant
# indépendante et signalée par email : tag Quarantine -> refus dans le NACL
# (règles 1 et 2) -> security group vide -> policy Deny * sur le rôle ->
# snapshots -> preuve JSON dans S3 -> arrêt de l'instance (jamais suppression).
#
# À savoir :
# - Terraform crée la policy Deny * mais ne l'attache jamais.
# - Les règles NACL 1 et 2 sont posées par la Lambda, pas par Terraform.
# - Aucun terraform apply pendant un incident : il remettrait le security group
#   d'origine et effacerait le tag de quarantaine.
# - Remise en service : voir le runbook de restauration.

variable "kill_switch_dry_run" {
  description = "false = le kill switch agit réellement (par défaut). true = simulation : appels EC2 en DryRun, sans attachement IAM ni écriture S3."
  type        = bool
  default     = false
}

variable "evidence_retention_days" {
  description = "Durée de conservation des preuves (finding JSON) dans le bucket evidences-*, en jours."
  type        = number
  default     = 90

  validation {
    condition     = var.evidence_retention_days >= 1
    error_message = "evidence_retention_days doit être supérieur ou égal à 1."
  }
}

variable "snapshot_retention_days" {
  description = "Valeur du tag DeleteAfter posé sur les snapshots (simple rappel : la suppression des snapshots reste manuelle)."
  type        = number
  default     = 30
}

# ---- Security group de quarantaine : aucune règle ----
# Terraform retire la règle de sortie créée par défaut. Un security group garde
# l'état des connexions : le refus dans le NACL coupe aussi celles déjà établies.
resource "aws_security_group" "quarantine_sg" {
  name        = "honeypot-quarantine-sg"
  description = "Quarantaine : aucune regle entrante ni sortante"
  vpc_id      = aws_vpc.honeypot_vpc.id

  tags = {
    Name = "SG-Honeypot-Quarantine"
  }
}

# ---- Policy Deny * ----
# Attachée au rôle de l'instance par le kill switch seulement. Un Deny l'emporte
# sur tout Allow : des credentials volés deviennent inutiles.
resource "aws_iam_policy" "quarantine_deny_all" {
  name        = "honeypot-quarantine-deny-all"
  description = "Deny * : attachee au role EC2 uniquement par le kill switch"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyEverything"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# ---- Bucket de preuves ----
# Un terraform destroy ne doit pas effacer des preuves.
resource "aws_s3_bucket" "evidences_bucket" {
  bucket        = "evidences-${random_id.bucket_suffix.hex}"
  force_destroy = false

  tags = {
    Name = "S3-Honeypot-Evidences"
  }
}

resource "aws_s3_bucket_public_access_block" "evidences_bucket_pab" {
  bucket                  = aws_s3_bucket.evidences_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidences_bucket_sse" {
  bucket = aws_s3_bucket.evidences_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidences_bucket_lifecycle" {
  bucket = aws_s3_bucket.evidences_bucket.id

  rule {
    id     = "expire-evidences"
    status = "Enabled"

    filter {}

    expiration {
      days = var.evidence_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Refuse tout accès en HTTP simple.
resource "aws_s3_bucket_policy" "evidences_bucket_policy" {
  bucket = aws_s3_bucket.evidences_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.evidences_bucket.arn,
          "${aws_s3_bucket.evidences_bucket.arn}/*"
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.evidences_bucket_pab]
}

# ---- Rôle du kill switch ----
# La Lambda est hors du VPC : elle reste joignable même si le réseau du honeypot
# est coupé.
resource "aws_iam_role" "lambda_kill_switch_role" {
  name = "lambda-honeypot-kill-switch-role"

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

resource "aws_cloudwatch_log_group" "lambda_kill_switch_logs" {
  name              = "/aws/lambda/${local.kill_switch_function_name}"
  retention_in_days = 14

  tags = {
    Name = "CloudWatch-Lambda-KillSwitch-Logs"
  }
}

resource "aws_iam_role_policy" "lambda_kill_switch_policy" {
  name = "lambda-honeypot-kill-switch-policy"
  role = aws_iam_role.lambda_kill_switch_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Logs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.lambda_kill_switch_logs.arn}:*"
      },
      {
        # Lecture seule : les Describe* d'EC2 ne supportent pas de ressource précise.
        Sid      = "DescribeEc2"
        Effect   = "Allow"
        Action   = ["ec2:Describe*"]
        Resource = "*"
      },
      {
        Sid      = "NaclDenyEntries"
        Effect   = "Allow"
        Action   = ["ec2:CreateNetworkAclEntry", "ec2:ReplaceNetworkAclEntry"]
        Resource = "arn:aws:ec2:eu-west-3:${data.aws_caller_identity.current.account_id}:network-acl/${aws_network_acl.honeypot_nacl.id}"
      },
      {
        # Uniquement l'interface réseau du honeypot et le SG de quarantaine.
        Sid    = "SwapSecurityGroup"
        Effect = "Allow"
        Action = ["ec2:ModifyNetworkInterfaceAttribute"]
        Resource = [
          "arn:aws:ec2:eu-west-3:${data.aws_caller_identity.current.account_id}:network-interface/${aws_instance.honeypot_ec2.primary_network_interface_id}",
          aws_security_group.quarantine_sg.arn
        ]
      },
      {
        Sid    = "Snapshots"
        Effect = "Allow"
        Action = ["ec2:CreateSnapshots"]
        Resource = [
          "arn:aws:ec2:eu-west-3:${data.aws_caller_identity.current.account_id}:instance/${aws_instance.honeypot_ec2.id}",
          "arn:aws:ec2:eu-west-3:${data.aws_caller_identity.current.account_id}:volume/*",
          "arn:aws:ec2:eu-west-3::snapshot/*"
        ]
      },
      {
        # Tags des snapshots : seulement au moment de leur création par CreateSnapshots.
        Sid       = "TagSnapshotsAtCreation"
        Effect    = "Allow"
        Action    = ["ec2:CreateTags"]
        Resource  = "arn:aws:ec2:eu-west-3::snapshot/*"
        Condition = { StringEquals = { "ec2:CreateAction" = "CreateSnapshots" } }
      },
      {
        # Tag de quarantaine : cette instance uniquement, et ces deux clés seulement.
        Sid       = "TagInstanceQuarantine"
        Effect    = "Allow"
        Action    = ["ec2:CreateTags"]
        Resource  = "arn:aws:ec2:eu-west-3:${data.aws_caller_identity.current.account_id}:instance/${aws_instance.honeypot_ec2.id}"
        Condition = { "ForAllValues:StringEquals" = { "aws:TagKeys" = ["Quarantine", "QuarantineAt"] } }
      },
      {
        # Arrêter, jamais supprimer : pas d'action ec2:TerminateInstances.
        Sid      = "StopHoneypotOnly"
        Effect   = "Allow"
        Action   = ["ec2:StopInstances"]
        Resource = "arn:aws:ec2:eu-west-3:${data.aws_caller_identity.current.account_id}:instance/${aws_instance.honeypot_ec2.id}"
      },
      {
        # Seule la policy Deny peut être attachée, et seulement à ce rôle.
        Sid       = "AttachDenyPolicyOnly"
        Effect    = "Allow"
        Action    = ["iam:AttachRolePolicy"]
        Resource  = aws_iam_role.ec2_cloudwatch_role.arn
        Condition = { ArnEquals = { "iam:PolicyARN" = aws_iam_policy.quarantine_deny_all.arn } }
      },
      {
        Sid      = "WriteEvidence"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.evidences_bucket.arn}/*"
      },
      {
        Sid      = "Notify"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.honeypot_alerts.arn
      }
    ]
  })
}

# ---- Lambda kill switch ----
# Code identique à kill_switch.py, testé par pytest. Pas de "${" ni de "%{"
# dans le Python : Terraform les interpréterait.
data "archive_file" "kill_switch_zip" {
  type        = "zip"
  output_path = "${path.module}/kill_switch_function.zip"

  source {
    content  = <<EOF
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

INSTANCE_ID = os.environ.get('INSTANCE_ID', '')
QUARANTINE_SG_ID = os.environ.get('QUARANTINE_SG_ID', '')
NACL_ID = os.environ.get('NACL_ID', '')
ROLE_NAME = os.environ.get('ROLE_NAME', '')
DENY_POLICY_ARN = os.environ.get('DENY_POLICY_ARN', '')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
EVIDENCE_BUCKET = os.environ.get('EVIDENCE_BUCKET', '')
SNAPSHOT_RETENTION_DAYS = int(os.environ.get('SNAPSHOT_RETENTION_DAYS', '30'))

def parse_dry_run(raw):
    """Securite : tout ce qui n'est pas exactement "false" laisse le mode simulation
    actif. Une variable absente ou mal ecrite ne declenche donc jamais le vrai arret."""
    return str(raw if raw is not None else 'true').strip().lower() != 'false'


DRY_RUN = parse_dry_run(os.environ.get('DRY_RUN'))

NACL_DENY_RULE_V4 = 1
NACL_DENY_RULE_V6 = 2
TAG_KEY = 'Quarantine'

ec2 = boto3.client('ec2')
iam = boto3.client('iam')
s3 = boto3.client('s3')
sns = boto3.client('sns')


# ---------------------------------------------------------------- utilitaires

def _now():
    return datetime.now(timezone.utc)


def _error_code(exc):
    return exc.response.get('Error', {}).get('Code', '')


def _ec2_call(method, **kwargs):
    """Appelle EC2. En mode simulation, ajoute DryRun=True : une reponse
    DryRunOperation signifie que l'appel serait autorise (droits corrects),
    UnauthorizedOperation signifie qu'un droit manque. Retourne (simule, reponse)."""
    if DRY_RUN:
        kwargs['DryRun'] = True
    try:
        resp = getattr(ec2, method)(**kwargs)
    except ClientError as exc:
        if DRY_RUN and _error_code(exc) == 'DryRunOperation':
            return True, None
        raise
    return False, resp


def _label(simulated):
    return 'simulation OK (droits valides)' if simulated else 'fait'


def _ascii(text, limit):
    return str(text).encode('ascii', 'replace').decode('ascii').replace('\n', ' ')[:limit]


def publish(step, ok, detail):
    """Un message SNS par etape. Ne doit jamais interrompre le kill switch."""
    mode = ' (SIMULATION)' if DRY_RUN else ''
    subject = _ascii(f"[KILL-SWITCH]{mode} {step} : {'OK' if ok else 'ECHEC'}", 100)
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=str(detail)[:2000])
    except Exception as exc:
        print(f"sns: echec publication ({type(exc).__name__})")


def safe_incident_id(raw):
    """Identifiant utilisable dans une cle S3 et un tag : [A-Za-z0-9_-], 64 max."""
    cleaned = re.sub(r'[^A-Za-z0-9_-]', '', str(raw or ''))[:64]
    return cleaned or uuid.uuid4().hex[:16]


def finding_instance_id(event):
    try:
        return event['detail']['resource']['instanceDetails']['instanceId']
    except (KeyError, TypeError):
        return None


def is_guardduty_finding(event):
    return isinstance(event, dict) and (
        event.get('detail-type') == 'GuardDuty Finding' or event.get('source') == 'aws.guardduty')


def describe_instance():
    resp = ec2.describe_instances(InstanceIds=[INSTANCE_ID])
    return resp['Reservations'][0]['Instances'][0]


def already_quarantined(instance):
    return any(t.get('Key') == TAG_KEY and t.get('Value') == 'true'
               for t in instance.get('Tags', []))


# --------------------------------------------------------------------- etapes
# Chaque etape recoit un contexte (dict) et retourne un texte de detail.
# Une exception = etape en echec ; les etapes suivantes s'executent quand meme.

def step_tag(ctx):
    simulated, _ = _ec2_call(
        'create_tags', Resources=[INSTANCE_ID],
        Tags=[{'Key': TAG_KEY, 'Value': 'true'}, {'Key': 'QuarantineAt', 'Value': ctx['now_iso']}])
    return f"Tag {TAG_KEY}=true sur {INSTANCE_ID} : {_label(simulated)}"


def _vpc_has_ipv6(vpc_id):
    resp = ec2.describe_vpcs(VpcIds=[vpc_id])
    return bool(resp['Vpcs'][0].get('Ipv6CidrBlockAssociationSet'))


def step_nacl(ctx):
    entries = [(NACL_DENY_RULE_V4, 'CidrBlock', '0.0.0.0/0')]
    note = ''
    try:
        if ctx.get('vpc_id') and _vpc_has_ipv6(ctx['vpc_id']):
            entries.append((NACL_DENY_RULE_V6, 'Ipv6CidrBlock', '::/0'))
        elif not ctx.get('vpc_id'):
            note = ' (VPC inconnu : IPv6 non verifie)'
    except Exception as exc:
        note = f" (verification IPv6 impossible : {type(exc).__name__})"
    done = []
    for number, key, cidr in entries:
        for egress in (False, True):
            params = {'NetworkAclId': NACL_ID, 'RuleNumber': number, 'Protocol': '-1',
                      'RuleAction': 'deny', 'Egress': egress, key: cidr}
            try:
                simulated, _ = _ec2_call('create_network_acl_entry', **params)
            except ClientError as exc:
                if _error_code(exc) != 'NetworkAclEntryAlreadyExists':
                    raise
                simulated, _ = _ec2_call('replace_network_acl_entry', **params)
            done.append(f"{'sortie' if egress else 'entree'} n{number} {cidr}")
    return f"NACL {NACL_ID} : deny {', '.join(done)} : {_label(simulated)}{note}"


def step_security_group(ctx):
    eni = ctx.get('eni_id')
    if not eni:
        raise RuntimeError("interface reseau inconnue (description de l'instance impossible)")
    simulated, _ = _ec2_call('modify_network_interface_attribute',
                             NetworkInterfaceId=eni, Groups=[QUARANTINE_SG_ID])
    return (f"ENI {eni} : groupes {ctx.get('original_sgs')} remplaces par {QUARANTINE_SG_ID} : "
            f"{_label(simulated)}")


def step_deny_policy(ctx):
    if DRY_RUN:
        # IAM n'a pas de DryRun : on ne l'attache pas en simulation.
        return (f"Policy {DENY_POLICY_ARN} NON attachee a {ROLE_NAME} (simulation, IAM n'a pas de "
                f"mode DryRun ; droit a verifier avec simulate-principal-policy)")
    iam.attach_role_policy(RoleName=ROLE_NAME, PolicyArn=DENY_POLICY_ARN)
    return f"Policy Deny attachee a {ROLE_NAME} : fait"


def step_snapshot(ctx):
    delete_after = (_now() + timedelta(days=SNAPSHOT_RETENTION_DAYS)).strftime('%Y-%m-%d')
    simulated, resp = _ec2_call(
        'create_snapshots',
        InstanceSpecification={'InstanceId': INSTANCE_ID, 'ExcludeBootVolume': False},
        Description=f"Kill switch honeypot - incident {ctx['incident_id']}",
        TagSpecifications=[{'ResourceType': 'snapshot', 'Tags': [
            {'Key': 'Incident', 'Value': ctx['incident_id']},
            {'Key': 'IncidentDate', 'Value': ctx['now_iso'][:10]},
            {'Key': 'DeleteAfter', 'Value': delete_after},
            {'Key': 'Source', 'Value': 'honeypot-kill-switch'}]}])
    ids = [s.get('SnapshotId') for s in (resp or {}).get('Snapshots', [])]
    return f"Snapshots {ids or '(aucun en simulation)'} DeleteAfter={delete_after} : {_label(simulated)}"


def step_evidence(ctx):
    key = f"incidents/{ctx['now_iso'][:10]}/{ctx['incident_id']}/finding.json"
    if DRY_RUN:
        return f"Preuve NON ecrite (simulation) : s3://{EVIDENCE_BUCKET}/{key}"
    body = json.dumps({
        'incident_id': ctx['incident_id'],
        'received_at': ctx['now_iso'],
        'instance_id': INSTANCE_ID,
        'security_groups_before': ctx.get('original_sgs'),
        'network_interface': ctx.get('eni_id'),
        'finding': ctx['event'],
    }, default=str).encode('utf-8')
    s3.put_object(Bucket=EVIDENCE_BUCKET, Key=key, Body=body,
                  ContentType='application/json', ServerSideEncryption='AES256')
    return f"Preuve ecrite : s3://{EVIDENCE_BUCKET}/{key}"


def step_stop(ctx):
    # JAMAIS de terminate : on arrete l'instance pour garder le disque.
    simulated, _ = _ec2_call('stop_instances', InstanceIds=[INSTANCE_ID])
    return f"Arret (stop) de {INSTANCE_ID} : {_label(simulated)}"


STEPS = (
    ('1-tag', step_tag),
    ('2-nacl', step_nacl),
    ('3-security-group', step_security_group),
    ('4-deny-policy', step_deny_policy),
    ('5-snapshot', step_snapshot),
    ('6-evidence', step_evidence),
    ('7-stop', step_stop),
)


# ------------------------------------------------------------------- handler

def lambda_handler(event, context):
    # 1) Verification de ciblage : un finding GuardDuty sur une autre instance
    #    (ou sans identifiant d'instance) est ignore, sans aucune action.
    if is_guardduty_finding(event):
        target = finding_instance_id(event)
        if target != INSTANCE_ID:
            print("ignore : finding hors cible")
            return {'statusCode': 200, 'body': 'ignore : hors cible'}

    # 2) Idempotence : si l'instance est deja en quarantaine, on sort.
    ctx = {'event': event, 'now_iso': _now().strftime('%Y-%m-%dT%H:%M:%SZ')}
    detail = event.get('detail') if isinstance(event, dict) else None
    ctx['incident_id'] = safe_incident_id(detail.get('id') if isinstance(detail, dict) else None)
    try:
        instance = describe_instance()
        ctx['vpc_id'] = instance.get('VpcId')
        nics = instance.get('NetworkInterfaces', [])
        if nics:
            ctx['eni_id'] = nics[0].get('NetworkInterfaceId')
            ctx['original_sgs'] = [g.get('GroupId') for g in nics[0].get('Groups', [])]
        if already_quarantined(instance):
            publish('verification', True, f"{INSTANCE_ID} est deja en quarantaine : rien a faire.")
            return {'statusCode': 200, 'body': 'deja en quarantaine'}
    except Exception as exc:
        # On ne bloque pas le kill switch : on poursuit avec ce qui ne depend pas de la description.
        publish('verification', False, f"Description de l'instance impossible ({type(exc).__name__}) : "
                                       f"poursuite des etapes.")

    # 3) Les etapes, chacune dans son propre try/except.
    failed = []
    for name, fn in STEPS:
        try:
            detail = fn(ctx)
            publish(name, True, detail)
        except Exception as exc:
            failed.append(name)
            publish(name, False, f"{type(exc).__name__} : {_ascii(exc, 300)}")
    print(f"incident {ctx['incident_id']} : {len(STEPS) - len(failed)}/{len(STEPS)} etapes OK, "
          f"dry_run={DRY_RUN}")
    if failed:
        # Fait monter la metrique Errors : l'alarme 3 previent par email.
        raise RuntimeError(f"etapes en echec : {', '.join(failed)}")
    return {'statusCode': 200, 'body': 'OK'}
EOF
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "kill_switch" {
  function_name    = local.kill_switch_function_name
  role             = aws_iam_role.lambda_kill_switch_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 128
  filename         = data.archive_file.kill_switch_zip.output_path
  source_code_hash = data.archive_file.kill_switch_zip.output_base64sha256

  depends_on = [
    aws_cloudwatch_log_group.lambda_kill_switch_logs,
    aws_iam_role_policy.lambda_kill_switch_policy,
  ]

  environment {
    variables = {
      INSTANCE_ID             = aws_instance.honeypot_ec2.id
      QUARANTINE_SG_ID        = aws_security_group.quarantine_sg.id
      NACL_ID                 = aws_network_acl.honeypot_nacl.id
      ROLE_NAME               = aws_iam_role.ec2_cloudwatch_role.name
      DENY_POLICY_ARN         = aws_iam_policy.quarantine_deny_all.arn
      SNS_TOPIC_ARN           = aws_sns_topic.honeypot_alerts.arn
      EVIDENCE_BUCKET         = aws_s3_bucket.evidences_bucket.id
      SNAPSHOT_RETENTION_DAYS = tostring(var.snapshot_retention_days)
      DRY_RUN                 = var.kill_switch_dry_run ? "true" : "false"
    }
  }
}

# Pas de nouvelle tentative : la Lambda va déjà au bout de ses étapes, et un
# second passage sortirait tout de suite à cause du tag. Un échec déclenche
# l'alarme des erreurs.
resource "aws_lambda_function_event_invoke_config" "kill_switch" {
  function_name          = aws_lambda_function.kill_switch.function_name
  maximum_retry_attempts = 0
}

# ---- File d'erreurs ----
# Reçoit les événements qu'EventBridge n'a pas pu livrer au kill switch.
# Seules les règles nommées honeypot-killswitch-* peuvent y écrire.
resource "aws_sqs_queue" "kill_switch_dlq" {
  name                      = "honeypot-kill-switch-dlq"
  message_retention_seconds = 1209600 # 14 jours
  sqs_managed_sse_enabled   = true

  tags = {
    Name = "SQS-KillSwitch-DLQ"
  }
}

resource "aws_sqs_queue_policy" "kill_switch_dlq_policy" {
  queue_url = aws_sqs_queue.kill_switch_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowKillSwitchRulesToSend"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.kill_switch_dlq.arn
        Condition = {
          ArnLike = { "aws:SourceArn" = "arn:aws:events:eu-west-3:${data.aws_caller_identity.current.account_id}:rule/honeypot-killswitch-*" }
        }
      }
    ]
  })
}

# ==============================================================================
# DÉCLENCHEURS DU KILL SWITCH
# ==============================================================================
# Deux règles, filtrées sur l'ID de l'instance (la Lambda le revérifie). Le
# honeypot est attaqué en permanence : un finding où il est la cible (TARGET)
# est normal et ne déclenche rien.

variable "kill_switch_rules_enabled" {
  description = "false = les deux règles existent mais ne déclenchent plus rien, sans les détruire."
  type        = bool
  default     = true
}

# L'instance est à l'origine (ACTOR) d'une activité malveillante.
resource "aws_cloudwatch_event_rule" "killswitch_actor" {
  name        = "honeypot-killswitch-actor-activity"
  description = "Finding GuardDuty ou le honeypot est l'ACTEUR (malware, minage, scan, Tor) : declenche le kill switch."
  state       = var.kill_switch_rules_enabled ? "ENABLED" : "DISABLED"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      resource = {
        instanceDetails = { instanceId = [aws_instance.honeypot_ec2.id] }
      }
      service = { resourceRole = ["ACTOR"] }
      type = [
        { prefix = "Backdoor:EC2/" },
        { prefix = "Trojan:EC2/" },
        { prefix = "CryptoCurrency:EC2/" },
        { prefix = "Impact:EC2/" },
        { prefix = "Recon:EC2/Portscan" },
        { prefix = "UnauthorizedAccess:EC2/Tor" },
      ]
    }
  })
}

# Les credentials du rôle de l'instance sont utilisés ailleurs. Pas de filtre
# ACTOR : dans ce finding, la ressource concernée est la clé d'accès.
resource "aws_cloudwatch_event_rule" "killswitch_credential_exfiltration" {
  name        = "honeypot-killswitch-credential-exfiltration"
  description = "Credentials du role de l'instance honeypot utilises depuis l'exterieur : declenche le kill switch."
  state       = var.kill_switch_rules_enabled ? "ENABLED" : "DISABLED"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      resource = {
        instanceDetails = { instanceId = [aws_instance.honeypot_ec2.id] }
      }
      type = [{ prefix = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration" }]
    }
  })
}

# Deux nouvelles tentatives sur une heure au plus, puis la file d'erreurs.
resource "aws_cloudwatch_event_target" "killswitch_actor_target" {
  rule = aws_cloudwatch_event_rule.killswitch_actor.name
  arn  = aws_lambda_function.kill_switch.arn

  retry_policy {
    maximum_retry_attempts       = 2
    maximum_event_age_in_seconds = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.kill_switch_dlq.arn
  }
}

resource "aws_cloudwatch_event_target" "killswitch_credential_exfiltration_target" {
  rule = aws_cloudwatch_event_rule.killswitch_credential_exfiltration.name
  arn  = aws_lambda_function.kill_switch.arn

  retry_policy {
    maximum_retry_attempts       = 2
    maximum_event_age_in_seconds = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.kill_switch_dlq.arn
  }
}

resource "aws_lambda_permission" "allow_eventbridge_killswitch_actor" {
  statement_id  = "AllowEventBridgeKillSwitchActor"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.kill_switch.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.killswitch_actor.arn
}

resource "aws_lambda_permission" "allow_eventbridge_killswitch_exfiltration" {
  statement_id  = "AllowEventBridgeKillSwitchExfiltration"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.kill_switch.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.killswitch_credential_exfiltration.arn
}

# ---- Alarmes du kill switch ----
# Période d'une minute : un échec du kill switch est prioritaire. La Lambda
# termine en erreur dès qu'une étape a échoué.
resource "aws_cloudwatch_metric_alarm" "kill_switch_errors" {
  alarm_name          = "honeypot-kill-switch-errors"
  alarm_description   = "La Lambda kill switch a echoue (au moins une etape en echec)."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.kill_switch.function_name }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.honeypot_alerts.arn]
  ok_actions    = [aws_sns_topic.honeypot_alerts.arn]

  depends_on = [aws_sns_topic_policy.honeypot_alerts]
}

resource "aws_cloudwatch_metric_alarm" "kill_switch_throttles" {
  alarm_name          = "honeypot-kill-switch-throttles"
  alarm_description   = "La Lambda kill switch a ete limitee (throttle) : une invocation n'a pas pu demarrer."
  namespace           = "AWS/Lambda"
  metric_name         = "Throttles"
  dimensions          = { FunctionName = aws_lambda_function.kill_switch.function_name }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.honeypot_alerts.arn]
  ok_actions    = [aws_sns_topic.honeypot_alerts.arn]

  depends_on = [aws_sns_topic_policy.honeypot_alerts]
}

# Un message dans la file d'erreurs : EventBridge n'a pas pu appeler le kill
# switch. SQS publie ses métriques toutes les 5 minutes.
resource "aws_cloudwatch_metric_alarm" "kill_switch_dlq_not_empty" {
  alarm_name          = "honeypot-kill-switch-dlq-not-empty"
  alarm_description   = "Un evenement n'a pas pu etre livre au kill switch (message dans la file d'erreurs)."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.kill_switch_dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.honeypot_alerts.arn]
  ok_actions    = [aws_sns_topic.honeypot_alerts.arn]

  depends_on = [aws_sns_topic_policy.honeypot_alerts]
}

# ==============================================================================
# OUTPUTS
# ==============================================================================

output "guardduty_detector_id" {
  description = "ID du détecteur GuardDuty"
  value       = aws_guardduty_detector.honeypot.id
}

output "monitoring_dashboard_url" {
  description = "Lien vers le dashboard CloudWatch du honeypot"
  value       = "https://eu-west-3.console.aws.amazon.com/cloudwatch/home?region=eu-west-3#dashboards:name=${aws_cloudwatch_dashboard.honeypot.dashboard_name}"
}

output "honeypot_public_ip" {
  description = "IP publique de l'instance honeypot"
  value       = aws_eip.honeypot_eip.public_ip
}

output "geoip_cache_table_name" {
  description = "Nom de la table DynamoDB du cache GeoIP"
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

output "processor_function_name" {
  description = "Nom de la Lambda processor"
  value       = aws_lambda_function.processor.function_name
}

output "processed_logs_bucket_name" {
  description = "Nom du bucket S3 des événements normalisés"
  value       = aws_s3_bucket.processed_logs_bucket.id
}

output "honeypot_stats_table_name" {
  description = "Table DynamoDB des compteurs"
  value       = aws_dynamodb_table.honeypot_stats.name
}

output "publisher_function_name" {
  description = "Nom de la Lambda publisher"
  value       = aws_lambda_function.publisher.function_name
}

output "attack_map_bucket_name" {
  description = "Nom du bucket S3 de la carte (index.html + data.json)"
  value       = aws_s3_bucket.map_site_bucket.id
}

output "sns_alerts_topic_arn" {
  description = "ARN du topic SNS des alertes (email)"
  value       = aws_sns_topic.honeypot_alerts.arn
}

output "ec2_instance_id" {
  description = "ID de l'instance EC2, pour la connexion via SSM"
  value       = aws_instance.honeypot_ec2.id
}

output "attack_map_url" {
  description = "URL HTTPS de la carte des attaques (CloudFront)"
  value       = "https://${aws_cloudfront_distribution.map_cdn.domain_name}"
}

output "killswitch_rule_names" {
  description = "Règles EventBridge qui déclenchent le kill switch"
  value = [
    aws_cloudwatch_event_rule.killswitch_actor.name,
    aws_cloudwatch_event_rule.killswitch_credential_exfiltration.name,
  ]
}

output "kill_switch_function_name" {
  description = "Nom de la Lambda kill switch"
  value       = aws_lambda_function.kill_switch.function_name
}

output "quarantine_sg_id" {
  description = "ID du security group de quarantaine"
  value       = aws_security_group.quarantine_sg.id
}

output "quarantine_deny_policy_arn" {
  description = "ARN de la policy Deny * (jamais attachée par Terraform)"
  value       = aws_iam_policy.quarantine_deny_all.arn
}

output "evidence_bucket_name" {
  description = "Bucket des preuves d'incident"
  value       = aws_s3_bucket.evidences_bucket.id
}

output "kill_switch_dlq_url" {
  description = "URL de la file d'erreurs du kill switch"
  value       = aws_sqs_queue.kill_switch_dlq.id
}

output "honeypot_ec2_role_name" {
  description = "Nom du rôle de l'instance (cible de la policy Deny du kill switch)"
  value       = aws_iam_role.ec2_cloudwatch_role.name
}

output "honeypot_nacl_id" {
  description = "ID du NACL du sous-réseau honeypot"
  value       = aws_network_acl.honeypot_nacl.id
}
