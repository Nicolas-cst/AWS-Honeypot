# Runbook de restauration après quarantaine

À suivre quand le kill switch a mis l'instance honeypot en quarantaine (ou après l'exercice de la phase 8).

> ⛔ **Aucun `terraform apply` pendant l'incident.** Il remettrait le security group d'origine sur l'instance et effacerait les tags de quarantaine, c'est-à-dire qu'il annulerait le kill switch.

Toutes les commandes se lancent depuis `~/honeypot`, dans WSL.

```bash
cd ~/honeypot
export AWS_PROFILE=<ton-profil-non-root> AWS_REGION=eu-west-3
```

## 0. Comprendre avant de restaurer

1. Lis les emails du kill switch : un message par étape, avec l'objet `[KILL-SWITCH] ...`.
2. Récupère la preuve : le JSON du finding est dans le bucket `evidences-*`.
   ```bash
   EVID=$(terraform output -raw evidence_bucket_name)
   aws s3 ls "s3://$EVID/incidents/" --recursive
   aws s3 cp "s3://$EVID/incidents/<date>/<id>/finding.json" - | jq .
   ```
3. Décide : **restaurer** la machine ou **la reconstruire** ?
   - Compromission confirmée ou doute sérieux : ne redémarre pas cette instance. Garde les snapshots pour analyse, puis reconstruis une instance saine (`terraform apply -replace=aws_instance.honeypot_ec2` une fois les étapes 1 à 4 ci-dessous faites, car elles nettoient aussi le réseau et le rôle).
   - Fausse alerte (exercice, finding de test) : continue avec les étapes ci-dessous.

## 1. Retirer la policy Deny du rôle de l'instance

```bash
ROLE=$(terraform output -raw honeypot_ec2_role_name)
DENY=$(terraform output -raw quarantine_deny_policy_arn)
aws iam detach-role-policy --role-name "$ROLE" --policy-arn "$DENY"
aws iam list-attached-role-policies --role-name "$ROLE"   # la policy honeypot-quarantine-deny-all ne doit plus y figurer
```

## 2. Supprimer les règles de deny du NACL

```bash
NACL=$(terraform output -raw honeypot_nacl_id)
aws ec2 delete-network-acl-entry --network-acl-id "$NACL" --ingress --rule-number 1
aws ec2 delete-network-acl-entry --network-acl-id "$NACL" --egress  --rule-number 1
# Seulement si le VPC a de l'IPv6 (ce n'est pas le cas aujourd'hui) :
# aws ec2 delete-network-acl-entry --network-acl-id "$NACL" --ingress --rule-number 2
# aws ec2 delete-network-acl-entry --network-acl-id "$NACL" --egress  --rule-number 2
aws ec2 describe-network-acls --network-acl-ids "$NACL" \
  --query 'NetworkAcls[0].Entries[].[Egress,RuleNumber,RuleAction]' --output table
```
Les règles 100, 110 et la règle 32767 doivent rester ; les n°1 et n°2 ont disparu.

## 3. Remettre le security group d'origine

```bash
INSTANCE=$(terraform output -raw ec2_instance_id)
ENI=$(aws ec2 describe-instances --instance-ids "$INSTANCE" \
  --query 'Reservations[0].Instances[0].NetworkInterfaces[0].NetworkInterfaceId' --output text)
SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=honeypot-sg \
  --query 'SecurityGroups[0].GroupId' --output text)
aws ec2 modify-network-interface-attribute --network-interface-id "$ENI" --groups "$SG"
```
Le groupe d'origine est aussi indiqué dans le finding de la preuve (`security_groups_before`).

## 4. Retirer les tags de quarantaine

```bash
aws ec2 delete-tags --resources "$INSTANCE" --tags Key=Quarantine Key=QuarantineAt
```
Sans cette étape, un nouveau déclenchement du kill switch sortirait aussitôt (« déjà en quarantaine »).

## 5. Redémarrer et vérifier

```bash
aws ec2 start-instances --instance-ids "$INSTANCE"
aws ec2 wait instance-running --instance-ids "$INSTANCE"
aws ssm start-session --target "$INSTANCE"      # attendre 1 à 2 minutes si l'agent SSM n'est pas encore prêt
```
Dans la session SSM :
```bash
sudo systemctl status cowrie honeypot-iptables
sudo journalctl -u cowrie -n 30     # chercher EGRESS-TEST : le test de sortie doit réussir
```
Puis vérifie dans CloudWatch que des logs Cowrie arrivent à nouveau (`aws logs tail /aws/ec2/cowrie --since 10m`).

## 6. Nettoyer les snapshots (manuel)

Le tag `DeleteAfter` n'est qu'un rappel : rien ne les supprime tout seul.

```bash
aws ec2 describe-snapshots --owner-ids self \
  --filters Name=tag:Source,Values=honeypot-kill-switch \
  --query 'Snapshots[].[SnapshotId,StartTime,Tags[?Key==`Incident`]|[0].Value,Tags[?Key==`DeleteAfter`]|[0].Value]' \
  --output table
aws ec2 delete-snapshot --snapshot-id <snap-...>     # quand la date DeleteAfter est dépassée
```
Les preuves du bucket `evidences-*` expirent seules après `evidence_retention_days` (90 jours par défaut).

## 7. Contrôle final

```bash
terraform plan      # attendu : "No changes."
```
Si le plan montre encore une différence sur l'instance (tags) ou le SG de l'interface, c'est qu'une étape 3 ou 4 est incomplète.
