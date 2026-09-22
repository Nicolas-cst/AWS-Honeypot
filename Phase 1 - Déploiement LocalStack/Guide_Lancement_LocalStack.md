# Guide de lancement du projet en local
 
Ce guide couvre le déroulé complet pour tester l'infrastructure sur
LocalStack : démarrage du conteneur, déploiement Terraform, génération de
logs de test, et vérification des résultats à chaque étage du pipeline.
 
---
 
## 1. Lancer LocalStack
 
Avant toute chose, il faut créer un compte Localstack et renseigner son token dansla variable d'environnement suivante : 

```powershell
  $env:LOCALSTACK_AUTH_TOKEN = "token"
```

```powershell
docker rm -f localstack
docker run -d --name localstack `
  -p 4566:4566 -p 4510-4559:4510-4559 `
  -e LOCALSTACK_AUTH_TOKEN=$env:LOCALSTACK_AUTH_TOKEN `
  -v /var/run/docker.sock:/var/run/docker.sock `
  localstack/localstack
```

Le montage du socket Docker (`-v /var/run/docker.sock:...`) est
indispensable : c'est ce qui permet à LocalStack d'émuler Lambda en
lançant de vrais conteneurs pour exécuter le code.
 
## 2. Déployer l'infrastructure
 
```powershell
terraform init
terraform apply --auto-approve
```
 
## 3. Générer des logs de test
 
```powershell
python .\log_generator.py
```
 
Le script envoie des logs simulés directement dans CloudWatch, qui
déclenche la Lambda d'enrichissement.
 
## 4. Vérifier les résultats
 
**Lister les buckets :**
```powershell
awslocal s3 ls
```
 
**Lister les fichiers d'un bucket :**
```powershell
awslocal s3 ls s3://honeypot-enriched-logs --recursive
```
 
## 5. Nettoyer / inspecter l'état
 
```powershell
terraform state list      # liste ce qui a été créé
terraform destroy         # supprime toutes les ressources de test
```