# SealGood - Signature et horodatage de documents

SealGood est un script Bash permettant de signer et d'horodater des documents
(PDF, XML, HTML, etc.) de manière non intrusive en utilisant OpenSSL et des
services TSA (Time Stamp Authority).

## Fonctionnalités principales

-  **Signature numérique** avec clés Ed25519 protégées par mot de passe
- ⏱ **Horodatage** via le service gratuit FreeTSA
-  **Préservation** du format original des documents
-  **Vérification** complète des signatures et horodatages
-  **Transparence** - Toutes les étapes sont reproductibles manuellement
-  **Traitement par lot** des fichiers

## Cas d'utilisation

- Preuve d'intégrité et d'antériorité de documents
- Signature électronique simple et vérifiable
- Archivage de documents avec preuve temporelle

## Prérequis

- Bash 4+
- OpenSSL
- Awk
- Base64
- cURL (pour l'horodatage)

## Installation

1. Copiez le script dans un fichier nommé `sealgood`
2. Rendez-le exécutable :
   ```bash
   chmod +x sealgood

# SealGood - *The 100% DIY Document Authenticator*  

> **No servers. No subscriptions. No bullshit.**  
> Just cryptographic truth in filenames and files.  

### Philosophy  
- 🔥 **Single-file script** (~ 900 lines of Bash)  
- 🧱 **Zero dependencies** (just `openssl` and your OS)  

### How It Stays Pure  
1. Rejects PKI complexity  
2. Never phones home  
3. Your keys = your property (generated locally, managed as you like)
