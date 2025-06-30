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


### Help ###

```
SealGood - Signature et horodatage de documents via OpenSSL + TSA

Utilisation: sealgood help genkey { clean inject date sign verify }

COMMANDES:
  genkey    Génère une nouvelle paire de clés ed25519 protégée par mot de passe
  help      Affiche cette aide
  clean     Extrait le contenu original sans les balises SEALGOOD
  inject    Injecte le payload SealGood dans un fichier PDF, HTML ou PEM
  date      Horodate un document via un tiers de confiance (TSA)
  sign      Signe un document avec votre clé privée
  verify    Vérifie la signature et l'horodatage d'un document

  Les commandes se composent en pipeline implicitement ordonné:

  clean | inject | date | sign | verify
  - lit les données sur stdin
  - commente la progression sur stderr
  - écrit les données sur stdout
  - ne modifie JAMAIS directement aucun fichier

  Quand l'entrée est une liste de fichiers, celle-ci est énumérée
  et chaque élément est traité dans le pipeline de transformation.
  Le résultat est archivé au format tar+gzip avec des empreintes
  cryptographiques intégrées aux noms de fichiers signés/horodatés
  enumerate
   \
     +-- clean | inject | date | sign | verify

  inject          respecte le payload SealGood déjà présent;
  date sign       opèrent implicitement inject;
  date sign       respectent une signature/horodatage déjà présente;
  enumerate sign  ne demande qu'une fois la passphrase de la clé privée.

Exemples:
  sealgood sign date < contract.pdf > contract_sealgood.pdf
  sealgood verify    < contract_sealgood.pdf
  ls contract*.pdf | sealgood sign date > contracts.tgz

Fichiers utilisés:
  $HOME/.ssh/ed25519_private_*.pem  : clés privées signataires
  $HOME/.ssh/ed25519_public_*.pem   : clés publiques associées
  $HOME/.ssh/id_rsa.pub             : déclaration d'identité du signataire
  https://freetsa.org/files/cacert.pem : certificat racine TSA

Servlet ouverte :
  ssh -o SendEnv=LANGUAGE sealgood@perso.tlp.name {clean inject date verify}

Voir aussi : https://github.com/tibolpol/sealgood

Copyright (c) 2025 Thibault Le Paul (@tibolpol)
Licence MIT - https://opensource.org/license/mit/

```
