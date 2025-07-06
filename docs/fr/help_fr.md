```console
[1;36mSealGood - Signature et horodatage de documents via OpenSSL + TSA[0m

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

  clean | inject | sign | date | verify
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
     +-- clean | inject | sign | date | verify

  inject          respecte le payload SealGood déjà présent;
  sign date       opèrent implicitement inject;
  sign date       respectent une signature/horodatage déjà présente;
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
[1;32mmain output: application/x-empty; charset=binary[0m
```
