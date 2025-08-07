<title>SealGood - Présentation</title>

# SealGood - Signature et horodatage de documents

SealGood est un script Bash permettant de signer et d'horodater des documents
(PDF, XML, HTML, Certificats et public keys PEM, gzip, shellscripts) de manière non intrusive en utilisant OpenSSL et des
services TSA (Time Stamp Authority).

## Fonctionnalités principales

-  **Signature numérique** avec clés Ed25519 (`sign`)
-  ⏱ **Horodatage** via Digicert (`date`)
-  **Vérification** complète des signatures et horodatages (`verify`)
-  **Génération** d'une paire de clés Ed25519 (`genkey`)
-  **Préservation** du format original des documents
-  **Transparence** - Toutes les étapes sont reproductibles manuellement
-  **Traitement par lot** des fichiers
-  **Facile à distribuer**
-  **Compatible avec une servlet SSH**

### Particularités

- **Le scellement est intégré au document** sans nécessiter d'enveloppe
  ajoutée, tant que le type de document supporte une forme d'ajout compatible
  avec son format interne.
- **La conception en shell** avec un script [`filetypes`](bin/filetypes) séparé
  a pour but de faciliter l'adaptation du scellement à de nouveaux types de
  fichiers sur le même principe.
- **L'horodatage inclut le certificat racine** de la TSA, pour garantir sa vérifiabilité sans perte du
  certificat.
- **Le scellement est auto-documenté** et utilise des outils standards et gratuits.
- **La signature et horodatage de shellscript** (et autres langages possibles) permet de sécuriser une pile d'exécution.
- **L'horodatage de clé publique PEM** ferme la répudiation des documents signés avec cette clé.
- **L'ensemble ne nécessite aucune ressource ni compte** dans une
  infrastructure, un seul ou des milliers de documents sont scellés en toute autonomie.
- **Le document signé retrouve facilement sa forme originelle**.
- **gzip peut servir de format d'enveloppe** pour le scellement de tout
  document non pris en charge nativement
- **Les destinataires n'ont aucune précaution particulière à prendre** pour
  conserver des documents signés ou horodatés, à condition de les utiliser en
  lecture seule.  Les documents restent pleinement compatibles avec les outils
  habituels (lecteurs PDF, décompresseurs), grâce à l'intégration du
  scellement dans le format d'origine sans altérer leur comportement.

## Cas d'utilisation

- Preuve d'intégrité et d'antériorité de documents
- Signature électronique simple et vérifiable
- Sécurisation de workflows DevOps ou d'installation
- Scellement de clés publiques pour renforcer les signatures ultérieures

## Prérequis

- Bash 4+
- OpenSSL
- Awk
- Base64
- cURL (pour l'horodatage)

## Installation

1. Copiez les scripts [`sealgood`](bin/sealgood) et [`filetypes`](bin/filetypes) dans le même répertoire ;
2. Rendez-les exécutables :
   ```bash
   chmod +x sealgood filetypes
   ```

### Internationalisation
- Copiez [`locale/{}/LC_MESSAGES/sealgood.mo`](locale/fr/LC_MESSAGES/sealgood.mo), avec ce même chemin relatif au répertoire des scripts, en remplaçant `{}` par la langue désirée ;

### Installation par github
   ```bash
   git clone https://github.com/tibolpol/sealgood.git
   ```

   Le dépôt cloné constitue un déploiement valide.

### Pages d'aide
- [help fr](docs/fr/help_fr.md)
- [help es](docs/es/help_es.md)
- [help pt](docs/pt/help_pt.md)
- [help us](docs/us/help_us.md)

### Source ###
- [markdown/mermaid view sealgood](docs/fr/sealgood.md)
- [markdown/mermaid view filetypes](docs/fr/filetypes.md)

## Servlet de test gratuite

Une servlet SSH permet de tester SealGood, excepté la signature parce que
celle-ci requiert votre propre clé privée chiffrée. Le génération de clés et
la signature doivent être effectués dans un environnement privé.

```bash
ssh -o SendEnv=LANGUAGE sealgood@perso.tlp.name {clean date verify}
```
