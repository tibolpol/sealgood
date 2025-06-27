# Analyse de robustesse du système SealGood

## Présentation

**SealGood** est un système d'authentification et d'horodatage
de documents fondé sur une approche minimaliste, manuelle, transparente et
indépendante. Il repose exclusivement sur des outils standards (POSIX,
OpenSSL) et des primitives cryptographiques robustes (Ed25519, RFC 3161). Il
vise à offrir une alternative légère et vérifiable à l'usage de
certificats et d'infrastructures centralisées.

## Principes fondamentaux

* **Signature Ed25519** : usage d'une clé publique robuste, encodée en
SPKI PEM.
* **Transparence** : aucune boîte noire, tous les outils sont standard, open
source ou POSIX.
* **Horodatage** : recours à une TSA externe (ex. FreeTSA) pour attester
d'un instant T.
* **Chaîne de confiance manuelle** : vérification explicite de chaque étape,
sans automatisation cachée.

## Évaluation de la solidité

### Points forts

1. **Cryptographie robuste**

   * Ed25519 : courbe moderne, rapide, difficile à compromettre.
   * Format de clé standard (SPKI base64 PEM), interopérable avec `openssl`,
`age`, `ssh-keygen`, etc.

2. **Transparence maximale**

   * Les étapes de vérification sont manuelles et documentées.
   * Chaque utilisateur peut contrôler entièrement le processus.

3. **Séparation des responsabilités**

   * Le contenu signé est extrait proprement avant horodatage.
   * Les fichiers intermédiaires sont explicites et modifiables.

4. **Avertissements honnêtes**

   * Le texte signale explicitement la faiblesse potentielle du lien entre
identité et clé.

5. **Conformité aux standards**

   * Utilisation du protocole RFC 3161 pour l'horodatage.
   * Inclusion du certificat de la TSA pour validation future.

### Limites et risques

1. **Chaîne de confiance externe**

   * Lier une identité à une clé repose ici sur l'hébergement
personnel (site TLS, Git signé, etc.)
   * Pas de certification externe (AC, eIDAS) sans action supplémentaire.

2. **Risque sur l'environnement d'exécution**

   * Fichiers temporaires `/tmp/` peuvent être compromis dans un système partagé.

3. **Vérification complexe pour néophytes**

   * Bien que vérifiable, le processus reste technique sans interface dédiée.

4. **TSA de confiance limitée**

   * FreeTSA est suffisante pour un usage personnel ou POC, mais sans
garanties contractuelles.

## Enrichissements possibles

### Attestation croisée de la clé

* Publication sur plusieurs canaux : site perso HTTPS, GitHub avec commit
signé, DNSSEC, Keybase, blockchain.

### Utilisation de certificats personnalisés

* Signature de sous-clés d'usage (documents) avec une clé racine horodatée.
* Création d'un format `SealGood-Cert` minimal : JSON ou PEM avec
signature de la sous-clé.

### Hash explicite de la clé dans chaque document

* Ajout d'un champ `pubkey-sha256:` ou `Fingerprint:` dans la
déclaration textuelle.

### Script POSIX de vérification automatisée

* Un script `sealgood-verify.sh` explicite chaque étape, sans magie, pour
l'utilisateur averti.

### Archivage scellé de la clé seule

* Horodatage d'un fichier contenant uniquement la clé et
l'identité déclarée, utilisable pour signer ensuite n'importe
quel document.

## Cas d'usages pertinents

* Dépôt personnel de manuscrits, projets, intentions.
* Archivage juridique ou technique (preuve d'antériorité).
* Notariat léger (engagements associatifs, revendications personnelles).
* Vérification asynchrone sans infrastructure.

## Conclusion

SealGood propose une base **solide, indépendante, reproductible** pour
garantir l'authenticité, l'intégrité et l'horodatage
d'un document.

Sa force réside dans sa **transparence totale**, son **absence de dépendance à
des tiers** fermés, et sa **modularité**. Il est particulièrement adapté aux
usages personnels, militants, techniques ou artistiques où la preuve doit être
accessible et autonome.

Le défi principal reste la **construction de la chaîne de confiance autour de
la clé publique**, mais les outils et les stratégies sont là pour y répondre
sans compromission de la philosophie "DIY".

SealGood n'est pas un substitut aux certificats qualifiés, mais un
**complément puissant pour les individus souverains** souhaitant sceller leur
parole ou leurs documents dans le temps.

