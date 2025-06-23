# Analyse de robustesse du syst�me SealGood

## Pr�sentation

**SealGood** est un syst�me d’authentification et d’horodatage
de documents fond� sur une approche minimaliste, manuelle, transparente et
ind�pendante. Il repose exclusivement sur des outils standards (POSIX,
OpenSSL) et des primitives cryptographiques robustes (Ed25519, RFC 3161). Il
vise � offrir une alternative l�g�re et v�rifiable � l’usage de
certificats et d’infrastructures centralis�es.

## Principes fondamentaux

* **Signature Ed25519** : usage d’une cl� publique robuste, encod�e en
SPKI PEM.
* **Transparence** : aucune bo�te noire, tous les outils sont standard, open
source ou POSIX.
* **Horodatage** : recours � une TSA externe (ex. FreeTSA) pour attester
d’un instant T.
* **Cha�ne de confiance manuelle** : v�rification explicite de chaque �tape,
sans automatisation cach�e.

## Évaluation de la solidit�

### Points forts

1. **Cryptographie robuste**

   * Ed25519 : courbe moderne, rapide, difficile � compromettre.
   * Format de cl� standard (SPKI base64 PEM), interop�rable avec `openssl`,
`age`, `ssh-keygen`, etc.

2. **Transparence maximale**

   * Les �tapes de v�rification sont manuelles et document�es.
   * Chaque utilisateur peut contr�ler enti�rement le processus.

3. **S�paration des responsabilit�s**

   * Le contenu sign� est extrait proprement avant horodatage.
   * Les fichiers interm�diaires sont explicites et modifiables.

4. **Avertissements honn�tes**

   * Le texte signale explicitement la faiblesse potentielle du lien entre
identit� et cl�.

5. **Conformit� aux standards**

   * Utilisation du protocole RFC 3161 pour l’horodatage.
   * Inclusion du certificat de la TSA pour validation future.

### Limites et risques

1. **Cha�ne de confiance externe**

   * Lier une identit� � une cl� repose ici sur l’h�bergement
personnel (site TLS, Git sign�, etc.)
   * Pas de certification externe (AC, eIDAS) sans action suppl�mentaire.

2. **Risque sur l’environnement d’ex�cution**

   * Fichiers temporaires `/tmp/` peuvent �tre compromis dans un syst�me partag�.

3. **V�rification complexe pour n�ophytes**

   * Bien que v�rifiable, le processus reste technique sans interface d�di�e.

4. **TSA de confiance limit�e**

   * FreeTSA est suffisante pour un usage personnel ou POC, mais sans
garanties contractuelles.

## Enrichissements possibles

### Attestation crois�e de la cl�

* Publication sur plusieurs canaux : site perso HTTPS, GitHub avec commit
sign�, DNSSEC, Keybase, blockchain.

### Utilisation de certificats personnalis�s

* Signature de sous-cl�s d’usage (documents) avec une cl� racine horodat�e.
* Cr�ation d’un format `SealGood-Cert` minimal : JSON ou PEM avec
signature de la sous-cl�.

### Hash explicite de la cl� dans chaque document

* Ajout d’un champ `pubkey-sha256:` ou `Fingerprint:` dans la
d�claration textuelle.

### Script POSIX de v�rification automatis�e

* Un script `sealgood-verify.sh` explicite chaque �tape, sans magie, pour
l'utilisateur averti.

### Archivage scell� de la cl� seule

* Horodatage d’un fichier contenant uniquement la cl� et
l’identit� d�clar�e, utilisable pour signer ensuite n’importe
quel document.

## Cas d’usages pertinents

* D�p�t personnel de manuscrits, projets, intentions.
* Archivage juridique ou technique (preuve d’ant�riorit�).
* Notariat l�ger (engagements associatifs, revendications personnelles).
* V�rification asynchrone sans infrastructure.

## Conclusion

SealGood propose une base **solide, ind�pendante, reproductible** pour
garantir l’authenticit�, l’int�grit� et l’horodatage
d’un document.

Sa force r�side dans sa **transparence totale**, son **absence de d�pendance �
des tiers** ferm�s, et sa **modularit�**. Il est particuli�rement adapt� aux
usages personnels, militants, techniques ou artistiques o� la preuve doit �tre
accessible et autonome.

Le d�fi principal reste la **construction de la cha�ne de confiance autour de
la cl� publique**, mais les outils et les strat�gies sont l� pour y r�pondre
sans compromission de la philosophie "DIY".

SealGood n’est pas un substitut aux certificats qualifi�s, mais un
**compl�ment puissant pour les individus souverains** souhaitant sceller leur
parole ou leurs documents dans le temps.

