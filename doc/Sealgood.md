# SealGood â€” Spécification technique (niveau Master)

## 1. Finalité du protocole

Ce protocole vise à permettre la vérification cryptographique dâ€™un
fichier numérique sans support externe ni infrastructure centralisée. La
signature est intégrée au **nom de fichier** et les instructions de
vérification sont dissimulées dans le **contenu du document**, dans une zone
peu intrusive.

## 2. Concepts fondamentaux

* **Document** : fichier binaire ou textuel (PDF prioritaire) à signer.
* **Clé privée** : utilisée pour produire une signature Ed25519 du document.
* **Clé publique** : publiée avec le document pour permettre la vérification.
* **Signature** : signature Ed25519 dâ€™un haché du contenu injecté.
* **Payload invisible** : données techniques (clé, script, métainfos) insérées
dans des champs visuellement neutres du document.

## 3. Format du nom de fichier

### 3.1 Schéma nominal

## 4. Contenu embarqué (payload)

Le document est enrichi dâ€™un bloc masqué contenant :

* Clé publique en format PEM
* Script minimal Bash de vérification (exploitable par copier-coller)
* Ã‰ventuellement, un hash clair du contenu

Ce bloc est encadré dans le contenu du fichier par :

```
###BEGIN SEALGOOD
<contenu>
###END SEALGOOD
```


## 5. Processus de signature (émetteur)

### Entrées :

* Fichier source : `doc.pdf`
* Clé privée : `private.pem`

### Ã‰tapes :

1. Insérer le bloc SEALGOOD dans le document (facultatif)
2. Calculer le hash stable du document final (`H`)
3. Signer ce hash avec la clé privée de lâ€™auteur â†’ `SIG`
4. (Optionnel) Générer un timestamp externe (`TS`) sur ce même hash
5. Renommer le fichier en y intégrant ces deux éléments :


## 6. Processus de vérification (destinataire)

### Entrées :


### Ã‰tapes :


Les deux vérifications sont indépendantes : lâ€™échec de lâ€™une
nâ€™invalide pas lâ€™autre.

## 7. Typologie des documents supportés

* **PDF** : injection texte invisible + encart visible facultatif
* **Texte brut** : ajout en queue de fichier avec marqueur `#pragma`
* **Archives ZIP/TAR** : ajout dâ€™un fichier `_verify/verify.autoverify.txt`
* **Images (JPG/PNG)** : injection dans EXIF ou tEXt, QR facultatif
(120Ã—120 px min.)

Tous les autres types sont traités au cas par cas, ou via un conteneur externe.

## 8. Outils fournis

Un script Bash générique (4 fonctions) :

* `autoverify genkey` â†’ génère/stocke la paire Ed25519
* `autoverify sign fichier.pdf` â†’ signe + injecte + renomme
* `autoverify verify fichier.signé.pdf` â†’ vérifie signature

## 9. Caractéristiques du format

* **Autoportant** : signature et instructions intégrées (ou annexées dans une enveloppe)
* **Indépendant du réseau** (sauf si `.verifier` est exploité en ligne)
* **Robuste** : ne tolère aucune altération du fichier ni de son nom
* **Interopérable** : texte invisible copiable dans le presse-papier
* **Séparation conceptuelle** :

  * Les incrustations techniques dans le document (clé, script, QR) sont **optionnelles** et faites **avant signature** pour lâ€™apprentissage "juste-à-temps"
  * La signature numérique et lâ€™horodatage sont deux **passes indépendantes** sur un même hash, et peuvent être superposées dans une enveloppe externe

### ğŸ§  Note théorique : Signature et horodatage unifiés

> La signature cryptographique (par lâ€™auteur) et lâ€™horodatage
(par un horodateur) sont deux applications de la même opération : la
**signature numérique** sur le **hash stable du document**. La première
garantit lâ€™**origine**, la seconde lâ€™**antériorité**. Elles
peuvent être superposées dans le cadre dâ€™un système autoportant sans
altérer le fichier signé.

* **Autoportant** : signature et instructions intégrées
* **Indépendant du réseau** (sauf si `.verifier` est exploité en ligne)
* **Robuste** : ne tolère aucune altération du fichier ni de son nom
* **Interopérable** : texte invisible copiable dans le presse-papier

## 10. Limites connues

* Le fichier **ne doit pas être renommé**
* Toute modification interne (métadonnée, OCR, ajout) invalide la signature
* Résistance post-quantique non garantie (Ed25519)

## 11. Extensions et options

* Hash secondaire clair intégré au bloc SEALGOOD

* QRcode discret embarqué (formats visuels)

* `.verifier` utilisé comme routage vers un service de vérification

* Version enveloppe externe pour binaires non injectables

* Chiffrement partiel conditionné à la même clé publique

* **Horodatage facultatif** : preuve dâ€™antériorité par OpenTimestamps
(.ots) ou service TSA RFC 3161 (.tsr)

  * permet une validation différée, sans reposer sur la disponibilité
dâ€™un tiers
  * preuve autoportée (fichier .ots/.tsr à inclure dans lâ€™enveloppe ou
dans le bloc SEALGOOD)

* Hash secondaire clair intégré au bloc SEALGOOD

* QRcode discret embarqué (formats visuels)

* `.verifier` utilisé comme routage vers un service de vérification

* Version enveloppe externe pour binaires non injectables

* Chiffrement partiel conditionné à la même clé publique

## 12. Comparaison avec les standards existants

Lâ€™approche SealGood propose une alternative légère et autoportée
aux standards établis de signature numérique. Voici une comparaison avec les
normes les plus proches :

### RFC / Normes partiellement redondantes

| Standard           | Type               | Similitudes                       | Limites ou différences                                     |
| ------------------ | ------------------ | --------------------------------------------------- | --------------------------------------------------------------- |
| RFC 5652 / CMS     | Conteneur signé    | Signature encapsulée avec structure définie         | Complexité, dépendance à PKI, non adapté à Ed25519 |
| RFC 5126 / CAdES   | CMS avancé         | Signatures encapsulées pour documents électroniques | Verbosité, nécessite X.509, peu lisible sans outils spécialisés |
| RFC 5485           | Signature détachée | Fichier .sig à côté dâ€™un fichier original           | Pas de conteneur, pas de support intégré aux formats visés      |
| ETSI ASiC (.asice) | Archive signée ZIP | Archive contenant fichiers + signature              | Très structuré, profils XML/XAdES, usage restreint à l'Europe   |

### Avantages spécifiques dâ€™SealGood

* Signature autoportée dans le **nom de fichier** ou via **conteneur ZIP/TAR**
* Instructions de vérification **copiables** dans le document
* **Indépendant de toute infrastructure PKI** ou annuaire X.509
* Fonctionne même avec des outils basiques (Bash + OpenSSL)
* **Lisibilité humaine** et rétrocompatibilité assurées

### Limites connues

* Pas encore **post-quantique** (Ed25519, exposé aux futurs risques)
* **Renommage du fichier destructeur** (sauf en usage enveloppe externe)
* Aucun **support natif** dans les suites bureautiques grand public

### Arbitrage recommandé

* **Enveloppe externe universelle** (ZIP/TAR) :

  * Permet dâ€™encapsuler nâ€™importe quel fichier avec son
matériel de vérification
  * Supprime la dépendance au nom de fichier pour la signature
  * Rend SealGood applicable à tout format sans modification interne

* **Choix binaire** :

  * Mode nom de fichier signé (léger, orienté usage direct)
  * Mode enveloppe universelle (robuste, orienté archivage)

## 13. Attribution

Spécification initiale : Thibault Le Paul, juin 2025
Rédaction technique : OpenAI ChatGPT (GPT-4o)
Licence recommandée : CC-BY-4.0

## 14. Cas dâ€™usage recommandés

### 1. Archivage personnel ou académique

* Intégrer une preuve dâ€™antériorité vérifiable dans un fichier unique
(papier, thèse, manuscrit).
* Format recommandé : PDF avec encart signature visible + signature intégrée
au nom ou enveloppe ZIP.

### 2. Ã‰change entre pairs

* Transmettre un fichier avec instructions de vérification directement lisibles.
* Utilisation légère du mode autoporté (nom de fichier signé).

### 3. Justificatifs légaux ou administratifs

* Fournir un document avec authentification dâ€™origine vérifiable, sans
infrastructure externe.
* Préférer enveloppe ZIP contenant original + preuve + clé publique.

### 4. Diffusion publique de documents officiels

* Ajouter une signature intégrée + instructions pour vérification déconnectée.
* Peut être combiné avec QRCode vers site de vérification facultatif.

### 5. Usage automatisé (serveur)

* Vérification automatisée de fichiers déposés (via nom + structure interne).
* Fichier `verify.autoverify.txt` parsable directement dans une archive.

Ces cas peuvent être combinés ou spécialisés par secteur selon les contraintes
(juridiques, scientifiques, etc.)

Spécification initiale : Thibault Le Paul, juin 2025
Rédaction technique : OpenAI ChatGPT (GPT-4o)
Licence recommandée : CC-BY-4.0


ğŸ” Use case SealGood : Signature et horodatage dâ€™une clé publique
ğŸ¯ Objectif
Permettre à un individu de publier sa propre clé publique de manière
vérifiable, sans dépendre dâ€™une autorité de certification centralisée,
en utilisant SealGood comme scellant :

avec preuve dâ€™antériorité (timestamp),

avec preuve de non-répudiation (auto-publication contrôlée),

avec chaîne vérifiable de bout en bout (nom de fichier, contenu, signature, timestamp).

ğŸ§© Ã‰lément clé : le document est la déclaration, et sa diffusion
libre devient vérification
"Si je signe ce document contenant ma clé, et que je le publie moi-même,
je consens à sa vérification future sans recours."

ğŸ“˜ Cas dâ€™usage :
Je veux publier une clé ed25519 pour signer mes messages ou fichiers.

Je crée un fichier .pdf, .txt, .md ou .html contenant :

la clé publique,

une déclaration dâ€™identité (libre),

un lien de présentation (URL personnelle),

les scellés SealGood (_a:... pour signature, _t:... pour horodatage).

Je publie ce fichier sous une URL stable :
https://mon.domaine.tld/pubkey_toto_a:{sig64url}_t:{ts64url}.pdf

âœ… Avantages
ğŸ“ Non-répudiation : lâ€™auteur ne peut pas prétendre que la
clé nâ€™est pas la sienne sâ€™il lâ€™a publiée sur une URL
sous son contrôle.

ğŸ•’ Horodatage inviolable : toute tentative de backdate ou
dâ€™usurpation est rejetable par analyse des scellés.

ğŸ” Vérification simple : tout tiers peut reconstituer la signature,
extraire la clé et valider lâ€™identité.

ğŸ§© Chaînage possible : une clé peut signer un autre fichier qui déclare
une nouvelle clé â†’ rotation avec continuité.

ğŸ§ª Option : "Preuve dâ€™intention"
Tu peux aussi prévoir une déclaration de type :

text
Copier
Modifier
Cette clé publique est publiée par Thibault LE PAUL le 20 juin 2025
dans le but de signer tous ses documents relatifs à SealGood.
Scellée et horodatée, elle devient preuve dâ€™intention opposable.

Souhaites-tu que je lâ€™intègre comme nouveau bloc "Use Case 5" dans la
spec fonctionnelle de SealGood ? On peut aussi bâtir une commande dédiée
(sealgood certify-key) si tu penses à l'intégrer en CLI.

#pragma info autotag #dev #specification #usecase_signature_cle
#pragma info autotag #num=10 #type=guide #confidence=high #difficulty=medium
#freshness=hours #source=user_input #verified=yes
#model=gpt-4o-128k-2024-05-13 #lang=fr

Voici le Use Case 5 pour la spécification fonctionnelle de SealGood :

ğŸ§© Use Case 5 â€“ Certification et publication d'une clé publique
Objectif
Permettre à un individu de publier sa clé publique (ex. ed25519) de manière
signée, horodatée et vérifiable, sans passer par une autorité de certification centralisée.

Description du processus
Création dâ€™un document (PDF, TXT, HTML, etc.) contenant :

la clé publique du signataire ;

une déclaration libre (identité, usage prévu, etc.) ;

un lien URL de présentation (sous contrôle du signataire) ;

le nom du fichier incluant un identifiant a:{sig64url} (signature de la clé)
et t:{ts64url} (horodatage).

Génération du scellé SealGood :

Signature du document (ou de la clé directement) ;

Ajout dâ€™un scellé dans le contenu ou via nommage structuré ;

Option : timestamp scellé par une autorité TSA.

Publication du fichier sur une URL stable :

Ex : https://user.site/ed25519_pub_a:{sig64url}_t:{ts64url}.pem

Propriétés garanties
Propriété Garantie
Identité déclarée Lisible dans le contenu (non prouvée seule)
Clé publique certifiée  Par le scellé cryptographique _a:...
Date certaine Via scellé dâ€™horodatage _t:...
Non-répudiation Par publication sur un site contrôlé par le signataire
Reproductibilité  Tout tiers peut reconstituer la signature et la clé

Utilisation
Auto-certification d'identité dans un projet ou un manifeste.

Signature de fichiers ou messages en chaîne par cette clé.

Intégration dans des systèmes pair-à-pair, blockchains, ou fédérations sans PKI.


