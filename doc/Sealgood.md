# SealGood — Sp�cification technique (niveau Master)

## 1. Finalit� du protocole

Ce protocole vise � permettre la v�rification cryptographique d’un
fichier num�rique sans support externe ni infrastructure centralis�e. La
signature est int�gr�e au **nom de fichier** et les instructions de
v�rification sont dissimul�es dans le **contenu du document**, dans une zone
peu intrusive.

## 2. Concepts fondamentaux

* **Document** : fichier binaire ou textuel (PDF prioritaire) � signer.
* **Cl� priv�e** : utilis�e pour produire une signature Ed25519 du document.
* **Cl� publique** : publi�e avec le document pour permettre la v�rification.
* **Signature** : signature Ed25519 d’un hach� du contenu inject�.
* **Payload invisible** : donn�es techniques (cl�, script, m�tainfos) ins�r�es
dans des champs visuellement neutres du document.

## 3. Format du nom de fichier

### 3.1 Sch�ma nominal

## 4. Contenu embarqu� (payload)

Le document est enrichi d’un bloc masqu� contenant :

* Cl� publique en format PEM
* Script minimal Bash de v�rification (exploitable par copier-coller)
* Éventuellement, un hash clair du contenu

Ce bloc est encadr� dans le contenu du fichier par :

```
###BEGIN SEALGOOD
<contenu>
###END SEALGOOD
```


## 5. Processus de signature (�metteur)

### Entr�es :

* Fichier source : `doc.pdf`
* Cl� priv�e : `private.pem`

### Étapes :

1. Ins�rer le bloc SEALGOOD dans le document (facultatif)
2. Calculer le hash stable du document final (`H`)
3. Signer ce hash avec la cl� priv�e de l’auteur → `SIG`
4. (Optionnel) G�n�rer un timestamp externe (`TS`) sur ce m�me hash
5. Renommer le fichier en y int�grant ces deux �l�ments :


## 6. Processus de v�rification (destinataire)

### Entr�es :


### Étapes :


Les deux v�rifications sont ind�pendantes : l’�chec de l’une
n’invalide pas l’autre.

## 7. Typologie des documents support�s

* **PDF** : injection texte invisible + encart visible facultatif
* **Texte brut** : ajout en queue de fichier avec marqueur `#pragma`
* **Archives ZIP/TAR** : ajout d’un fichier `_verify/verify.autoverify.txt`
* **Images (JPG/PNG)** : injection dans EXIF ou tEXt, QR facultatif
(120×120 px min.)

Tous les autres types sont trait�s au cas par cas, ou via un conteneur externe.

## 8. Outils fournis

Un script Bash g�n�rique (4 fonctions) :

* `autoverify genkey` → g�n�re/stocke la paire Ed25519
* `autoverify sign fichier.pdf` → signe + injecte + renomme
* `autoverify verify fichier.sign�.pdf` → v�rifie signature

## 9. Caract�ristiques du format

* **Autoportant** : signature et instructions int�gr�es (ou annex�es dans une enveloppe)
* **Ind�pendant du r�seau** (sauf si `.verifier` est exploit� en ligne)
* **Robuste** : ne tol�re aucune alt�ration du fichier ni de son nom
* **Interop�rable** : texte invisible copiable dans le presse-papier
* **S�paration conceptuelle** :

  * Les incrustations techniques dans le document (cl�, script, QR) sont **optionnelles** et faites **avant signature** pour l’apprentissage "juste-�-temps"
  * La signature num�rique et l’horodatage sont deux **passes ind�pendantes** sur un m�me hash, et peuvent �tre superpos�es dans une enveloppe externe

### 🧠 Note th�orique : Signature et horodatage unifi�s

> La signature cryptographique (par l’auteur) et l’horodatage
(par un horodateur) sont deux applications de la m�me op�ration : la
**signature num�rique** sur le **hash stable du document**. La premi�re
garantit l’**origine**, la seconde l’**ant�riorit�**. Elles
peuvent �tre superpos�es dans le cadre d’un syst�me autoportant sans
alt�rer le fichier sign�.

* **Autoportant** : signature et instructions int�gr�es
* **Ind�pendant du r�seau** (sauf si `.verifier` est exploit� en ligne)
* **Robuste** : ne tol�re aucune alt�ration du fichier ni de son nom
* **Interop�rable** : texte invisible copiable dans le presse-papier

## 10. Limites connues

* Le fichier **ne doit pas �tre renomm�**
* Toute modification interne (m�tadonn�e, OCR, ajout) invalide la signature
* R�sistance post-quantique non garantie (Ed25519)

## 11. Extensions et options

* Hash secondaire clair int�gr� au bloc SEALGOOD

* QRcode discret embarqu� (formats visuels)

* `.verifier` utilis� comme routage vers un service de v�rification

* Version enveloppe externe pour binaires non injectables

* Chiffrement partiel conditionn� � la m�me cl� publique

* **Horodatage facultatif** : preuve d’ant�riorit� par OpenTimestamps
(.ots) ou service TSA RFC 3161 (.tsr)

  * permet une validation diff�r�e, sans reposer sur la disponibilit�
d’un tiers
  * preuve autoport�e (fichier .ots/.tsr � inclure dans l’enveloppe ou
dans le bloc SEALGOOD)

* Hash secondaire clair int�gr� au bloc SEALGOOD

* QRcode discret embarqu� (formats visuels)

* `.verifier` utilis� comme routage vers un service de v�rification

* Version enveloppe externe pour binaires non injectables

* Chiffrement partiel conditionn� � la m�me cl� publique

## 12. Comparaison avec les standards existants

L’approche SealGood propose une alternative l�g�re et autoport�e
aux standards �tablis de signature num�rique. Voici une comparaison avec les
normes les plus proches :

### RFC / Normes partiellement redondantes

| Standard           | Type               | Similitudes                       | Limites ou diff�rences                                     |
| ------------------ | ------------------ | --------------------------------------------------- | --------------------------------------------------------------- |
| RFC 5652 / CMS     | Conteneur sign�    | Signature encapsul�e avec structure d�finie         | Complexit�, d�pendance � PKI, non adapt� � Ed25519 |
| RFC 5126 / CAdES   | CMS avanc�         | Signatures encapsul�es pour documents �lectroniques | Verbosit�, n�cessite X.509, peu lisible sans outils sp�cialis�s |
| RFC 5485           | Signature d�tach�e | Fichier .sig � c�t� d’un fichier original           | Pas de conteneur, pas de support int�gr� aux formats vis�s      |
| ETSI ASiC (.asice) | Archive sign�e ZIP | Archive contenant fichiers + signature              | Tr�s structur�, profils XML/XAdES, usage restreint � l'Europe   |

### Avantages sp�cifiques d’SealGood

* Signature autoport�e dans le **nom de fichier** ou via **conteneur ZIP/TAR**
* Instructions de v�rification **copiables** dans le document
* **Ind�pendant de toute infrastructure PKI** ou annuaire X.509
* Fonctionne m�me avec des outils basiques (Bash + OpenSSL)
* **Lisibilit� humaine** et r�trocompatibilit� assur�es

### Limites connues

* Pas encore **post-quantique** (Ed25519, expos� aux futurs risques)
* **Renommage du fichier destructeur** (sauf en usage enveloppe externe)
* Aucun **support natif** dans les suites bureautiques grand public

### Arbitrage recommand�

* **Enveloppe externe universelle** (ZIP/TAR) :

  * Permet d’encapsuler n’importe quel fichier avec son
mat�riel de v�rification
  * Supprime la d�pendance au nom de fichier pour la signature
  * Rend SealGood applicable � tout format sans modification interne

* **Choix binaire** :

  * Mode nom de fichier sign� (l�ger, orient� usage direct)
  * Mode enveloppe universelle (robuste, orient� archivage)

## 13. Attribution

Sp�cification initiale : Thibault Le Paul, juin 2025
R�daction technique : OpenAI ChatGPT (GPT-4o)
Licence recommand�e : CC-BY-4.0

## 14. Cas d’usage recommand�s

### 1. Archivage personnel ou acad�mique

* Int�grer une preuve d’ant�riorit� v�rifiable dans un fichier unique
(papier, th�se, manuscrit).
* Format recommand� : PDF avec encart signature visible + signature int�gr�e
au nom ou enveloppe ZIP.

### 2. Échange entre pairs

* Transmettre un fichier avec instructions de v�rification directement lisibles.
* Utilisation l�g�re du mode autoport� (nom de fichier sign�).

### 3. Justificatifs l�gaux ou administratifs

* Fournir un document avec authentification d’origine v�rifiable, sans
infrastructure externe.
* Pr�f�rer enveloppe ZIP contenant original + preuve + cl� publique.

### 4. Diffusion publique de documents officiels

* Ajouter une signature int�gr�e + instructions pour v�rification d�connect�e.
* Peut �tre combin� avec QRCode vers site de v�rification facultatif.

### 5. Usage automatis� (serveur)

* V�rification automatis�e de fichiers d�pos�s (via nom + structure interne).
* Fichier `verify.autoverify.txt` parsable directement dans une archive.

Ces cas peuvent �tre combin�s ou sp�cialis�s par secteur selon les contraintes
(juridiques, scientifiques, etc.)

Sp�cification initiale : Thibault Le Paul, juin 2025
R�daction technique : OpenAI ChatGPT (GPT-4o)
Licence recommand�e : CC-BY-4.0


🔐 Use case SealGood : Signature et horodatage d’une cl� publique
🎯 Objectif
Permettre � un individu de publier sa propre cl� publique de mani�re
v�rifiable, sans d�pendre d’une autorit� de certification centralis�e,
en utilisant SealGood comme scellant :

avec preuve d’ant�riorit� (timestamp),

avec preuve de non-r�pudiation (auto-publication contr�l�e),

avec cha�ne v�rifiable de bout en bout (nom de fichier, contenu, signature, timestamp).

🧩 Él�ment cl� : le document est la d�claration, et sa diffusion
libre devient v�rification
"Si je signe ce document contenant ma cl�, et que je le publie moi-m�me,
je consens � sa v�rification future sans recours."

📘 Cas d’usage :
Je veux publier une cl� ed25519 pour signer mes messages ou fichiers.

Je cr�e un fichier .pdf, .txt, .md ou .html contenant :

la cl� publique,

une d�claration d’identit� (libre),

un lien de pr�sentation (URL personnelle),

les scell�s SealGood (_a:... pour signature, _t:... pour horodatage).

Je publie ce fichier sous une URL stable :
https://mon.domaine.tld/pubkey_toto_a:{sig64url}_t:{ts64url}.pdf

✅ Avantages
📎 Non-r�pudiation : l’auteur ne peut pas pr�tendre que la
cl� n’est pas la sienne s’il l’a publi�e sur une URL
sous son contr�le.

🕒 Horodatage inviolable : toute tentative de backdate ou
d’usurpation est rejetable par analyse des scell�s.

🔍 V�rification simple : tout tiers peut reconstituer la signature,
extraire la cl� et valider l’identit�.

🧩 Cha�nage possible : une cl� peut signer un autre fichier qui d�clare
une nouvelle cl� → rotation avec continuit�.

🧪 Option : "Preuve d’intention"
Tu peux aussi pr�voir une d�claration de type :

text
Copier
Modifier
Cette cl� publique est publi�e par Thibault LE PAUL le 20 juin 2025
dans le but de signer tous ses documents relatifs � SealGood.
Scell�e et horodat�e, elle devient preuve d’intention opposable.

Souhaites-tu que je l’int�gre comme nouveau bloc "Use Case 5" dans la
spec fonctionnelle de SealGood ? On peut aussi b�tir une commande d�di�e
(sealgood certify-key) si tu penses � l'int�grer en CLI.

#pragma info autotag #dev #specification #usecase_signature_cle
#pragma info autotag #num=10 #type=guide #confidence=high #difficulty=medium
#freshness=hours #source=user_input #verified=yes
#model=gpt-4o-128k-2024-05-13 #lang=fr

Voici le Use Case 5 pour la sp�cification fonctionnelle de SealGood :

🧩 Use Case 5 – Certification et publication d'une cl� publique
Objectif
Permettre � un individu de publier sa cl� publique (ex. ed25519) de mani�re
sign�e, horodat�e et v�rifiable, sans passer par une autorit� de certification centralis�e.

Description du processus
Cr�ation d’un document (PDF, TXT, HTML, etc.) contenant :

la cl� publique du signataire ;

une d�claration libre (identit�, usage pr�vu, etc.) ;

un lien URL de pr�sentation (sous contr�le du signataire) ;

le nom du fichier incluant un identifiant a:{sig64url} (signature de la cl�)
et t:{ts64url} (horodatage).

G�n�ration du scell� SealGood :

Signature du document (ou de la cl� directement) ;

Ajout d’un scell� dans le contenu ou via nommage structur� ;

Option : timestamp scell� par une autorit� TSA.

Publication du fichier sur une URL stable :

Ex : https://user.site/ed25519_pub_a:{sig64url}_t:{ts64url}.pem

Propri�t�s garanties
Propri�t� Garantie
Identit� d�clar�e Lisible dans le contenu (non prouv�e seule)
Cl� publique certifi�e  Par le scell� cryptographique _a:...
Date certaine Via scell� d’horodatage _t:...
Non-r�pudiation Par publication sur un site contr�l� par le signataire
Reproductibilit�  Tout tiers peut reconstituer la signature et la cl�

Utilisation
Auto-certification d'identit� dans un projet ou un manifeste.

Signature de fichiers ou messages en cha�ne par cette cl�.

Int�gration dans des syst�mes pair-�-pair, blockchains, ou f�d�rations sans PKI.


