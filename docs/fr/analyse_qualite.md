# Analyse qualité du projet SealGood

## Qualités

### 1. Architecture — Pipeline Unix élégant
Le design en chaîne de fonctions composables (`help → genkey → enumerate → clean → sign → date → verify → end_of_pipe`) est remarquable. Chaque fonction décide si elle doit agir ou être passante via `strip`, ce qui permet une composition naturelle :
```bash
sealgood sign date < contract.pdf > contract_sealgood.pdf
```
C'est un modèle rare et bien pensé dans un script Bash.

### 2. Literate programming — Code = Documentation
Le fichier `bin/sealgood` est à la fois un script Bash exécutable **et** un document Markdown avec diagrammes Mermaid. Les blocs `:<<'```bash'` permettent d'intercaler documentation et code de façon brillante. Le code **est** sa propre documentation.

### 3. Cryptographie solide et transparente
- **Ed25519** (courbe moderne, résistante)
- **RFC 3161** (horodatage standard, interopérable)
- Clés privées **chiffrées AES-256-CBC** obligatoirement (rejet des clés non chiffrées, `bin/sealgood` L625)
- Chaque étape de vérification est reproductible manuellement avec OpenSSL

### 4. Minimal footprint — Zéro dépendance exotique
Seuls Bash 4+, OpenSSL, cURL et des outils POSIX standard. Aucun framework, aucun runtime, aucun serveur. Le projet peut même s'exécuter en **servlet SSH**.

### 5. Internationalisation complète
4 langues (fr, es, pt, us) avec gettext, testées explicitement dans les tests d'intégration avec `LANGUAGE=...`.

### 6. Payload auto-portant
Le document signé **embarque** la clé publique, le certificat TSA, la signature, l'horodatage **et** les instructions de vérification. Un document signé est auto-suffisant.

### 7. Sécurité opérationnelle
- `umask go=` pour les fichiers temporaires (`bin/sealgood` L175)
- `mktemp -d` pour le répertoire de travail
- Vérification des dépendances au démarrage
- `trap exit_policy EXIT` pour le nettoyage
- Arguments consommés et vérifiés en bout de pipe (`end_of_pipe`)

### 8. Tests multi-axes
Tests d'intégration couvrant : types de fichiers (PDF, gzip, tar, shell, PEM), locales multiples, vérifications croisées (signer en fr, vérifier en es), batch processing.

---

## Défauts

### 1. Script monolithique — Maintenabilité fragile
1266 lignes dans un seul fichier, mêlant logique métier, cryptographie, UI, i18n et gestion de fichiers. Les dossiers `src/core/`, `src/crypto/`, `src/utils/` sont **vides** — la modularisation prévue n'a pas été réalisée.

### 2. Quoting incohérent — Risques d'injection
Plusieurs variables non quotées, exposant à des problèmes avec les noms de fichiers contenant des espaces ou caractères spéciaux :
- `bin/sealgood` L173 : `[ -s $PRIVATE_KEY ]` au lieu de `"$PRIVATE_KEY"`
- `bin/sealgood` L309 : `(cd "$INITIAL_DIR" && cat "$STOPFILE$FILE")` — `$FILE` vient d'un `read` sur stdin sans sanitisation
- `for cmd in awk openssl base64 curl` sans guillemets (mineur)

### 3. Absence de `set -euo pipefail` global
Le script ne démarre pas avec les protections Bash standard. `set -o pipefail` n'est activé que localement dans `date()` (L530). Une erreur silencieuse dans un pipe peut passer inaperçue.

### 4. URLs TSA en HTTP non chiffré
```bash
export tsa_serv=http://timestamp.digicert.com
export tsa_ca=http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt.pem
```
Les communications avec la TSA et le téléchargement du certificat racine se font en **HTTP clair**, vulnérables à un MITM. Le `curl -s` sans `--fail` ni vérification de certificat aggrave le risque.

### 5. Fichiers temporaires dans `/tmp` sur systèmes partagés
Le `mktemp -d` crée dans `/tmp` par défaut. Sur un système multi-utilisateurs, cela peut exposer des données sensibles (même avec umask, le répertoire parent est lisible). Le document `docs/fr/Robustesse.md` le reconnaît lui-même.

### 6. Pas de framework de test — Assertions fragiles
Les tests reposent sur `diff` contre des fichiers de référence avec des `sed` de masquage. Pas de compteur de tests, pas de rapport pass/fail structuré, pas de mesure de couverture. Un changement cosmétique dans la sortie casse tous les tests.

### 7. `coproc` et descripteurs de fichiers avancés
L'utilisation de `coproc passrelay` (`bin/sealgood` L236) et de descripteurs `{fdpassin}`, `{fdpassask}`, `{fdtty}` est puissante mais très fragile et difficile à déboguer. C'est du Bash avancé qui limite la portabilité et la maintenabilité.

### 8. README incomplet
Le `README.md` mélange deux styles (technique français + slogan anglais), manque d'instructions d'installation claires, de troubleshooting, et de section contributeurs. La typo `Markdow` apparaît à deux endroits.

### 9. Commentaire `# DANGER : lit tout le doc`
Présent à deux endroits dans `sign()` et `date()`, ce commentaire signale que le `sed` relit l'intégralité du document pour une substitution. Pour des fichiers volumineux, c'est un problème de performance et de mémoire.

### 10. Gestion d'erreur `curl` minimale
`curl -s` masque les erreurs réseau. Le script utilise `perl` pour détecter les erreurs dans la réponse TSA, mais ne gère pas les timeouts, les codes HTTP d'erreur, ni les certificats invalides.

### 11. Hardcoded magic values
- `consecutive_errors >= 5` (`bin/sealgood` L340)
- `sha256sum | cut -c1-8` pour le hash dans le nom de fichier
- Tags `### BEGIN SEALGOOD` / `### END SEALGOOD` en dur

---

## Synthèse

| Dimension | Verdict |
|---|---|
| **Architecture** | Excellente conception pipeline, mais monolithique |
| **Code quality** | Lisible et bien commenté, mais quoting et robustesse insuffisants |
| **Sécurité crypto** | Solide (Ed25519, RFC 3161), mais transport TSA en HTTP |
| **Sécurité système** | Correcte (umask, mktemp, trap), mais `/tmp` partagé |
| **Tests** | Bonne couverture fonctionnelle, mais infrastructure fragile |
| **Documentation** | Remarquable en tant que literate programming, README à améliorer |
| **Portabilité** | Fonctionne partout où Bash 4+ et OpenSSL sont disponibles |
| **UX** | Bon help, bons messages colorés, i18n 4 langues |

Le projet est **conceptuellement excellent** — l'idée de literate programming en Bash avec pipeline composable est originale et bien exécutée. Les défauts sont principalement liés à la **rigueur industrielle** (quoting, tests structurés, HTTPS, modularisation) qui serait nécessaire pour un déploiement en production.
