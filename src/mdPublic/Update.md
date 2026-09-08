# 📑 Saferepo Update Report / Rapport de Mise à jour

> Les entrées ci-dessous conservent l'historique du projet. L'état de support,
> les limitations et les critères de release actuels sont définis dans la
> roadmap et la documentation courantes.

## ⚡ Shortcuts / Raccourcis

- [🇫🇷 Sortie Alpha des Corrections (v0.6.9-alpha)](#-sortie-alpha-des-corrections-v069-alpha)
- [🇬🇧 Correction Alpha Release (v0.6.9-alpha)](#-correction-alpha-release-v069-alpha)
- [🇫🇷 Version Française (v0.6.51)](#-version-française-v0651)
- [🇬🇧 English Version (v0.6.51)](#-english-version-v0651)
- [🇫🇷 Version Française (v0.6.5)](#-version-française-v065)
- [🇬🇧 English Version (v0.6.5)](#-english-version-v065)
- [🇫🇷 Version Française (v0.6.0)](#-version-française-v060)
- [🇬🇧 English Version (v0.6.0)](#-english-version-v060)
- [🇫🇷 Version Française (v0.5)](#-version-française-v05)
- [🇬🇧 English Version (v0.5)](#-english-version-v05)
- [🇫🇷 Version Française (v0.3)](#-version-française-v03)
- [🇬🇧 English Version (v0.3)](#-english-version-v03)

---

## 🇫🇷 Sortie Alpha des Corrections (v0.6.9-alpha)

**Date :** 2026-09-08  
**Statut :** alpha technique validée localement ; publication publique à préparer.

Cette sortie regroupe les corrections de stabilisation et la validation qualité
réalisées avant une release publique. Elle ne constitue pas encore une release
finale : la base `vulnera_db` doit toujours être préparée, validée et signée
avec le manifeste d'intégrité avant publication.

### Corrections incluses

- Suppression des mutabilités inutiles dans les tests Rust.
- Suppression des passages `&mut SecurityManager` inutiles vers `scan_repo`.
- Suppression d'un emprunt redondant dans le parcours de scan.
- Conservation de la mutabilité uniquement lorsque l'API l'exige réellement.
- Documentation publique des commandes CLI, des benchmarks réels et du cycle
  de préparation/signature de la base.

### Validation alpha

- `cargo fmt --all -- --check` : succès.
- `cargo clippy --all-targets --all-features -- -D warnings` : succès, aucun warning.
- `cargo test --all-targets --all-features` : succès.
- `cargo check --all-targets --all-features` : succès.
- `cargo build --all-targets --all-features` : succès.
- `cargo build --release --all-features` : succès.
- `cargo bench --no-run --all-features` : succès.
- Les groupes de benchmarks de production ont été exécutés avec succès.

### Points restant avant publication

- Corriger ou retirer les advisories invalides de la base locale.
- Régénérer `.integrity_manifest` avec `saferepo-prepare-database`.
- Signer le manifeste avec la clé privée conservée hors du dépôt.
- Vérifier que la clé publique embarquée correspond à la clé de release.

**Statut :** corrections d'audit appliquées, publication de release encore en préparation.

### Corrections des problèmes et bugs actuels

**Légende des sévérités :** 🔴 Critique · 🟠 Haute · 🟡 Moyenne · 🟢 Mineure.

- **ISSUE-001 — Type : Fonctionnel — Sévérité : 🟠 Haute — Exécution CLI :** les commandes et options Clap sont maintenant transmises au chemin d'exécution réel au lieu de lancer systématiquement un scan du répertoire courant.
- **ISSUE-002 — Type : Logique — Sévérité : 🟠 Haute — Résultats du scan :** le rapport contient uniquement les vulnérabilités réellement détectées dans les manifestes analysés, sans reprendre toute la base locale.
- **ISSUE-003 — Type : Sécurité — Sévérité : 🟠 Haute — Client OSV :** ajout de timeouts de connexion et de requête, ainsi que d'une limite de taille appliquée aux réponses HTTP normales et aux réponses d'erreur.
- **ISSUE-004 — Type : Sécurité — Sévérité : 🟠 Haute — Intégrité de la base :** les bases locales nécessitent un manifeste d'intégrité et une signature Ed25519 valides avant le chargement des advisories.
- **ISSUE-005 — Type : Fonctionnel — Sévérité : 🟠 Haute — Versions affectées :** prise en charge des bornes `introduced`, `fixed`, `patched` et `unaffected`, y compris pour plusieurs plages disjointes. Les contraintes Python ouvertes ou non résolubles sont signalées `À VÉRIFIER`.
- **ISSUE-006 — Type : Sécurité — Sévérité : 🟠 Haute — Base absente ou vide :** une base manquante, vide, non signée ou incohérente est refusée avant le scan.
- **ISSUE-007 — Type : Sécurité — Sévérité : 🟠 Haute — Dépendances NPM :** le parcours est itératif et limité en profondeur et en nombre de nœuds afin d'éviter les traitements excessifs.
- **ISSUE-008 — Type : Sécurité — Sévérité : 🟡 Moyenne — Fichiers de base volumineux :** les fichiers d'advisories dépassant la limite autorisée sont refusés avant leur lecture complète.
- **ISSUE-009 — Type : Logique — Sévérité : 🟠 Haute — Racine de projet :** le confinement du parcours utilise la racine effectivement retenue lorsque le projet est détecté depuis un sous-répertoire.
- **ISSUE-010 — Type : Logique — Sévérité : 🟡 Moyenne — Sortie JSON :** les diagnostics sont séparés de `stdout`; les rapports JSON restent parseables par les outils CI/CD.
- **ISSUE-011 — Type : Performance — Sévérité : 🟠 Haute — Mise à jour :** les bundles signés OSV ou hébergés sur GitHub sont téléchargés avec limites, contrôlés, validés puis installés atomiquement sans remplacer une base existante en cas d'échec.
- **ISSUE-012 — Type : Performance — Sévérité : 🟠 Haute — Configuration du scan :** les limites de profondeur et de taille, les exclusions, les manifestes, le chemin de base et le nombre de threads configurés sont appliqués.
- **ISSUE-013 — Type : Performance — Sévérité : 🟡 Moyenne — Benchmarks :** les benchmarks utilisent désormais le parsing et le scan de production sur des fixtures déterministes.
- **ISSUE-014 — Type : Performance — Sévérité : 🟡 Moyenne — Parcours filesystem :** les chemins de répertoires sont canonicalisés une seule fois lorsque cela est possible, tout en conservant les contrôles de confinement et de liens symboliques.
- **ISSUE-015 — Type : Tests — Sévérité : 🟡 Moyenne — Regroupement :** les tests de scan redondants sont regroupés dans une suite cohérente.
- **ISSUE-016 — Type : Tests — Sévérité : 🟡 Moyenne — Couverture CLI :** le parsing Clap réel et l'exécution du binaire sont testés au-delà de la construction manuelle de structures.
- **ISSUE-017 — Type : Tests — Sévérité : 🟡 Moyenne — Erreurs de parsing :** les erreurs inattendues ne sont plus masquées par des valeurs par défaut dans les tests.
- **ISSUE-018 — Type : Tests — Sévérité : 🟡 Moyenne — Portabilité :** un job CI Windows couvre les comportements spécifiques aux liens symboliques et aux permissions.
- **ISSUE-019 — Type : Documentation — Sévérité : 🟢 Mineure — Statut public :** les limites et le statut réel des fonctionnalités sont documentés sans revendiquer de performances ou de compatibilité non mesurées.

### Correctifs de stabilisation

- **CLI sans sous-commande :** le comportement Clap est couvert par un test ; l'aide s'affiche et le code 2 est conservé lorsqu'aucune commande n'est fournie.
- **Exclusion de la base locale :** `vulnera_db` est ignoré par défaut pendant le parcours du projet afin que ses nombreux fichiers ne soient pas traités comme des manifestes à scanner.
- **Compatibilité des advisories :** les lignes legacy `aliases = @(...)` sont normalisées en mémoire avant parsing, sans modifier les fichiers ni contourner leur vérification d'intégrité.
- **Progression CLI :** le chargement de la base puis le scan disposent chacun d'un spinner placé à droite du texte ; les logs détaillés restent disponibles en mode debug.

### Limites publiques restantes

- Les contraintes Python ouvertes ou non résolubles ne permettent pas de déduire une version installée avec certitude et restent donc `À VÉRIFIER`.
- Les résultats de benchmarks dépendent de la machine et du système de fichiers utilisés.
- Le chargement de la base locale reste long avec un corpus de très grande taille ; un fichier EEF/OSV non conforme est actuellement signalé puis ignoré.

---

## 🇬🇧 Correction Alpha Release (v0.6.9-alpha)

**Date:** 2026-09-08  
**Status:** technically validated locally; public publication remains pending.

This release groups the stabilization fixes and quality validation completed
before a public release. It is not a final release yet: `vulnera_db` must still
be prepared, validated, and signed with its integrity manifest before
publication.

### Included corrections

- Removed unnecessary mutability from Rust tests.
- Removed unnecessary `&mut SecurityManager` arguments passed to `scan_repo`.
- Removed a redundant borrow in filesystem traversal.
- Kept mutability only where the API genuinely requires it.
- Updated public documentation for CLI commands, actual benchmarks, and the
  database preparation/signing workflow.

### Alpha validation

- `cargo fmt --all -- --check`: success.
- `cargo clippy --all-targets --all-features -- -D warnings`: success, no warnings.
- `cargo test --all-targets --all-features`: success.
- `cargo check --all-targets --all-features`: success.
- `cargo build --all-targets --all-features`: success.
- `cargo build --release --all-features`: success.
- `cargo bench --no-run --all-features`: success.
- Production benchmark groups executed successfully.

### Remaining pre-publication work

- Fix or remove invalid advisories from the local database.
- Regenerate `.integrity_manifest` with `saferepo-prepare-database`.
- Sign the manifest with the private key kept outside the repository.
- Verify that the embedded public key matches the release key.
  **Status:** audit fixes applied; release publication is still being prepared.

### Current bug and issue fixes

**Severity legend:** 🔴 Critical · 🟠 High · 🟡 Medium · 🟢 Minor.

- **ISSUE-001 — Type: Functional — Severity: 🟠 High — CLI execution:** Clap commands and options now reach the real execution path instead of always scanning the current directory.
- **ISSUE-002 — Type: Logic — Severity: 🟠 High — Scan results:** reports contain only vulnerabilities actually detected in scanned manifests, rather than the entire local database.
- **ISSUE-003 — Type: Security — Severity: 🟠 High — OSV client:** connection and request timeouts are enforced, with response-size limits applied to both successful and error responses.
- **ISSUE-004 — Type: Security — Severity: 🟠 High — Database integrity:** local databases require a valid integrity manifest and Ed25519 signature before advisories are loaded.
- **ISSUE-005 — Type: Functional — Severity: 🟠 High — Affected versions:** `introduced`, `fixed`, `patched`, and `unaffected` bounds are supported, including multiple disjoint ranges. Open or unresolved Python constraints are reported as `À VÉRIFIER`.
- **ISSUE-006 — Type: Security — Severity: 🟠 High — Missing or empty database:** missing, empty, unsigned, or inconsistent databases are rejected before scanning.
- **ISSUE-007 — Type: Security — Severity: 🟠 High — NPM dependencies:** traversal is iterative and bounded by depth and node-count limits.
- **ISSUE-008 — Type: Security — Severity: 🟡 Medium — Oversized database files:** advisory files above the allowed limit are rejected before full reading.
- **ISSUE-009 — Type: Logic — Severity: 🟠 High — Project root:** traversal confinement uses the root actually selected when scanning from a subdirectory.
- **ISSUE-010 — Type: Logic — Severity: 🟡 Medium — JSON output:** diagnostics are separated from `stdout`, keeping JSON reports parseable by CI/CD tools.
- **ISSUE-011 — Type: Performance — Severity: 🟠 High — Updates:** signed OSV bundles or bundles hosted on GitHub are bounded, checked, validated, and installed atomically without replacing an existing database on failure.
- **ISSUE-012 — Type: Performance — Severity: 🟠 High — Scan configuration:** depth and file-size limits, exclusions, manifest selection, database path, and configured thread count are applied.
- **ISSUE-013 — Type: Performance — Severity: 🟡 Medium — Benchmarks:** benchmarks now exercise production parsing and scanning paths with deterministic fixtures.
- **ISSUE-014 — Type: Performance — Severity: 🟡 Medium — Filesystem traversal:** directory paths are canonicalized once where possible while confinement and symbolic-link checks remain active.
- **ISSUE-015 — Type: Testing — Severity: 🟡 Medium — Consolidation:** overlapping scan tests are grouped into a coherent suite.
- **ISSUE-016 — Type: Testing — Severity: 🟡 Medium — CLI coverage:** real Clap parsing and binary execution are tested beyond manual structure construction.
- **ISSUE-017 — Type: Testing — Severity: 🟡 Medium — Parsing errors:** unexpected errors are no longer hidden behind default values in tests.
- **ISSUE-018 — Type: Testing — Severity: 🟡 Medium — Portability:** a Windows CI job covers behavior specific to symbolic links and permissions.
- **ISSUE-019 — Type: Documentation — Severity: 🟢 Minor — Public status:** feature status and limitations are documented without claiming unmeasured performance or compatibility.

### Stabilization fixes

- **CLI without a subcommand:** Clap behavior is covered by a test; help is shown and exit code 2 remains intentional when no command is provided.
- **Local database exclusion:** `vulnera_db` is ignored by default while traversing the project, so its many files are not treated as project manifests.
- **Advisory compatibility:** legacy `aliases = @(...)` lines are normalized in memory before parsing, without modifying files or bypassing integrity verification.
- **CLI progress:** database loading and scanning each have a spinner positioned to the right of the message; detailed logs remain available in debug mode.

### Remaining public limitations

- Open or unresolved Python constraints cannot identify an installed version with certainty and remain `À VÉRIFIER`.
- Benchmark results depend on the machine and filesystem used.
- Loading remains slow for the very large local corpus; one non-conforming EEF/OSV file is currently reported and skipped.

---

## 🇫🇷 Version Française (v0.6.51)

**Objectif :** Stabiliser les correctifs mineurs, renforcer le parsing des manifests et améliorer l'expérience CLI.

### 🎯 Correctifs & Améliorations

- **Gestion d'erreurs améliorée :** Messages utilisateurs explicites et conversions d'erreurs centralisées sur les chemins couverts. L'inventaire exhaustif de `panic!`, `unwrap()` et `expect()` reste hors du périmètre de cette note.
- **Parsers :** Implémentation du parseur `package.json` et renforcement du traitement de `Cargo.toml` (acceptation des versions courtes et normalisation SemVer).
- **UX CLI :** Ajout d'un spinner / barre de progression pour les scans longs, sorties colorées en console (`colored`) et rapport final enrichi (stats détaillées).
- **Tests :** Ajout de tests unitaires et d'intégration pour les parseurs et le moteur de scan; les résultats de validation sont consignés dans le rapport de correction.
- **CI & Performance :** Optimisations ciblées du scanner (filtrage de manifestes, limites de taille/profondeur). Les benchmarks de production et la validation CI complète restent à finaliser.

---

## 🇬🇧 English Version (v0.6.51)

**Goal:** Stabilize minor fixes, harden manifest parsing and improve CLI UX.

### 🎯 Fixes & Improvements

- **Improved error handling:** clearer user-facing messages and centralized error conversions on covered paths. An exhaustive inventory of `panic!`, `unwrap()`, and `expect()` is outside this note's scope.
- **Parsers:** implemented `package.json` parser and strengthened `Cargo.toml` handling (accept short versions and SemVer normalization).
- **CLI UX:** added spinner/progress indicator, colored terminal output (`colored` crate) and an enriched final statistics report.
- **Tests:** added unit and integration tests for parsers and the scanning engine; validation results are recorded in the correction report.
- **CI & Performance:** targeted scanner optimizations (manifest filtering, size/depth limits). Production benchmarks and complete CI validation remain pending.

---

## 🇫🇷 Version Française (v0.6.5)

**Objectif :** Professionnaliser l'interface CLI et améliorer l'expérience développeur avec logging avancé, configuration centralisée et outputs structurés pour intégration CI/CD.

### 🎯 CLI & Interface (English)

⚠️ **Note :** CLI en version test - Stabilisation en cours pour v0.7.0

- **CLI avec Clap :** Structure professionnelle avec sous-commandes organisées.
  - `saferepo scan <path>` → Scanner un projet complet
  - `saferepo check <file>` → Vérifier un seul fichier manifeste
  - `saferepo update` → Synchronisation différentielle d'un bundle signé; seuls les advisories nouveaux ou modifiés sont téléchargés
  - `--help` et `--version` fonctionnels et détaillés
  - Support des flags globaux (`--verbose`, `--config`, etc.)

### 📝 Logging & Output (English)

- **Logging Structuré :** Intégration crate `log` + `env_logger`
  - Console avec niveaux (DEBUG, INFO, WARN, ERROR)
  - Format standardisé avec timestamp et module
  - Contrôle via variable d'environnement `RUST_LOG`

- **Output JSON :** Format structuré pour intégration CI/CD
  - Sortie JSON valide pour les commandes couvertes par les tests
  - Diagnostics séparés sur `stderr`
  - Schéma documenté par les sorties du CLI; compatibilité webhook non encore validée

### ⚙️ Configuration (English)

- **Configuration System :** Fichier `.saferepo.toml` centralisé
  - `ignore_patterns` → Chemins à ignorer lors du scan
  - `min_severity` → Niveau minimum de sévérité (low, medium, high, critical)
  - `skip_code_scan` → Option acceptée; le scanner actuel analyse uniquement les manifestes
  - Merge stratégies (CLI flags > config file > defaults)
  - Validation des valeurs prises en charge à la lecture

### 📊 Changements par rapport à v0.6.0

| Feature                    | v0.6.0 | v0.6.5              | Statut  |
| -------------------------- | ------ | ------------------- | ------- |
| CLI avec Clap              | ❌     | ✅                  | NOUVEAU |
| Logging Structuré          | ❌     | ✅ (log+env_log)    | NOUVEAU |
| Output JSON                | ❌     | ✅                  | NOUVEAU |
| Configuration System       | ❌     | ✅ (.saferepo.toml) | NOUVEAU |
| Sub-commandes (scan/check) | ❌     | ✅                  | NOUVEAU |

---

## 🇬🇧 English Version (v0.6.5)

**Goal:** Professionalize CLI interface and improve developer experience with advanced logging, centralized configuration, and structured outputs for CI/CD integration.

### 🎯 CLI & Interface

⚠️ **Note:** CLI under testing - Stabilization in progress for v0.7.0

- **CLI with Clap :** Professional structure with organized sub-commands.
  - `saferepo scan <path>` → Scan a complete project
  - `saferepo check <file>` → Verify a single manifest file
  - `saferepo update` → Differential synchronization of a signed bundle; only new or changed advisories are downloaded
  - `--help` and `--version` functional and detailed
  - Support for global flags (`--verbose`, `--config`, etc.)

### 📝 Logging & Output

- **Structured Logging :** Integration of `log` crate + `env_logger`
  - Console with levels (DEBUG, INFO, WARN, ERROR)
  - Standardized format with timestamp and module
  - Control via `RUST_LOG` environment variable

- **JSON Output :** Structured format for CI/CD integration
  - Valid JSON output for commands covered by tests
  - Diagnostics separated on `stderr`
  - Schema is documented by CLI output; webhook compatibility is not yet validated

### ⚙️ Configuration

- **Configuration System :** Centralized `.saferepo.toml` file
  - `ignore_patterns` → Paths to ignore during scan
  - `min_severity` → Minimum severity level (low, medium, high, critical)
  - `skip_code_scan` → Accepted option; the current scanner analyzes manifests only
  - Merge strategies (CLI flags > config file > defaults)
  - Validation of supported values on read

### 📊 Changes vs v0.6.0

| Feature                   | v0.6.0 | v0.6.5              | Status |
| ------------------------- | ------ | ------------------- | ------ |
| CLI with Clap             | ❌     | ✅                  | NEW    |
| Structured Logging        | ❌     | ✅ (log+env_log)    | NEW    |
| JSON Output               | ❌     | ✅                  | NEW    |
| Configuration System      | ❌     | ✅ (.saferepo.toml) | NEW    |
| Sub-commands (scan/check) | ❌     | ✅                  | NEW    |

---

## 🇫🇷 Version Française (v0.6.0)

**Objectif historique :** Durcissement de sécurité MVP et stabilisation des fondations. Cette version n'était pas destinée à un usage de production.

### 🔐 Sécurité & Intégrité

- **Path Traversal Protection :** Implémentation complète de `canonicalize()` pour valider strictement tous les chemins de fichiers. Prévention des attaques par remontée de répertoires (`../`).
- **Root Validation :** Détection automatique et validation de la racine du projet via marqueurs `.root_markers` (Cargo.toml, package.json, go.mod, pom.xml, Gemfile, composer.json, pubspec.yaml).
- **TOML Strict Validation :** Les advisory TOML malformés sont rejetés avec une erreur explicite.
- **Database Integrity (SHA-256) :** Vérification d'intégrité cryptographique pour tous les fichiers de vulnérabilités. Struct `FileIntegrity` + `DatabaseAudit` pour traçabilité complète.
- **Gestion d'erreurs :** Introduction de `SafeRepoError` et amélioration de la propagation des erreurs sur les chemins couverts.

### 🧠 Parseurs Multi-Langage

- **Cargo.lock (Rust)** : Parsing TOML des blocs `[[package]]` et matching SemVer.
- **package-lock.json (Node.js/NPM)** : Prise en charge bornée de l'arborescence de dépendances.
- **requirements.txt (Python/PIP)** : Les versions `==` sont analysées; les contraintes combinées et opérateurs reconnus sont conservés et signalés `À VÉRIFIER` lorsqu'ils ne permettent pas de connaître la version installée.
- **go.mod (Go)** : Parsing des directives `require` et `replace` avec gestion des commentaires et des blocs multi-lignes.

### 🔍 Moteur de Scan Amélioré

- **Manifest Auto-Detection :** Détection ciblée des formats de manifestes actuellement pris en charge.
- **Filtered Output :** Comptage et rapport détaillé des fichiers ignorés, traversés et analysés.

### ✅ Tests & Qualité

- **Tests automatisés :** Couverture de chemins DB, scan, parseurs, erreurs et intégration :
  - Fonctionnalité DB (testdb.rs)
  - Scanner engine (testscan.rs)
  - Parseurs multi-formats (testsecurity.rs)
  - Gestion d'erreurs (testerror.rs)
  - Workflows complets (integration.rs)
- **Validation :** Les résultats de tests sont consignés dans le rapport de correction; aucun seuil global de couverture n'est revendiqué.

### 📚 Documentation (Français)

- **README.md :** Installation, usage, limites et formats actuellement documentés.
- **AGENT_BRIEFING.md :** Base de connaissances pour les agents (mise à jour May 8, 2026).
- **Inline Comments :** Documentation des sections critiques dans le code source.

### 📊 Changements par rapport à v0.5.5

| Feature                 | v0.5.5    | v0.6.0                     | Statut   |
| ----------------------- | --------- | -------------------------- | -------- |
| Path Traversal Security | ❌        | ✅                         | NOUVEAU  |
| Root Validation         | ❌        | ✅                         | NOUVEAU  |
| SHA-256 DB Integrity    | ❌        | ✅                         | NOUVEAU  |
| Error System (Custom)   | Basique   | ✅ Complet                 | AMÉLIORÉ |
| Parseurs (1→4 formats)  | 1 (Cargo) | 4 (Cargo, NPM, Python, Go) | ÉTENDU   |
| Tests                   | <30       | 43+                        | AUGMENTÉ |
| Gestion d'erreurs       | Basique   | Améliorée                  | ÉVOLUTIF |

---

## 🇬🇧 English Version (v0.6.0)

**Historical goal:** MVP security hardening and foundation stabilization. This version was not intended for production use.

### 🔐 Security & Integrity

- **Path Traversal Protection:** Full implementation of `canonicalize()` with strict validation for all file paths. Prevents directory traversal attacks (`../`).
- **Root Validation:** Automatic detection and validation of project root via `.root_markers` (Cargo.toml, package.json, go.mod, pom.xml, Gemfile, composer.json, pubspec.yaml).
- **TOML Strict Validation:** Malformed advisory TOML files are rejected with an explicit error.
- **Database Integrity (SHA-256):** Cryptographic integrity verification for all vulnerability database files. `FileIntegrity` struct + `DatabaseAudit` for full traceability.
- **Error handling:** Introduced `SafeRepoError` and improved error propagation on covered paths.

### 🧠 Multi-Language Parsers

- **Cargo.lock (Rust):** TOML parsing of `[[package]]` blocks and SemVer matching.
- **package-lock.json (Node.js/NPM):** Bounded dependency-tree handling.
- **requirements.txt (Python/PIP):** Explicit `==` pins are analyzed; open constraints remain to be resolved.
- **go.mod (Go):** `require` and `replace` directive parsing with comment and multi-line block handling.

### 🔍 Enhanced Scanning Engine

- **Manifest Auto-Detection:** Targeted detection of currently supported manifest formats.
- **Filtered Output:** Detailed reporting of ignored, traversed, and analyzed files.

### ✅ Testing & Quality

- **Automated tests:** Coverage of database, scan, parser, error, and integration paths:
  - DB functionality (testdb.rs)
  - Scanner engine (testscan.rs)
  - Multi-format parsers (testsecurity.rs)
  - Error handling (testerror.rs)
  - Complete workflows (integration.rs)
- **Validation:** Test results are recorded in the correction report; no complete-coverage threshold is claimed.

### 📚 Documentation

- **README.md:** Currently documented installation, usage, limits, and formats.
- **AGENT_BRIEFING.md:** Knowledge base for agents (updated May 8, 2026).
- **Inline Comments:** Critical sections documented in source code.

### 📊 Changes vs v0.5.5

| Feature                 | v0.5.5    | v0.6.0                     | Status    |
| ----------------------- | --------- | -------------------------- | --------- |
| Path Traversal Security | ❌        | ✅                         | NEW       |
| Root Validation         | ❌        | ✅                         | NEW       |
| SHA-256 DB Integrity    | ❌        | ✅                         | NEW       |
| Error System (Custom)   | Basic     | ✅ Complete                | IMPROVED  |
| Parsers (1→4 formats)   | 1 (Cargo) | 4 (Cargo, NPM, Python, Go) | EXTENDED  |
| Tests                   | <30       | 43+                        | INCREASED |

---

## 🇫🇷 Version Version Française (v0.5.5)

**Objectif :** Durcissement de la sécurité du moteur de scan, protection contre les fichiers volumineux et gestion de la profondeur d'arborescence.

### 🛡️ Sécurité & Robustesse du Fonctionnement

- **Limite de Taille (Protection RAM) :** Introduction d'un plafond de sécurité à **2 Mo** par fichier. Cette mesure empêche la saturation de la mémoire vive (RAM) par des fichiers géants ou des données binaires imprévues.
- **Limite de Profondeur (Anti-DoS) :** Plafond fixé à **40 niveaux** de dossiers. Cela protège l'outil contre les structures de dossiers infinies ou les "bombes de répertoires" malveillantes.

### 🚀 Optimisation du Scan

- **Filtrage de Fichier Ciblé :** Le scanner n'ouvre et ne lit désormais que les fichiers manifestes reconnus (`Cargo.lock`, `package.json`, etc.). Cela offre un gain de performance majeur sur les projets contenant des milliers d'images, de vidéos ou de binaires.

### ✨ Expérience Utilisateur (UX)

- **Rapport de Filtrage Détaillé :** Affichage explicite en fin de scan des éléments ignorés pour cause de profondeur excessive ou de taille trop importante.

---

## 🇬🇧 English Version (v0.5.5)

**Goal:** Scanner security hardening, protection against large files, and directory depth management.

### 🛡️ Operational Security & Robustness

- **Size Limitation (RAM Protection):** Introduced a **2 MB** safety cap per file. This prevents RAM saturation from giant files or unexpected binary data.
- **Depth Limitation (Anti-DoS):** Depth ceiling set at **40 levels**. Protects the tool against malicious infinite directory structures or "directory bombs."

### 🚀 Scan Optimization

- **Targeted File Filtering:** The scanner opens and reads recognized manifest files (`Cargo.lock`, `package.json`, etc.), reducing unnecessary reads. The performance impact has not been measured by a production benchmark.

### ✨ User Experience (UX)

- **Detailed Filtering Report:** Explicit display of folders or files ignored due to excessive depth or oversized limits.

---

## 🇫🇷 Version Française (v0.5)

**Objectif :** Architecture modulaire professionnelle, parsing hiérarchique et accès direct O(1).

### 🏗️ Architecture & Modularité (Refonte)

- **Découplage Logique :** Extraction du code monolithique vers une structure multi-fichiers :
  - `db.rs` : Gestion exclusive de la base de données (chargement, stockage, parsing).
  - `security.rs` : Moteur d'analyse et logique de reporting.
- **Modèle de Données :** Introduction du bridge `VulnerabilityFile` pour réconcilier le format physique TOML et la représentation mémoire.

### 🧠 Intelligence et Parsing

- **Parsing Hiérarchique :** Prise en charge des blocs TOML standardisés `[advisory]` et `[versions]`.
- **Analyse SemVer :** Intégration profonde de `VersionReq` pour gérer des plages de correctifs complexes (ex: `>=1.2.0, <2.0.0`).
- **Performance O(1) :** Migration vers une `HashMap` indexée par nom de package. La vitesse de recherche est désormais constante.

---

## 🇬🇧 English Version (v0.5)

**Goal:** Professional modular architecture, hierarchical parsing, and O(1) direct access.

### 🏗️ Architecture & Modularity (Overhaul)

- **Logical Decoupling:** Monolithic code extracted into a multi-file structure (`db.rs`, `security.rs`).
- **Data Modeling:** Introduced the `VulnerabilityFile` bridge to reconcile TOML format with memory representation.

### 🧠 Intelligence & Parsing

- **Hierarchical Parsing:** Handling of standardized `[advisory]` and `[versions]` TOML blocks.
- **SemVer Analysis:** Deep `VersionReq` integration for complex patch ranges.
- **O(1) Performance:** Migrated internal storage to a package-indexed `HashMap` for constant search time.

---

## 🇫🇷 Version Française (v0.3)

**Objectif :** Sécurisation du moteur de scan, filtrage intelligent et optimisation des performances.

### 🛡️ Sécurité & Robustesse

- **Correction Critique (DoS) :** Passage à une **pile itérative (Stack-based)** pour éliminer le risque de Stack Overflow.
- **Correction Moyenne (Intégrité) :** Gestion d'erreurs non-bloquante (`match`) pour éviter l'arrêt brutal du scan.

### 🚀 Performances & Nouveautés

- **Filtrage Intelligent :** Exclusion automatique des répertoires lourds (`node_modules`, `target`, `.git`).
- **Throttling d'affichage (100ms) :** Limite la fréquence de rafraîchissement du terminal; le gain CPU n'est pas encore mesuré par un benchmark de production.

---

## 🇬🇧 English Version (v0.3)

**Goal:** Secure the scanning engine, implement smart filtering, and optimize performance.

### 🛡️ Security & Robustness

- **Critical Fix (DoS):** Switched to an iterative stack-based architecture to eliminate Stack Overflow risks.
- **Medium Fix (Integrity):** Non-blocking error handling (`match`) to prevent scan interruption.

### 🚀 Performance & Features

- **Smart Filtering:** Automatic exclusion of heavy directories (`node_modules`, `target`, `.git`).
- **Display Throttling (100ms):** Limits terminal refresh frequency; the CPU gain has not yet been measured by a production benchmark.

---

**Dernière mise à jour** : 2026-09-04
**Last Updated**: 2026-09-04
