# 🛡️ SafeRepo CLI

**[Français](#-documentation-française) | [English](#-english-documentation)**

---

## 🇫🇷 Documentation Française

### 📋 Aperçu

**SafeRepo CLI** est un scanner de vulnérabilités multi-langage conçu pour détecter les dépendances vulnérables dans vos projets. Développé en Rust, il analyse les manifestes de dépendances avec des limites de ressources explicites.

### ✨ Fonctionnalités

- ✅ **Multi-langage** : Analyse Cargo, NPM, Python et Go selon les formats documentés
- ✅ **Limites de ressources** : Taille des manifestes et profondeur de parcours bornées
- ✅ **Gestion d'erreurs** : Les erreurs de scan sont retournées avec leur contexte
- ✅ **Intégrité DB** : Manifeste et signature Ed25519 requis pour une base locale
- ✅ **Path Traversal Protection** : Validation stricte des chemins avec `canonicalize()`
- ✅ **Tests automatisés** : Tests unitaires et d'intégration pour les comportements critiques
- ✅ **Symlinks Support** : Ignoration sécurisée des liens symboliques

### 📦 Parseurs Supportés

| Langage        | Fichier Manifeste   | Statut    | Format          |
| -------------- | ------------------- | --------- | --------------- |
| 🦀 Rust        | `Cargo.lock`        | ✅ Stable | TOML            |
| 🦀 Rust        | `Cargo.toml`        | ✅ Stable | TOML            |
| 📦 Node.js/NPM | `package-lock.json` | ✅ Stable | JSON            |
| 📦 Node.js/NPM | `package.json`      | ✅ Stable | JSON            |
| 🐍 Python      | `requirements.txt`  | ✅ Stable | TXT             |
| 🔵 Go          | `go.mod`            | ✅ Stable | Require/Replace |

### 🚀 Installation Rapide

#### Via Cargo (Méthode Recommandée)

```bash
# Installation depuis les sources
git clone https://github.com/TitanFR25/SafeRepo_CLI.git
cd SafeRepo_CLI
cargo install --path .

# Ou directement depuis crates.io (à venir)
cargo install saferepo
```

#### Prérequis

- **Rust** 1.85+ ([installer Rust](https://rustup.rs/))
- **Cargo** (livré avec Rust)
- **Droits administrateur** (pour les symlinks sur Windows)

### 🔒 Sécurité

#### Limits et Protections

| Limite             | Valeur     | Raison                           |
| ------------------ | ---------- | -------------------------------- |
| Taille max fichier | 2 Mo       | Éviter saturation RAM            |
| Profondeur max     | 40 niveaux | Prévention attaques DoS          |
| Symlinks           | Ignorés    | Éviter boucles infinies          |
| Path Traversal     | Bloqué     | Validation avec `canonicalize()` |

#### Validation Racine Projet

Le scanner détecte automatiquement la racine valide du projet en cherchant les marqueurs :

- `Cargo.toml` (Rust)
- `package.json` (Node.js)
- `requirements.txt` (Python)
- `go.mod` (Go)
- `pom.xml` (Java/Maven)
- `Gemfile` (Ruby)
- `composer.json` (PHP)

### 📊 Dossiers Ignorés par Défaut

Pour optimiser les performances, ces dossiers sont automatiquement ignorés :

```text
.git, node_modules, target, build, dist, vendor, .cache, vulnera_db
```

`vulnera_db` est exclu du parcours du projet, mais il est chargé séparément
comme base de référence des advisories.

### 🖥️ Utilisation CLI

```bash
# Afficher l'aide
cargo run --release -- --help

# Scanner le répertoire courant
cargo run --release -- scan .

# Vérifier un manifeste précis
cargo run --release -- check Cargo.lock

# Afficher la configuration
cargo run --release -- config --show-path
```

La commande `scan` charge d'abord la base locale, puis parcourt le projet.
Avec un corpus très volumineux, le chargement de la base peut prendre du temps.

### 🧪 Tests

```bash
# Exécuter tous les tests
cargo test

# Tests spécifiques
cargo test test_scan_ignores_symlinks
cargo test test_parse_package_lock_json_valide

# Avec output détaillé
cargo test -- --nocapture
```

La suite couvre notamment les limites de scan, les parseurs supportés, la DB signée et les sorties CLI JSON. Les seuils de couverture ne sont pas encore publiés.

### 🔧 Développement

#### Compiler en Mode Debug

```bash
cargo build
```

#### Compiler en Mode Release (Optimisé)

```bash
cargo build --release
```

#### Vérifier les Erreurs de Compilation

```bash
cargo check
```

### 📝 Format Fichiers Vulnérabilités

Les fichiers de vulnérabilités doivent être au format TOML avec la structure suivante :

```toml
[advisory]
id = "CVE-2024-12345"
package = "library-x"
severity = "critical"
title = "Critical issue in library X"
description = "Describe the affected package and remediation."

[versions]
patched = ["1.5.0"]
```

Une base destinée à une release doit contenir uniquement des fichiers valides,
être accompagnée de `.integrity_manifest` et de
`.integrity_manifest.sig`, puis être signée avec la clé privée de release.
La clé privée ne doit jamais être ajoutée au dépôt.

### 📄 Licence

Distribué sous licence MIT. Voir [LICENSE](LICENSE) pour plus de détails.

---

## 🇬🇧 English Documentation

### 📋 Overview

**SafeRepo CLI** is a high-performance multi-language vulnerability scanner designed to detect vulnerable dependencies in your projects. Built in Rust, it provides fast and reliable analysis of dependency manifests.

### ✨ Features

- ✅ **Multi-language** : Cargo, NPM, Python, and Go analysis for documented formats
- ✅ **Resource limits** : Manifest size and traversal depth are bounded
- ✅ **Error handling** : Scan errors are returned with context
- ✅ **Database integrity** : An Ed25519-signed manifest is required for a local database
- ✅ **Path Traversal Protection** : Strict path validation with `canonicalize()`
- ✅ **Automated tests** : Unit and integration coverage for critical behavior
- ✅ **Symlinks Support** : Safe handling of symbolic links

### 📦 Supported Parsers

| Language       | Manifest File       | Status    | Format          |
| -------------- | ------------------- | --------- | --------------- |
| 🦀 Rust        | `Cargo.lock`        | ✅ Stable | TOML            |
| 📦 Node.js/NPM | `package-lock.json` | ✅ Stable | JSON            |
| 🐍 Python      | `requirements.txt`  | ✅ Stable | TXT             |
| 🔵 Go          | `go.mod`            | ✅ Stable | Require/Replace |

### 🚀 Quick Start

#### Via Cargo

```bash
# Install from sources
git clone https://github.com/TitanFR25/SafeRepo_CLI.git
cd SafeRepo_CLI
cargo install --path .

# Or directly from crates.io (coming soon)
cargo install saferepo
```

#### Prerequisites

- **Rust 1.85+** ([Install Rust](https://rustup.rs/))
- **Cargo** (included with Rust)
- **Administrator rights** (for symlinks on Windows)

### 🔒 Security

#### Limits and Protections

| Limit          | Value     | Reason                           |
| -------------- | --------- | -------------------------------- |
| Max file size  | 2 MB      | Prevent RAM saturation           |
| Max depth      | 40 levels | DOS attack prevention            |
| Symlinks       | Ignored   | Prevent infinite loops           |
| Path Traversal | Blocked   | Validation with `canonicalize()` |

#### Project Root Detection

Scanner automatically detects valid project root by searching for markers:

- `Cargo.toml` (Rust)
- `package.json` (Node.js)
- `requirements.txt` (Python)
- `go.mod` (Go)

### 📊 Default Ignored Directories

For performance optimization, these directories are automatically ignored:

```text
.git, node_modules, target, build, dist, vendor, .cache, vulnera_db
```

`vulnera_db` is excluded from project traversal but loaded separately as the
reference advisory database.

### 🖥️ CLI Usage

```bash
# Show help
cargo run --release -- --help

# Scan the current directory
cargo run --release -- scan .

# Check one manifest
cargo run --release -- check Cargo.lock

# Show the active configuration path
cargo run --release -- config --show-path
```

The `scan` command loads the local database before traversing the project. A
very large advisory corpus can therefore take time to load.

### 🧪 Testing

```bash
# Run all tests
cargo test

# Run specific tests
cargo test test_scan_ignores_symlinks
cargo test test_parse_package_lock_json_valide

# With detailed output
cargo test -- --nocapture
```

The suite covers scan limits, supported parsers, signed databases, and JSON CLI output. Coverage thresholds are not yet published.

### 🔧 Development

#### Compile in Debug Mode

```bash
cargo build
```

#### Compile in Release Mode (Optimized)

```bash
cargo build --release
./target/release/SafeRepo_CLI scan /path
```

#### Check for Compilation Errors

```bash
cargo check
```

### 📝 Vulnerability File Format

Vulnerability files must be in TOML format with the following structure:

```toml
[advisory]
id = "CVE-2024-12345"
package = "library-x"
severity = "critical"
title = "Critical issue in library X"
description = "Describe the affected package and remediation."

[versions]
patched = ["1.5.0"]
```

A release database must contain only valid advisory files and include
`.integrity_manifest` and `.integrity_manifest.sig` generated and signed with
the release private key. The private key must never be committed.

#### Préparer et signer une base

Le dépôt fournit un outil de préparation qui valide chaque fichier TOML,
refuse les fichiers trop volumineux, écrit un manifeste déterministe et retire
une signature devenue obsolète :

```bash
cargo run --release --bin saferepo-prepare-database -- vulnera_db
cargo run --release --bin saferepo-sign-manifest -- C:\chemin\hors depot\saferepo-release.key vulnera_db
```

La clé publique correspondant à la clé privée doit être intégrée dans
`src/database/db.rs`. Après la signature, ne modifiez plus aucun fichier TOML
ni le manifeste. Vérifiez ensuite avec `cargo run --release -- scan .` et
publiez uniquement les fichiers de base, le manifeste et sa signature.

### 📄 License

Distributed under MIT License. See [LICENSE](LICENSE) for details.

---

**Made with Rust** | **v0.6.9** | **Last Updated: 2026-09-08**
