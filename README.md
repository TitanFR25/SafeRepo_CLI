# 🛡️ SafeRepo CLI

**[Français](#-documentation-française) | [English](#-english-documentation)**

---

## 🇫🇷 Documentation Française

### 📋 Aperçu

**SafeRepo CLI** est un scanner de vulnérabilités multi-langage haute performance conçu pour détecter les dépendances vulnérables dans vos projets. Développé en Rust, il offre une analyse rapide et fiable des manifestes de dépendances.

### ✨ Fonctionnalités

- ✅ **Multi-langage** : Support complet Rust, Node.js/NPM, Python, Go
- ✅ **Haute performance** : Écrit en Rust pour une vitesse maximale
- ✅ **Sécurisé** : Zéro panic, gestion complète des erreurs
- ✅ **Intégrité DB** : Vérification SHA-256 de tous les fichiers de vulnérabilités
- ✅ **Path Traversal Protection** : Validation stricte des chemins avec `canonicalize()`
- ✅ **Tests Complets** : 43 tests unitaires et d'intégration
- ✅ **Symlinks Support** : Ignoration sécurisée des liens symboliques

### 📦 Parseurs Supportés

| Langage        | Fichier Manifeste   | Statut    | Format          |
| -------------- | ------------------- | --------- | --------------- |
| 🦀 Rust        | `Cargo.lock`        | ✅ Stable | TOML            |
| 📦 Node.js/NPM | `package-lock.json` | ✅ Stable | JSON            |
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

- **Rust** 1.70+ ([installer Rust](https://rustup.rs/))
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

```
.git, node_modules, target, build, dist, vendor, .cache
```

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

**Couverture de Tests:**

- ✅ 43 tests au total
- ✅ 6 tests d'intégration
- ✅ 16 tests base de données
- ✅ 5 tests gestion d'erreurs
- ✅ 10 tests scanner
- ✅ 9 tests analyse de sécurité

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
[[vulnerability]]
id = "CVE-2024-12345"
title = "Critical RCE in library X"
description = "Remote Code Execution vulnerability in package X versions < 1.5.0"
severity = "critical"
affected_versions = ["0.1.0", "0.2.0", "1.0.0", "1.4.9"]

[[vulnerability]]
id = "CVE-2024-12346"
title = "XSS in template engine"
description = "Cross-site scripting in template rendering"
severity = "high"
affected_versions = ["2.0.0", "2.1.0"]
```

### 📄 Licence

Distribué sous licence MIT. Voir [LICENSE](LICENSE) pour plus de détails.

---

## 🇬🇧 English Documentation

### 📋 Overview

**SafeRepo CLI** is a high-performance multi-language vulnerability scanner designed to detect vulnerable dependencies in your projects. Built in Rust, it provides fast and reliable analysis of dependency manifests.

### ✨ Features

- ✅ **Multi-language** : Full support for Rust, Node.js/NPM, Python, Go
- ✅ **High Performance** : Written in Rust for maximum speed
- ✅ **Secure** : Zero panics, complete error handling
- ✅ **Database Integrity** : SHA-256 verification for all vulnerability files
- ✅ **Path Traversal Protection** : Strict path validation with `canonicalize()`
- ✅ **Complete Tests** : 43 unit and integration tests
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

- **Rust** ([Install Rust](https://rustup.rs/))
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

```
.git, node_modules, target, build, dist, vendor, .cache
```

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

**Test Coverage:**

- ✅ 43 total tests
- ✅ 6 integration tests
- ✅ 16 database tests
- ✅ 5 error handling tests
- ✅ 10 scanner tests
- ✅ 9 security analysis tests

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
[[vulnerability]]
id = "CVE-2024-12345"
title = "Critical RCE in library X"
description = "Remote Code Execution vulnerability in package X versions < 1.5.0"
severity = "critical"
affected_versions = ["0.1.0", "0.2.0", "1.0.0", "1.4.9"]

[[vulnerability]]
id = "CVE-2024-12346"
title = "XSS in template engine"
description = "Cross-site scripting in template rendering"
severity = "high"
affected_versions = ["2.0.0", "2.1.0"]
```

### 📄 License

Distributed under MIT License. See [LICENSE](LICENSE) for details.

---

**Made with ❤️ in Rust** | **v0.6.0** | **Last Updated: May 2026**
