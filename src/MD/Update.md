# 📑 Saferepo Update Report / Rapport de Mise à jour

### ⚡ Shortcuts / Raccourcis

- [🇫🇷 Version Française (v0.5.5)](#-version-française-v055)
- [🇬🇧 English Version (v0.5.5)](#-english-version-v055)
- [🇫🇷 Version Française (v0.5)](#-version-française-v05)
- [🇬🇧 English Version (v0.5)](#-english-version-v05)
- [🇫🇷 Version Française (v0.3)](#-version-française-v03)
- [🇬🇧 English Version (v0.3)](#-english-version-v03)

---

## 🇫🇷 Version Française (v0.5.5)

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

- **Targeted File Filtering:** The scanner now only opens and reads recognized manifest files (`Cargo.lock`, `package.json`, etc.). This provides a major performance boost in projects containing thousands of images or binaries.

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

### 🧠 Intelligence & Parsing

- **Parsing Hiérarchique :** Support complet des blocs TOML standardisés `[advisory]` et `[versions]`.
- **Analyse SemVer :** Intégration profonde de `VersionReq` pour gérer des plages de correctifs complexes (ex: `>=1.2.0, <2.0.0`).
- **Performance O(1) :** Migration vers une `HashMap` indexée par nom de package. La vitesse de recherche est désormais constante.

---

## 🇬🇧 English Version (v0.5)

**Goal:** Professional modular architecture, hierarchical parsing, and O(1) direct access.

### 🏗️ Architecture & Modularity (Overhaul)

- **Logical Decoupling:** Monolithic code extracted into a multi-file structure (`db.rs`, `security.rs`).
- **Data Modeling:** Introduced the `VulnerabilityFile` bridge to reconcile TOML format with memory representation.

### 🧠 Intelligence & Parsing

- **Hierarchical Parsing:** Full support for standardized `[advisory]` and `[versions]` TOML blocks.
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
- **Throttling d'affichage (100ms) :** Réduit l'utilisation CPU de ~90% lors du rafraîchissement du terminal.

---

## 🇬🇧 English Version (v0.3)

**Goal:** Secure the scanning engine, implement smart filtering, and optimize performance.

### 🛡️ Security & Robustness

- **Critical Fix (DoS):** Switched to an iterative stack-based architecture to eliminate Stack Overflow risks.
- **Medium Fix (Integrity):** Non-blocking error handling (`match`) to prevent scan interruption.

### 🚀 Performance & Features

- **Smart Filtering:** Automatic exclusion of heavy directories (`node_modules`, `target`, `.git`).
- **Display Throttling (100ms):** Reduces CPU overhead by ~90% by limiting terminal refreshes.
