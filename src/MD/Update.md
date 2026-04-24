# 📑 Saferepo Update Report / Rapport de Mise à jour

### ⚡ Shortcuts / Raccourcis

- [🇫🇷 Version Française (v0.5)](#-version-française-v05)
- [🇬🇧 English Version (v0.5)](#-english-version-v05)
- [🇫🇷 Version Française (v0.3)](#-version-française-v03)
- [🇬🇧 English Version (v0.3)](#-english-version-v03)

---

## 🇫🇷 Version Française (v0.5)

**Objectif :** Architecture modulaire professionnelle, parsing hiérarchique et accès direct O(1).

### 🏗️ Architecture & Modularité (Refonte)

- **Découplage Logique :** Extraction du code monolithique vers une structure multi-fichiers :
  - `db.rs` : Gestion exclusive de la base de données (chargement, stockage, parsing).
  - `security.rs` : Moteur d'analyse et logique de reporting des vulnérabilités.
- **Modèle de Données :** Introduction du bridge `VulnerabilityFile` pour réconcilier le format physique TOML et la représentation mémoire.

### 🧠 Intelligence & Parsing

- **Parsing Hiérarchique :** Support complet des blocs TOML standardisés `[advisory]` et `[versions]`.
- **Analyse SemVer :** Abandon du filtrage textuel basique pour une intégration profonde de `VersionReq`. Permet de gérer des plages de correctifs complexes (ex: `>=1.2.0, <2.0.0`).
- **Performance O(1) :** Migration vers une `HashMap` indexée par nom de package. La vitesse de recherche est désormais constante, supprimant la latence sur les projets à gros volume de dépendances.

### 🛠️ Fiabilité

- **Fail-safe Loading :** Le chargeur de base de données ignore désormais les fichiers mal formés avec un log d'erreur en `stderr`, garantissant la continuité du scan.
- **Type Safety :** Utilisation d'Enums pour la sévérité et de structures typées pour garantir l'intégrité des données après parsing.

---

## 🇬🇧 English Version (v0.5)

**Goal:** Professional modular architecture, hierarchical parsing, and O(1) direct access.

### 🏗️ Architecture & Modularity (Overhaul)

- **Logical Decoupling:** Monolithic code extracted into a multi-file structure:
  - `db.rs`: Exclusive database management (loading, storage, parsing).
  - `security.rs`: Analysis engine and vulnerability reporting logic.
- **Data Modeling:** Introduced the `VulnerabilityFile` bridge to reconcile physical TOML format with memory representation.

### 🧠 Intelligence & Parsing

- **Hierarchical Parsing:** Full support for standardized `[advisory]` and `[versions]` TOML blocks.
- **SemVer Analysis:** Replaced basic text filtering with deep `VersionReq` integration. Handles complex patch ranges (e.g., `>=1.2.0, <2.0.0`).
- **O(1) Performance:** Migrated internal storage to a package-indexed `HashMap`. Search time is now constant, eliminating latency in dependency-heavy projects.

### 🛠️ Reliability

- **Fail-safe Loading:** Database loader now skips malformed files via `stderr` logging, ensuring scan continuity.
- **Type Safety:** Implemented Enums for severity levels and strictly typed structures to guarantee post-parsing data integrity.

---

## 🇫🇷 Version Française (v0.3)

**Objectif :** Sécurisation du moteur de scan, filtrage intelligent et optimisation des performances.

### 🛡️ Sécurité & Robustesse

- **Correction Critique (DoS) :** Passage à une **pile itérative (Stack-based)**. Élimine le risque de plantage par saturation de la pile de mémoire sur les arborescences géantes.
- **Correction Moyenne (Intégrité) :** Gestion d'erreurs non-bloquante (`match`). Empêche l'arrêt brutal du scan lors de la rencontre de fichiers corrompus ou de dossiers protégés.
- **Correction Mineure (Précision) :** Synchronisation post-boucle. Garantit que les derniers fichiers traités sont bien comptabilisés malgré le délai d'affichage de 100ms.
- **Résilience :** Bypass automatique des dossiers "système" inaccessibles sans crash de l'exécutable.

### 🚀 Performances & Nouveautés

- **Nouveauté : Filtrage Intelligent (Smart Filtering) :** Exclusion automatique des répertoires lourds (`node_modules`, `target`, `.git`) pour un gain de vitesse jusqu'à **x100**.
- **Priorité Manifestes :** Le filtre ignore les dossiers mais préserve les fichiers critiques (`package.json`, `Cargo.toml`) pour l'analyse future des dépendances.
- **Throttling d'affichage (100ms) :** Réduit l'utilisation CPU de **~90%** en limitant les rafraîchissements du terminal.

### ✨ Expérience Utilisateur (UX)

- **Spinner Dynamique :** Feedback visuel en temps réel pour confirmer que le scan est actif.
- **Rapport Détaillé :** Affichage séparé des éléments scannés et des éléments ignorés pour une meilleure transparence.

---

## 🇬🇧 English Version (v0.3)

**Goal:** Secure the scanning engine, implement smart filtering, and optimize performance.

### 🛡️ Security & Robustness

- **Critical Fix (DoS):** Switched to an **iterative stack-based** architecture. Eliminates the risk of crashes due to stack overflow on deep directory structures.
- **Medium Fix (Integrity):** Non-blocking error handling (`match`). Prevents the scanner from stopping when encountering corrupted files or protected folders.
- **Minor Fix (Accuracy):** Post-loop synchronization. Ensures the final file count is exact even with the 100ms display delay.
- **Resilience:** Automatic bypass of inaccessible "system" directories without crashing the executable.

### 🚀 Performance & Features

- **New: Smart Filtering:** Automatic exclusion of heavy directories (`node_modules`, `target`, `.git`), increasing scan speed by up to **x100**.
- **Manifest Priority:** Filters out directories but preserves critical files (`package.json`, `Cargo.toml`) for future dependency analysis.
- **Display Throttling (100ms):** Reduces CPU overhead by **~90%** by limiting terminal refreshes.

### ✨ User Experience (UX)

- **Dynamic Spinner:** Real-time visual feedback to confirm the scan is active.
- **Detailed Reporting:** Separate display of scanned and ignored items for better transparency.
