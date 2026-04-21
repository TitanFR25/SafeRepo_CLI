# 📑 Saferepo Update Report / Rapport de Mise à jour

### ⚡ Shortcuts / Raccourcis

- [🇫🇷 Version Française](#-version-française-v03)
- [🇬🇧 English Version](#-english-version-v03)

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

## 🇬🇧 English Version (v0.2)

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

---
