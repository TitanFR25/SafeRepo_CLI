# 📊 SafeRepo Performance Benchmarks / Benchmarks de Performance SafeRepo

### ⚡ Raccourcis / Shortcuts
- [🇫🇷 Version Française](#-version-française)
- [🇬🇧 English Version](#-english-version)

---

## 🇫🇷 Version Française

### 📋 Aperçu

SafeRepo inclut des benchmarks de performance complets utilisant `criterion.rs` pour mesurer:
- **Vitesse de scanning** (fichiers traités par seconde)
- **Performance de parsing** (différents formats de manifestes)
- **Utilisation mémoire** (via criterion)
- **Traversée de répertoires** (avec profondeurs variables)
- **Détection de manifestes** (identification des types de fichiers)

### 🏃 Exécuter les Benchmarks

#### Tous les benchmarks
```bash
cargo bench
```

#### Groupe spécifique
```bash
cargo bench --bench scanner_bench -- format_parsing
```

#### Avec comparaison baseline
```bash
cargo bench -- --save-baseline ma_baseline
cargo bench -- --baseline ma_baseline
```

#### Rapport HTML
```bash
cargo bench -- --plotting-backend gnuplot
```
Rapports générés dans `target/criterion/`.

### 📊 Groupes de Benchmarks

#### 1. Scanning d'un fichier unique
- **Nom**: `scan_single_file_1000_lines`
- **Mesure**: Temps pour scanner un fichier manifeste de 1000 lignes
- **Cible**: < 100μs par fichier

#### 2. Parsing de formats

**Cargo.lock**
- **Nom**: `parse_cargo_lock_format`
- **Mesure**: Parsing du fichier TOML Cargo.lock
- **Cible**: < 500μs

**package-lock.json**
- **Nom**: `parse_package_lock_format`
- **Mesure**: Parsing du fichier JSON npm
- **Cible**: < 1ms

**requirements.txt**
- **Nom**: `parse_requirements_format`
- **Mesure**: Parsing du fichier texte Python
- **Cible**: < 300μs

#### 3. Scanning de répertoires
- **Profondeurs testées**: 10, 20, 40 niveaux
- **Fichiers par niveau**: 3 fichiers
- **Cible**: Complexité linéaire O(n)
- **Attendu**: Arborescence 40-level (120 fichiers) < 10ms

#### 4. Détection de manifestes

Types testés:
- Cargo.lock
- package-lock.json
- requirements.txt
- go.mod
- pom.xml
- Gemfile.lock
- composer.lock

#### 5. Débit (Throughput)
- **Nom**: `process_1000_small_files`
- **Mesure**: Fichiers traités par seconde
- **Cible**: > 10 000 fichiers/seconde

### 🎯 Cibles de Performance (v0.6.5.1)

| Métrique | Cible | Actuel |
|----------|-------|--------|
| Scanning fichier unique | < 100μs | - |
| Parse Cargo.lock | < 500μs | - |
| Parse npm | < 1ms | - |
| Parse Python | < 300μs | - |
| Scan dir (40-level) | < 10ms | - |
| Débit | > 10k fichiers/s | - |
| Mémoire max (1000 fichiers) | < 50MB | - |

### 🔄 Benchmarking Continu

Lancés automatiquement:
- ✅ À chaque push vers `main`
- ✅ Sur les pull requests (comparaison optionnelle)

Voir `.github/workflows/ci.yml` pour l'intégration CI/CD.

### 🧠 Profilage Mémoire

```bash
# Linux:
valgrind --tool=massif cargo bench --bench scanner_bench -- single_file

# macOS (Xcode):
cargo bench --bench scanner_bench -- single_file -- --profile-time=10
```

### 🎯 Stratégies d'Optimisation

Futur (v0.7.0+):

1. **Scanning parallèle** (rayon)
   - Actuellement: Séquentiel
   - Cible: Multi-threadé (+50-80% speedup)

2. **Couche de cache**
   - Actuellement: Pas de cache
   - Cible: Cache les manifestes parsés par hash

3. **Scanning incrémental**
   - Actuellement: Scan complet
   - Cible: Scan uniquement les fichiers modifiés

### 📈 Établir une Baseline

```bash
cargo bench -- --save-baseline v0.6.5.1
```

### 🐛 Déboguer les Benchmarks

```bash
# Sortie verbose
CRITERION_VERBOSE=1 cargo bench

# Infos debug
cargo bench -- --verbose

# Test simple multiple fois
cargo bench --bench scanner_bench -- scan_single_file_1000_lines --sample-size 100
```

### 📚 Références

- [Criterion.rs Documentation](https://bheisler.github.io/criterion.rs/book/)
- [Benching Best Practices](https://nnethercote.github.io/perf-book/)

---

## 🇬🇧 English Version

### 📋 Overview

SafeRepo includes comprehensive performance benchmarks using `criterion.rs` to measure and track:
- **Scanning speed** (files processed per second)
- **Parsing performance** (different manifest formats)
- **Memory usage** (via criterion)
- **Directory traversal** (with varying depths)
- **Manifest detection** (file type identification)

### 🏃 Running Benchmarks

#### All benchmarks
```bash
cargo bench
```

#### Specific benchmark group
```bash
cargo bench --bench scanner_bench -- format_parsing
```

#### With baseline comparison
```bash
cargo bench -- --save-baseline my_baseline
cargo bench -- --baseline my_baseline
```

#### HTML report
```bash
cargo bench -- --plotting-backend gnuplot
```
Reports generated in `target/criterion/`.

### 📊 Benchmark Groups

#### 1. Single File Scanning
- **Name**: `scan_single_file_1000_lines`
- **Measures**: Time to scan a single manifest file with 1000 lines
- **Goal**: < 100μs per file

#### 2. Format Parsing

**Cargo.lock**
- **Name**: `parse_cargo_lock_format`
- **Measures**: Parsing TOML-based Cargo.lock file
- **Goal**: < 500μs

**package-lock.json**
- **Name**: `parse_package_lock_format`
- **Measures**: Parsing JSON-based npm lock file
- **Goal**: < 1ms

**requirements.txt**
- **Name**: `parse_requirements_format`
- **Measures**: Parsing plain text Python requirements
- **Goal**: < 300μs

#### 3. Directory Scanning
- **Depths tested**: 10, 20, 40 levels
- **Files per level**: 3 files
- **Goal**: Linear complexity O(n)
- **Expected**: 40-level tree (120 files) < 10ms

#### 4. Manifest Detection

Types tested:
- Cargo.lock
- package-lock.json
- requirements.txt
- go.mod
- pom.xml
- Gemfile.lock
- composer.lock

#### 5. Throughput
- **Name**: `process_1000_small_files`
- **Measures**: Files processed per second
- **Goal**: > 10,000 files/second

### 🎯 Performance Targets (v0.6.5.1)

| Metric | Target | Current |
|--------|--------|---------|
| Single file scan | < 100μs | - |
| Cargo.lock parse | < 500μs | - |
| npm parse | < 1ms | - |
| Python parse | < 300μs | - |
| Dir scan (40-level) | < 10ms | - |
| Throughput | > 10k files/s | - |
| Max memory (1000 files) | < 50MB | - |

### 🔄 Continuous Benchmarking

Run automatically:
- ✅ Every push to `main` branch
- ✅ On pull requests (optional comparison)

See `.github/workflows/ci.yml` for CI integration.

### 🧠 Memory Profiling

```bash
# Linux:
valgrind --tool=massif cargo bench --bench scanner_bench -- single_file

# macOS (Xcode):
cargo bench --bench scanner_bench -- single_file -- --profile-time=10
```

### 🎯 Optimization Strategies

Current (v0.6.5.1):

1. **Sequential scanning** (rayon ready)
   - Current: Single-threaded
   - Future: Multi-threaded (+50-80% speedup)

2. **No caching layer**
   - Current: No caching between scans
   - Future: Cache parsed manifests by hash

3. **Full scanning**
   - Current: Full scan every time
   - Future: Scan only modified files

### 📈 Establish Baseline

```bash
cargo bench -- --save-baseline v0.6.5.1
```

### 🐛 Debug Benchmarks

```bash
# Verbose output
CRITERION_VERBOSE=1 cargo bench

# Debug info
cargo bench -- --verbose

# Single test multiple times
cargo bench --bench scanner_bench -- scan_single_file_1000_lines --sample-size 100
```

### 📚 References

- [Criterion.rs Documentation](https://bheisler.github.io/criterion.rs/book/)
- [Benching Best Practices](https://nnethercote.github.io/perf-book/)
