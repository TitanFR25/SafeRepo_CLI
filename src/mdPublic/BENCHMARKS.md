# 📊 SafeRepo Performance Benchmarks / Benchmarks de Performance SafeRepo

### ⚡ Raccourcis / Shortcuts

- [🇫🇷 Version Française](#-version-française)
- [🇬🇧 English Version](#-english-version)

---

## 🇫🇷 Version Française

### 📋 Aperçu

SafeRepo inclut des benchmarks de performance complets utilisant `criterion.rs` pour mesurer:

- **Parsing de production** via `SecurityManager::analyze_file`
- **Scan de production** via `scan_repo`
- **Effet du parallélisme** avec 1 et 4 threads
- **Débit** sur une arborescence de manifestes réelle

### 🏃 Exécuter les Benchmarks

#### Tous les benchmarks

```bash
cargo bench
```

#### Groupe spécifique

```bash
cargo bench --bench scanner_bench -- production_parsing
cargo bench --bench scanner_bench -- production_scan
cargo bench --bench scanner_bench -- production_throughput
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

#### 1. Parsing de production

- **Groupe**: `production_parsing`
- **Mesure**: Appel réel à `SecurityManager::analyze_file` sur Cargo.lock, package-lock.json et requirements.txt

#### 2. Parsing de formats

Les noms des mesures sont générés depuis les fichiers fixtures, par exemple
`Cargo_lock`, `package-lock_json` et `requirements_txt`. Aucune cible fixe en
microsecondes n'est publiée : les résultats dépendent de la machine.

#### 3. Scan de production

- **Groupe**: `production_scan`
- **Mesure**: Appel réel à `scan_repo` sur 40 manifestes imbriqués
- **Variantes**: `threads_1` et `threads_4`

#### 4. Débit (Throughput)

- **Groupe**: `production_throughput`
- **Nom**: `scan_101_real_manifests`
- **Mesure**: Manifestes réellement analysés par seconde via `scan_repo`

### 🎯 Références de Performance (v0.6.9)

| Métrique                  | Cible              | Actuel                |
| ------------------------- | ------------------ | --------------------- |
| Parsing de production     | Baseline Criterion | À mesurer par machine |
| Scan production threads=1 | Baseline Criterion | À mesurer par machine |
| Scan production threads=4 | Baseline Criterion | À mesurer par machine |
| Débit de manifestes       | Baseline Criterion | À mesurer par machine |

### 🔄 Benchmarking Continu

Le workflow CI compile les benchmarks sur les pushes vers `main`. Il ne publie
pas encore de comparaison automatique de performances.

Voir `.github/workflows/ci.yml` pour l'intégration CI/CD.

### 🧠 Profilage Mémoire

```bash
# Linux:
valgrind --tool=massif cargo bench --bench scanner_bench -- production_parsing

# macOS (Xcode):
valgrind --tool=massif cargo bench --bench scanner_bench -- production_parsing
```

### 🎯 Stratégies d'Optimisation

Suivi (v0.7.0+):

1. **Scanning parallèle** (rayon)
   - Actuellement: Disponible via `ScanOptions.threads`
   - Suivi: Comparer les baselines sur des machines et systèmes de fichiers représentatifs

2. **Couche de cache**
   - Actuellement: Pas de cache
   - Cible: Cache les manifestes parsés par hash

3. **Scanning incrémental**
   - Actuellement: Scan complet
   - Cible: Scan uniquement les fichiers modifiés

### 📈 Établir une Baseline

```bash
cargo bench -- --save-baseline v0.6.9
```

cargo bench -- --save-baseline v0.6.9

```bash
# Sortie verbose
CRITERION_VERBOSE=1 cargo bench

# Infos debug
cargo bench -- --verbose

# Test simple multiple fois
cargo bench --bench scanner_bench -- production_scan -- --sample-size 10
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
cargo bench --bench scanner_bench -- production_parsing
cargo bench --bench scanner_bench -- production_scan
cargo bench --bench scanner_bench -- production_throughput
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

- **Group**: `production_parsing`
- **Measures**: Real parser calls through `SecurityManager::analyze_file`

#### 2. Format Parsing

Benchmark names are generated from fixture filenames, such as `Cargo_lock`,
`package-lock_json`, and `requirements_txt`. No fixed microsecond target is
published because results depend on the machine.

#### 3. Production Scanning

- **Group**: `production_scan`
- **Measures**: Real `scan_repo` calls over 40 nested manifests
- **Variants**: `threads_1` and `threads_4`

#### 4. Throughput

- **Group**: `production_throughput`
- **Name**: `scan_101_real_manifests`
- **Measures**: Real manifests processed per second through `scan_repo`

### 🎯 Performance References (v0.6.9)

| Metric                    | Target             | Current           |
| ------------------------- | ------------------ | ----------------- |
| Production parsing        | Criterion baseline | Machine-dependent |
| Production scan threads=1 | Criterion baseline | Machine-dependent |
| Production scan threads=4 | Criterion baseline | Machine-dependent |
| Manifest throughput       | Criterion baseline | Machine-dependent |

### 🔄 Continuous Benchmarking

The CI workflow compiles benchmarks on pushes to `main`. It does not yet
publish automatic performance comparisons.

See `.github/workflows/ci.yml` for CI integration.

### 🧠 Memory Profiling

```bash
# Linux:
valgrind --tool=massif cargo bench --bench scanner_bench -- production_parsing

# macOS (Xcode):
cargo bench --bench scanner_bench -- production_parsing -- --profile-time=10
```

### 🎯 Optimization Strategies

Current (v0.6.9):

1. **Parallel scanning** (rayon)
   - Current: Configurable through `ScanOptions.threads`
   - Follow-up: Compare baselines on representative machines and file systems

2. **No caching layer**
   - Current: No caching between scans
   - Future: Cache parsed manifests by hash

3. **Full scanning**
   - Current: Full scan every time
   - Future: Scan only modified files

### 📈 Establish Baseline

```bash
cargo bench -- --save-baseline v0.6.9
```

### 🐛 Debug Benchmarks

```bash
# Verbose output
CRITERION_VERBOSE=1 cargo bench

# Debug info
cargo bench -- --verbose

# Single test multiple times
cargo bench --bench scanner_bench -- production_scan --sample-size 10
```

### 📚 References

- [Criterion.rs Documentation](https://bheisler.github.io/criterion.rs/book/)
- [Benching Best Practices](https://nnethercote.github.io/perf-book/)
