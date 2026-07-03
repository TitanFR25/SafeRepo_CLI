use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::path::Path;
use tempfile::TempDir;

// ============================================================================
// 📊 BENCHMARKS SAFEREPO - Mesure de Performance
// ============================================================================
// Ce fichier contient les benchmarks pour tester les performances du scanner
// SafeRepo. Les tests mesurent le temps d'exécution et l'utilisation mémoire
// pour différentes opérations clés du scanner.
// ============================================================================

// Fonctions simulées de benchmark (dans un scénario réel, ces fonctions
// seraient importées depuis la bibliothèque SafeRepo_CLI).
// Les simulations permettent de tester la performance des algorithmes
// sans dépendre de l'état interne de la lib.

/// 📄 Scanne un fichier unique et compte le nombre de lignes
///
/// Cette fonction simule la lecture d'un fichier manifeste et le compte
/// du nombre de lignes. C'est une opération fondamentale du scanner.
///
/// # Arguments
/// * `path` - Chemin du fichier à scanner
///
/// # Résultat
/// * `Ok(count)` - Nombre de lignes dans le fichier
/// * `Err(msg)` - Message d'erreur en cas de problème
fn simulate_scan_file(path: &Path) -> Result<usize, String> {
    // Lit le contenu du fichier en une chaîne de caractères
    std::fs::read_to_string(path)
        // Compte le nombre de lignes (séparées par '\n')
        .map(|content| content.lines().count())
        // Convertit les erreurs de lecture en messages String
        .map_err(|e| e.to_string())
}

/// 🔒 Parse un fichier Cargo.lock (format TOML simplifié)
///
/// Cargo.lock est le fichier de verrouillage de Rust. Cette fonction
/// simule l'extraction des noms de packages d'un fichier Cargo.lock.
///
/// # Format attendu
/// ```text
/// [[package]]
/// name = "serde"
/// version = "1.0.0"
/// ```
///
/// # Arguments
/// * `content` - Contenu du fichier Cargo.lock à parser
///
/// # Résultat
/// * `Ok(packages)` - Liste des noms de packages trouvés
/// * `Err(msg)` - Message d'erreur si le parsing échoue
fn simulate_parse_cargo_lock(content: &str) -> Result<Vec<String>, String> {
    // Parcourt chaque ligne du fichier et extrait les noms de packages
    Ok(content
        .lines()
        // Filtre les lignes qui commencent par "name" (déclaration de package)
        .filter(|line| line.starts_with("name"))
        // Convertit chaque ligne en String pour la stocker
        .map(|line| line.to_string())
        // Collecte tous les résultats dans un vecteur
        .collect())
}

/// 📦 Parse un fichier package-lock.json (format JSON npm/Node.js)
///
/// package-lock.json est le fichier de verrouillage npm pour Node.js.
/// Cette fonction extrait les dépendances du champ "dependencies".
///
/// # Format attendu
/// ```json
/// {
///   "dependencies": {
///     "express": { "version": "4.17.1" },
///     "lodash": { "version": "4.17.21" }
///   }
/// }
/// ```
///
/// # Arguments
/// * `content` - Contenu JSON du package-lock.json à parser
///
/// # Résultat
/// * `Ok(packages)` - Liste des noms de packages trouvés
/// * `Err(msg)` - Message d'erreur si le parsing JSON échoue
fn simulate_parse_package_lock(content: &str) -> Result<Vec<String>, String> {
    // Parse le contenu JSON en structure serde_json::Value
    let json: serde_json::Value = serde_json::from_str(content).map_err(|e| e.to_string())?;

    // Initialise le vecteur qui contiendra les noms de packages
    let mut packages = Vec::new();

    // Extrait le champ "dependencies" s'il existe et si c'est un objet JSON
    if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
        // Parcourt chaque clé du champ dependencies (ce sont les noms de packages)
        for key in deps.keys() {
            // Ajoute le nom du package à la liste
            packages.push(key.clone());
        }
    }

    // Retourne la liste des packages trouvés
    Ok(packages)
}

/// 🐍 Parse un fichier requirements.txt (format texte Python/pip)
///
/// requirements.txt est le fichier de dépendances Python standard.
/// Cette fonction extrait les noms de packages des lignes de dépendances.
///
/// # Format attendu
/// ```text
/// django==3.2.0
/// requests>=2.26.0
/// # Commentaire
/// numpy~=1.21.0
/// ```
///
/// # Arguments
/// * `content` - Contenu du fichier requirements.txt à parser
///
/// # Résultat
/// * `Ok(packages)` - Liste des noms de packages trouvés
fn simulate_parse_requirements(content: &str) -> Result<Vec<String>, String> {
    // Parcourt chaque ligne du fichier
    Ok(content
        .lines()
        // Filtre les lignes vides ET les lignes de commentaires (commençant par #)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        // Convertit chaque ligne en String pour la stocker
        .map(|line| line.to_string())
        // Collecte tous les résultats dans un vecteur
        .collect())
}

/// 📁 Scanne un répertoire en respectant une limite de profondeur
///
/// Cette fonction simule la traversée itérative d'une arborescence de fichiers.
/// Elle limite la profondeur pour éviter les structures infinies et compte
/// le nombre de fichiers trouvés.
///
/// # Algorithme
/// Utilise une pile (stack) itérative pour éviter les débordements de pile.
/// Chaque tuple (chemin, profondeur) est traité jusqu'à atteindre la limite.
///
/// # Arguments
/// * `dir` - Répertoire racine à scanner
/// * `max_depth` - Limite de profondeur (0 = racine seulement, 40 = limite de sécurité)
///
/// # Résultat
/// * `Ok(count)` - Nombre total de fichiers trouvés
/// * `Err(msg)` - Message d'erreur en cas de problème d'accès
fn simulate_scan_directory(dir: &Path, max_depth: usize) -> Result<usize, String> {
    // Initialise le compteur de fichiers
    let mut file_count = 0;

    // Initialise la pile avec le répertoire de départ et sa profondeur (0)
    let mut to_visit = vec![(dir.to_path_buf(), 0)];

    // Boucle tant qu'il y a des éléments à traiter dans la pile
    while let Some((current_path, depth)) = to_visit.pop() {
        // Si nous avons atteint la limite de profondeur, ignorons ce répertoire
        if depth > max_depth {
            continue;
        }

        // Essaie de lire les entrées du répertoire courant
        if let Ok(entries) = std::fs::read_dir(&current_path) {
            // Parcourt chaque entrée du répertoire
            for entry in entries.flatten() {
                // Essaie d'obtenir les métadonnées de l'entrée
                if let Ok(metadata) = entry.metadata() {
                    // Si c'est un fichier, incrémente le compteur
                    if metadata.is_file() {
                        file_count += 1;
                    }
                    // Si c'est un répertoire, l'ajoute à la pile pour traitement
                    else if metadata.is_dir() {
                        to_visit.push((entry.path(), depth + 1));
                    }
                }
            }
        }
    }

    // Retourne le nombre total de fichiers trouvés
    Ok(file_count)
}

// ============================================================================
// 🎯 GROUPES DE BENCHMARKS - Configurations des tests de performance
// ============================================================================
// Chaque groupe de benchmarks teste un aspect spécifique du scanner.
// Les résultats sont comparés avec les cibles de performance définies.
// ============================================================================

/// 📄 Benchmark: Scanning d'un fichier unique
///
/// Ce test mesure le temps pour scanner un fichier manifeste unique
/// contenant 1000 lignes de données. C'est une mesure fondamentale
/// de la performance du moteur de scan de base.
///
/// **Cible**: < 100 microsecondes par fichier
/// **Importance**: Haute - opération fréquente
fn bench_single_file_scan(c: &mut Criterion) {
    // Crée un répertoire temporaire pour le test
    let temp_dir = TempDir::new().expect("Erreur: impossible de créer un répertoire temporaire");
    let test_file = temp_dir.path().join("test_manifest.txt");

    // Génère un contenu de test avec 1000 lignes
    // Chaque ligne contient: "line_N: some_data_M" où M = N * 2
    let large_content = (0..1000)
        .map(|i| format!("line_{}: some_data_{}", i, i * 2))
        .collect::<Vec<_>>()
        .join("\n");

    // Écrit le contenu dans le fichier de test
    std::fs::write(&test_file, &large_content)
        .expect("Erreur: impossible d'écrire le fichier de test");

    // Lance le benchmark avec criterion
    // black_box() empêche l'optimiseur de compiler le code trop agressivement
    c.bench_function("scan_single_file_1000_lines", |b| {
        b.iter(|| simulate_scan_file(black_box(&test_file)))
    });
}

/// 🔍 Benchmark: Parsing de formats de manifestes
///
/// Ce groupe mesure les performances de parsing pour les trois formats
/// de manifestes les plus courants. Chaque format a des caractéristiques
/// différentes (TOML, JSON, texte brut) qui affectent la performance.
///
/// **Cible globale**: < 1.5 millisecondes pour tous les formats
fn bench_format_parsing(c: &mut Criterion) {
    // Crée un groupe de benchmarks nommé "format_parsing"
    // Les résultats seront groupés sous ce nom dans le rapport
    let mut group = c.benchmark_group("format_parsing");

    // ========== TEST 1: Cargo.lock (Rust - Format TOML) ==========
    // Cargo.lock est le fichier de verrouillage des dépendances Rust.
    // Format: Texte TOML avec blocs [[package]]
    let cargo_content = r#"
[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "toml"
version = "0.5.0"

[[package]]
name = "sha2"
version = "0.11.0"
"#;

    // Lance le benchmark pour Cargo.lock
    // Mesure le temps pour extraire les noms de packages
    // Cible: < 500 microsecondes
    group.bench_function("parse_cargo_lock_format", |b| {
        b.iter(|| simulate_parse_cargo_lock(black_box(cargo_content)))
    });

    // ========== TEST 2: package-lock.json (Node.js/npm - Format JSON) ==========
    // package-lock.json est le fichier de verrouillage npm pour Node.js.
    // Format: JSON structuré avec champ "dependencies"
    // C'est généralement plus grand et plus complexe que Cargo.lock
    let npm_content = r#"{
  "dependencies": {
    "express": { "version": "4.17.1" },
    "lodash": { "version": "4.17.21" },
    "axios": { "version": "0.24.0" },
    "react": { "version": "18.0.0" },
    "react-dom": { "version": "18.0.0" }
  }
}"#;

    // Lance le benchmark pour package-lock.json
    // Mesure le temps pour extraire les noms de packages du JSON
    // Cible: < 1 milliseconde
    group.bench_function("parse_package_lock_format", |b| {
        b.iter(|| simulate_parse_package_lock(black_box(npm_content)))
    });

    // ========== TEST 3: requirements.txt (Python/pip - Format texte) ==========
    // requirements.txt est le fichier de dépendances Python standard.
    // Format: Texte brut avec une dépendance par ligne
    // C'est le format le plus simple à parser
    let python_content = r#"
Django==3.2.0
requests==2.26.0
numpy==1.21.0
pandas==1.3.0
flask==2.0.0
scipy==1.7.0
scikit-learn==0.24.2
"#;

    // Lance le benchmark pour requirements.txt
    // Mesure le temps pour extraire les noms de packages
    // Cible: < 300 microsecondes (plus rapide car format simple)
    group.bench_function("parse_requirements_format", |b| {
        b.iter(|| simulate_parse_requirements(black_box(python_content)))
    });

    // Finalise le groupe (génère rapports, etc.)
    group.finish();
}

/// 📂 Benchmark: Scanning de répertoires avec profondeur variable
///
/// Ce groupe teste la performance du scanner avec des arborescences
/// de répertoires de différentes profondeurs. Cela simule des projets
/// réels avec structures de dossiers imbriquées.
///
/// **Profondeurs testées**: 10, 20, 40 niveaux
/// **Cible**: Scalabilité linéaire O(n)
fn bench_directory_scanning(c: &mut Criterion) {
    // Crée un groupe de benchmarks pour le scanning de répertoires
    let mut group = c.benchmark_group("directory_scanning");

    // Teste trois profondeurs différentes pour mesurer l'évolutivité
    // 10 niveaux = structure simple
    // 20 niveaux = structure typique réelle
    // 40 niveaux = limite de sécurité du scanner SafeRepo
    for depth in [10, 20, 40].iter() {
        // BenchmarkId crée un identifiant unique pour chaque configuration
        // Cela permet de comparer les performances à différentes profondeurs
        group.bench_with_input(BenchmarkId::from_parameter(depth), depth, |b, &depth| {
            // Crée un répertoire temporaire pour le test
            let temp_dir =
                TempDir::new().expect("Erreur: impossible de créer un répertoire temporaire");

            // Construit une arborescence imbriquée
            // Chaque niveau contient 3 fichiers
            let mut current = temp_dir.path().to_path_buf();
            for i in 0..depth {
                // Crée un sous-répertoire "level_N"
                current = current.join(format!("level_{}", i));
                std::fs::create_dir_all(&current)
                    .expect("Erreur: impossible de créer un répertoire");

                // Crée 3 fichiers à ce niveau
                for j in 0..3 {
                    let file = current.join(format!("file_{}.txt", j));
                    std::fs::write(&file, format!("content_{}", j)).ok();
                }
            }

            // Lance le benchmark pour scanner cette arborescence
            // Mesure le temps total pour traverser tous les niveaux
            // et compter tous les fichiers
            b.iter(|| simulate_scan_directory(black_box(temp_dir.path()), depth))
        });
    }

    // Finalise le groupe
    group.finish();
}

/// 🔎 Benchmark: Détection des formats de manifestes
///
/// Ce groupe teste la vitesse de détection des différents formats.
/// Chaque type de manifeste est testé indépendamment.
///
/// **Types testés**: 7 formats (Cargo, npm, Python, Go, Java, Ruby, PHP)
/// **Cible**: < 10 microsecondes par détection
fn bench_manifest_detection(c: &mut Criterion) {
    // Crée un groupe de benchmarks pour la détection de manifestes
    let mut group = c.benchmark_group("manifest_detection");

    // Crée un répertoire temporaire contenant tous les fichiers manifestes
    let temp_dir = TempDir::new().expect("Erreur: impossible de créer un répertoire temporaire");

    // Définit les manifestes à tester: (nom_fichier, contenu)
    let manifests = vec![
        ("Cargo.lock", "name = 'test'"),      // Rust
        ("package-lock.json", "{}"),          // Node.js/npm
        ("requirements.txt", "django==3.2"),  // Python/pip
        ("go.mod", "module github.com/test"), // Go
        ("pom.xml", "<project></project>"),   // Java/Maven
        ("Gemfile.lock", "GEM"),              // Ruby/Bundler
        ("composer.lock", "{}"),              // PHP/Composer
    ];

    // Teste la détection pour chaque type de manifeste
    for (filename, content) in manifests {
        // Crée le fichier manifeste dans le répertoire temporaire
        let file_path = temp_dir.path().join(filename);
        std::fs::write(&file_path, content)
            .expect("Erreur: impossible d'écrire le fichier manifeste");

        // Lance le benchmark pour détecter ce fichier
        // Cela simule la vérification de l'existence et du type du fichier
        group.bench_function(format!("detect_{}", filename), |b| {
            b.iter(|| {
                // Vérifie si le fichier existe en utilisant metadata
                // black_box() empêche les optimisations trop agressives
                std::fs::metadata(black_box(&file_path))
                    .map(|m| m.is_file())
                    .unwrap_or(false)
            })
        });
    }

    // Finalise le groupe
    group.finish();
}

/// ⚡ Benchmark: Débit (Throughput) - Fichiers traités par seconde
///
/// Ce benchmark mesure le nombre de fichiers que le scanner peut
/// traiter par seconde. C'est une métrique clé pour l'évolutivité.
///
/// **Cible**: > 10 000 fichiers par seconde
/// **Importance**: Critique pour les gros projets
fn bench_throughput(c: &mut Criterion) {
    // Crée un groupe de benchmarks pour le débit
    let mut group = c.benchmark_group("throughput");

    // Indique à criterion que nous mesurons des "Éléments" (fichiers)
    // Cela permet de calculer automatiquement les fichiers/seconde
    group.throughput(criterion::Throughput::Elements(1000));

    // Lance le benchmark pour traiter 1000 petits fichiers
    group.bench_function("process_1000_small_files", |b| {
        // Crée un répertoire temporaire
        let temp_dir =
            TempDir::new().expect("Erreur: impossible de créer un répertoire temporaire");

        // Crée 1000 petits fichiers de test
        for i in 0..1000 {
            let file = temp_dir.path().join(format!("file_{}.txt", i));
            std::fs::write(&file, format!("data_{}", i)).ok();
        }

        // Collecte la liste de tous les fichiers créés
        let file_list: Vec<_> = std::fs::read_dir(temp_dir.path())
            .ok()
            .map(|entries| entries.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();

        // Lance le benchmark
        // Chaque itération scanne tous les 1000 fichiers
        b.iter(|| {
            // Parcourt chaque fichier et le scanne
            file_list.iter().for_each(|path| {
                // Simule la lecture du fichier
                let _ = simulate_scan_file(black_box(path));
            })
        });
    });

    // Finalise le groupe
    group.finish();
}

// ============================================================================
// 📊 CONFIGURATION DES GROUPES ET POINT D'ENTRÉE
// ============================================================================
// Ces macros définissent quels groupes de benchmarks exécuter
// et le point d'entrée principal pour le test de benchmark.
// ============================================================================

// criterion_group! définit un groupe de benchmarks à exécuter
// Le premier paramètre est le nom du groupe, les suivants sont les fonctions de benchmark
criterion_group!(
    benches,
    bench_single_file_scan,   // Test 1: Scanning d'un fichier unique
    bench_format_parsing,     // Test 2: Parsing de formats (Cargo, npm, Python)
    bench_directory_scanning, // Test 3: Scanning d'arborescences
    bench_manifest_detection, // Test 4: Détection de types de manifestes
    bench_throughput          // Test 5: Débit (fichiers/seconde)
);

// criterion_main! défini le point d'entrée du programme de benchmark
// Criterion gère automatiquement l'exécution et le reporting
criterion_main!(benches);
