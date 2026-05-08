use crate::secure::security::SecurityManager;
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

// --- CONFIGURATION DE SÉCURITÉ ---
// On monte à 2 Mo car on ne traite que les fichiers manifeste
const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024;
const MAX_DEPTH: usize = 40;

// Liste de dossiers à ignorer pour les performances
const IGNORED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "build",
    "dist",
    "vendor",
    ".cache",
];

// Fichiers de manifestes de projets qui peuvent contenir des informations Nécessaire à la recherche de failles de sécurité (ex: dépendances vulnérables)
const MANIFEST_FILES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "requirements.txt",
];

// 🔍 Vérifie si un répertoire est la racine valide d'un projet
/// Retourne true si au moins un fichier de projet racine est détecté
fn is_valid_project_root(path: &Path) -> bool {
    // Liste des fichiers qui marquent la racine d'un projet
    let root_markers = vec![
        "Cargo.toml",       // Rust
        "package.json",     // Node.js/NPM
        "requirements.txt", // Python
        "go.mod",           // Go
        "pom.xml",          // Java/Maven
        "Gemfile",          // Ruby
        "composer.json",    // PHP
        "pubspec.yaml",     // Dart
    ];

    // Vérifie si au moin un marker existe dans le répartoire
    for marker in root_markers {
        let marker_path = path.join(marker);
        if marker_path.exists() {
            return true; // C'est une racine valide
        }
    }

    false
}

// 🏃 Trouve le répertoire racine du projet en remontant l'arborescence
// Utile si l'utilisateur lance le scan depuis un sous-dossier
fn find_project_root(start_path: &Path) -> Option<PathBuf> {
    let mut current = start_path.to_path_buf();

    // Remonte jusqu'a trouver une racine valide (max 10 niveaux)
    for _ in 0..10 {
        if is_valid_project_root(&current) {
            return Some(current); // Racine trouvée
        }

        // Remonte d'un niveaux
        if !current.pop() {
            break; // On à atteint la racine filesystem
        }
    }

    None // Pas de racine trouvée
}

// Structure pour stocker les résultats du scan
struct ScanResult {
    files_count: u64,     // Nombre total de fichiers trouvés
    dirs_count: u64,      // Nombre total de dossiers trouvés
    issues_found: u64,    // Nombre de failles de sécurité détectées
    ignored_count: u64,   // Nombre d'éléments ignorés (ex: dossiers dans IGNORED_DIRS)
    oversized_count: u64, // Fichiers dépassant 2 Mo
    depth_limit_hit: u64, // Dossiers trop profonds
}

// Fonction principale de scan sécurisé
// P: Asref<Path> permet d'accepter des String, &str ou des PathBuf en entrée
pub fn scan_repo<P: AsRef<Path>>(root_path: P, manager: &mut SecurityManager) -> io::Result<()> {
    // Canonicaliser le chemin (résoudre tous les .., les symlinks, etc.)
    // Cela permet de détecter les tentatives de sortie du répertoire racine
    let canonical_root = match std::fs::canonicalize(root_path.as_ref()) {
        Ok(path) => path,
        Err(e) => {
            eprintln!(
                "❌ Erreur : Impossible de résoudre le chemin racine : {}",
                e
            );
            return Err(e);
        }
    };

    // Vérifier que le chemin existe et est un répertoire
    if !canonical_root.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "❌ Le chemin '{}' n'est pas un répertoire valide",
                canonical_root.display()
            ),
        ));
    }
    // 1.INITIALISATION
    // On crée une pile (stack) pour stocker les chemins à visiter.
    // On utilise un Vec (Heap) plutot que la récursion pour éviter de faire planter le programme (Stack Overflow).
    let mut stack = vec![(canonical_root.clone(), 0)];

    //Vérifier que c'est une racine de projet valide
    if !is_valid_project_root(&canonical_root) {
        println!(
            "⚠️ ATTENTION : '{}' n'est pas une racine de projet reconnue",
            canonical_root.display()
        );
        println!(
            "Fichiers marqueurs attendus : Cargo.toml, package.json, requirements.txt, go.mod, etc."
        );

        // Essayer de trouver automatiquement la racine
        if let Some(found_root) = find_project_root(&canonical_root) {
            println!("✅ Racine de projet trouvée : {}", found_root.display());
            println!("   Utilisation de ce répertoire pour le scan...");
            stack = vec![(found_root, 0)]; // Utiliser la racine trouvée
        } else {
            println!("❌ Aucune racine de projet trouvée. Continuation du scan malgré tout...");
            stack = vec![(canonical_root.clone(), 0)]; // Continuer avec le chemin fourni
        }
    } else {
        println!(
            "✅ Racine de projet détectée : {}",
            canonical_root.display()
        );
        stack = vec![(canonical_root.clone(), 0)];
    }

    // On initialise nos compteurs à zéro
    let mut stats = ScanResult {
        files_count: 0,
        dirs_count: 0,
        issues_found: 0,
        ignored_count: 0,
        oversized_count: 0,
        depth_limit_hit: 0,
    };

    // Liste de caractères pour créer une animation de chargement (Spinner)
    let spinner_frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let mut frame_idx = 0; // Index pour savoir quel caractère du spinner afficher

    // Gestion du temps pour l'affichage
    let mut last_update = Instant::now(); // On stocke le moment du dernier affichage 
    let update_interval = Duration::from_millis(100); // On veut mettre à jour l'affichage toutes les 100ms

    println!("🚀 Saferepo : Démarrage du scan...");

    // 2. BOUCLE DE PARCOURS (Tant qu'il y a des dossiers dans la pile)
    while let Some((current_path, depth)) = stack.pop() {
        // Canonicaliser aussi le chemin courant pour une sécurité supplémentaire
        let safe_path = match std::fs::canonicalize(&current_path) {
            Ok(p) => p,
            Err(_) => continue, // Ignorer les chemins invalides
        };

        // ⚠️ S'assurer qu'on ne sort pas du répertoire racine
        if !safe_path.starts_with(&canonical_root) {
            eprintln!("🚨 ALERTE SÉCURITÉ : Tentative de path traversal détectée !");
            eprintln!("Racine autorisée : {}", canonical_root.display());
            eprintln!("Chemin tenté : {}", safe_path.display());
            continue; // Rejeter le chemin
        }
        // On arrete si c'est trop profond pour éviter les attaques DoS
        if depth > MAX_DEPTH {
            stats.depth_limit_hit += 1;
            continue;
        }

        // On tente d'ouvrir le dossier actuel
        // match permet de gérer l'erreur si le dossier est protégé par le système
        let entries = match fs::read_dir(&current_path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        // 3. PARCOURS DES ENTREES DU DOSSIER
        for entry in entries {
            // Si l'entrée est illisible (erreur systéme rare), on l'ignore
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            // On récupere les métadonnées sans suivre les lien symboliques
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };

            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            // --- LOGIQUE DE FILTRAGE ---
            // 1. Si c'est un fichier manifeste on accepte
            let is_manifest = MANIFEST_FILES.contains(&name_str.as_ref());

            // 2. Si ce n'est pas un manifeste et que c'est dans la liste IGNORED on passe
            if !is_manifest && IGNORED_DIRS.contains(&name_str.as_ref()) {
                stats.ignored_count += 1;
                continue;
            }

            // SECURITE : Si c'est un lien symbolique, on l'ignore pour éviter les boucles infinies
            if meta.file_type().is_symlink() {
                continue;
            }

            // CAS 1 : C'est un dossier
            if meta.is_dir() {
                stats.dirs_count += 1;
                // On ajoute le chemin du dossier dans la pile pour qu'il soit scanné plus tard
                stack.push((entry.path(), depth + 1));
            }
            // CAS 2 : C'est un fichier
            else if meta.is_file() {
                // Limite de taille pour ne pas saturer la RAM
                if meta.len() > MAX_FILE_SIZE {
                    stats.oversized_count += 1;
                    continue;
                }

                // On ne délègue au manager que si c'est un fichier qu'il connait
                if is_manifest {
                    stats.files_count += 1;
                    match manager.analyze_file(&entry.path()) {
                        Ok(vulns) => stats.issues_found += vulns.len() as u64,
                        Err(e) => eprintln!("✅ Analyse fichier: {}", e),
                    }
                }

                // --- GESTION DE L'AFFICHAGE DYNAMIQUE (UX) ---
                // S'affiche uniquement si supérieur ou égal à 100ms
                if last_update.elapsed() >= update_interval {
                    frame_idx = (frame_idx + 1) % spinner_frames.len();

                    // On affiche l'état actuel sur une seule ligne
                    print!(
                        "\r{} Scan en cours... [{} manifeste analysés]",
                        spinner_frames[frame_idx], stats.files_count
                    );
                    // Force l'affichage immédiat dans le terminal
                    io::stdout().flush()?;

                    // On réinitialise le chrono pour le prochain intervalle
                    last_update = Instant::now();
                }
            }
        }
    }

    // 4. FINALISATION ET RAPPORT EXACT
    // On efface la ligne du spinner pour un affichage propre
    print!("\r{: <60}\r", "");

    println!("✅ Scan terminé avec succès.");
    println!("📊 Statistiques du projet :");
    println!("   - Manifestes analysés : {}", stats.files_count);
    println!("   - Répertoires parcourus : {}", stats.dirs_count);

    // Section des éléments ignorés (affichée uniquement si nécessaire)
    if stats.ignored_count > 0 || stats.depth_limit_hit > 0 || stats.oversized_count > 0 {
        println!("\nℹ️  Informations sur le filtrage :");

        // Affiche le nombre de dossiers exclus
        if stats.ignored_count > 0 {
            println!("   - Dossiers exclus par défaut : {}", stats.ignored_count);
        }

        // Affiche si la limite de profondeur (40) a été atteinte
        if stats.depth_limit_hit > 0 {
            println!(
                "   - Dossiers trop profonds (> {} niveaux) : {}",
                MAX_DEPTH, stats.depth_limit_hit
            );
        }

        // Affiche si des fichiers étaient trop gros pour être lus en toute sécurité
        if stats.oversized_count > 0 {
            println!(
                "   - Fichiers ignorés car trop volumineux (> 2 Mo) : {}",
                stats.oversized_count
            );
        }
    }

    println!("\n--- RÉSULTAT DE SÉCURITÉ ---");
    if stats.issues_found > 0 {
        println!(
            "🚨 DANGER : {} vulnérabilité(s) détectée(s) dans vos dépendances !",
            stats.issues_found
        );
    } else {
        println!("🛡️  Félicitations : Aucune vulnérabilité connue détectée.");
    }
    Ok(())
}
