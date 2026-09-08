use crate::database::db::Advisory;
use crate::secure::security::SecurityManager;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::{
    collections::HashSet,
    fs, io,
    path::{Path, PathBuf},
    sync::OnceLock,
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
    "vulnera_db",
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

const ROOT_MARKERS: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "requirements.txt",
    "go.mod",
    "pom.xml",
    "Gemfile",
    "composer.json",
    "pubspec.yaml",
];

fn manifest_files_set() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| MANIFEST_FILES.iter().copied().collect())
}

fn ignored_dirs_set() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| IGNORED_DIRS.iter().copied().collect())
}

pub fn is_manifest_file(name: &str) -> bool {
    manifest_files_set().contains(name)
}

pub fn is_ignored_dir(name: &str) -> bool {
    ignored_dirs_set().contains(name)
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_depth: usize,
    pub max_file_size: u64,
    pub manifest_files: HashSet<String>,
    pub ignored_dirs: HashSet<String>,
    pub exclude_paths: Vec<String>,
    pub database_path: Option<PathBuf>,
    pub threads: Option<usize>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_depth: MAX_DEPTH,
            max_file_size: MAX_FILE_SIZE,
            manifest_files: MANIFEST_FILES
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
            ignored_dirs: IGNORED_DIRS
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
            exclude_paths: Vec::new(),
            database_path: None,
            threads: None,
        }
    }
}

fn is_excluded(path: &Path, root: &Path, options: &ScanOptions) -> bool {
    if let Some(database_path) = &options.database_path
        && (path == database_path || path.starts_with(database_path))
    {
        return true;
    }

    path.strip_prefix(root)
        .ok()
        .map(|relative| {
            relative.components().any(|component| {
                component
                    .as_os_str()
                    .to_str()
                    .is_some_and(|name| options.exclude_paths.iter().any(|pattern| pattern == name))
            })
        })
        .unwrap_or(false)
}

// 🔍 Vérifie si un répertoire est la racine valide d'un projet
/// Retourne true si au moins un fichier de projet racine est détecté
fn is_valid_project_root(path: &Path) -> bool {
    ROOT_MARKERS.iter().any(|marker| path.join(marker).exists())
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
pub fn scan_repo<P: AsRef<Path>>(
    root_path: P,
    manager: &SecurityManager,
    options: &ScanOptions,
) -> io::Result<Vec<Advisory>> {
    // Canonicaliser le chemin (résoudre tous les .., les symlinks, etc.)
    // Cela permet de détecter les tentatives de sortie du répertoire racine
    let mut canonical_root = match std::fs::canonicalize(root_path.as_ref()) {
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
        eprintln!(
            "⚠️ ATTENTION : '{}' n'est pas une racine de projet reconnue",
            canonical_root.display()
        );
        eprintln!(
            "Fichiers marqueurs attendus : Cargo.toml, package.json, requirements.txt, go.mod, etc."
        );

        // Essayer de trouver automatiquement la racine
        if let Some(found_root) = find_project_root(&canonical_root) {
            eprintln!("✅ Racine de projet trouvée : {}", found_root.display());
            eprintln!("   Utilisation de ce répertoire pour le scan...");
            canonical_root = found_root;
            stack = vec![(canonical_root.clone(), 0)]; // Utiliser la racine trouvée
        } else {
            eprintln!("❌ Aucune racine de projet trouvée. Continuation du scan malgré tout...");
            stack = vec![(canonical_root.clone(), 0)]; // Continuer avec le chemin fourni
        }
    } else {
        eprintln!(
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
    let mut detected_vulnerabilities = Vec::new();
    let mut manifest_paths = Vec::new();

    let progress = ProgressBar::new_spinner();
    progress.set_style(
        ProgressStyle::with_template("{msg} {spinner}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    progress.set_message("Scan en cours");
    progress.enable_steady_tick(std::time::Duration::from_millis(100));

    // 2. BOUCLE DE PARCOURS (Tant qu'il y a des dossiers dans la pile)
    while let Some((current_path, depth)) = stack.pop() {
        // Les chemins sont canonicalisés avant leur empilement.
        let safe_path = &current_path;

        if is_excluded(safe_path, &canonical_root, options) {
            stats.ignored_count += 1;
            continue;
        }

        // ⚠️ S'assurer qu'on ne sort pas du répertoire racine
        if !safe_path.starts_with(&canonical_root) {
            eprintln!("🚨 ALERTE SÉCURITÉ : Tentative de path traversal détectée !");
            eprintln!("Racine autorisée : {}", canonical_root.display());
            eprintln!("Chemin tenté : {}", safe_path.display());
            continue; // Rejeter le chemin
        }
        // On arrete si c'est trop profond pour éviter les attaques DoS
        if depth > options.max_depth {
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
            let is_manifest = options.manifest_files.contains(name_str.as_ref());

            // 2. Si ce n'est pas un manifeste et que c'est dans la liste IGNORED on passe
            if !is_manifest && options.ignored_dirs.contains(name_str.as_ref()) {
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
                // Canonicaliser une seule fois avant l'empilement du dossier.
                let child_path = match fs::canonicalize(entry.path()) {
                    Ok(path) => path,
                    Err(_) => continue,
                };
                if !child_path.starts_with(&canonical_root) {
                    eprintln!("🚨 ALERTE SÉCURITÉ : Tentative de path traversal détectée !");
                    continue;
                }
                stack.push((child_path, depth + 1));
            }
            // CAS 2 : C'est un fichier
            else if meta.is_file() {
                // Limite de taille pour ne pas saturer la RAM
                if meta.len() > options.max_file_size {
                    stats.oversized_count += 1;
                    continue;
                }

                // On ne délègue au manager que si c'est un fichier qu'il connait
                if is_manifest {
                    stats.files_count += 1;
                    manifest_paths.push(entry.path());
                }

                progress.set_message(format!(
                    "{} manifeste(s), {} dossier(s) parcouru(s)",
                    stats.files_count, stats.dirs_count
                ));
            }
        }
    }

    progress.set_message(format!(
        "analyse de {} manifeste(s) en cours",
        stats.files_count
    ));

    let thread_pool = match options.threads {
        Some(0) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Le nombre de threads doit être supérieur à zéro",
            ));
        }
        Some(thread_count) => rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .build()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?,
        None => rayon::ThreadPoolBuilder::new()
            .build()
            .map_err(|error| io::Error::other(error.to_string()))?,
    };

    let analysis_results = thread_pool.install(|| {
        manifest_paths
            .par_iter()
            .map(|path| {
                manager
                    .analyze_file(path)
                    .map_err(|error| error.to_string())
            })
            .collect::<Vec<_>>()
    });

    for result in analysis_results {
        match result {
            Ok(vulns) => {
                stats.issues_found += vulns.len() as u64;
                detected_vulnerabilities.extend(vulns);
            }
            Err(error) => eprintln!("⚠️ Analyse du manifeste impossible: {}", error),
        }
    }

    progress.finish_with_message(format!(
        "scan terminé : {} manifeste(s), {} dossier(s)",
        stats.files_count, stats.dirs_count
    ));

    // 4. FINALISATION ET RAPPORT EXACT
    // On efface la ligne du spinner pour un affichage propre
    eprint!("\r{: <60}\r", "");

    eprintln!("✅ Scan terminé avec succès.");
    eprintln!("📊 Statistiques du projet :");
    eprintln!("   - Manifestes analysés : {}", stats.files_count);
    eprintln!("   - Répertoires parcourus : {}", stats.dirs_count);

    // Section des éléments ignorés (affichée uniquement si nécessaire)
    if stats.ignored_count > 0 || stats.depth_limit_hit > 0 || stats.oversized_count > 0 {
        eprintln!("\nℹ️  Informations sur le filtrage :");

        // Affiche le nombre de dossiers exclus
        if stats.ignored_count > 0 {
            eprintln!("   - Dossiers exclus par défaut : {}", stats.ignored_count);
        }

        // Affiche si la limite de profondeur (40) a été atteinte
        if stats.depth_limit_hit > 0 {
            eprintln!(
                "   - Dossiers trop profonds (> {} niveaux) : {}",
                options.max_depth, stats.depth_limit_hit
            );
        }

        // Affiche si des fichiers étaient trop gros pour être lus en toute sécurité
        if stats.oversized_count > 0 {
            eprintln!(
                "   - Fichiers ignorés car trop volumineux (> 2 Mo) : {}",
                stats.oversized_count
            );
        }
    }

    eprintln!("\n--- RÉSULTAT DE SÉCURITÉ ---");
    if stats.issues_found > 0 {
        eprintln!(
            "🚨 DANGER : {} vulnérabilité(s) détectée(s) dans vos dépendances !",
            stats.issues_found
        );
    } else {
        eprintln!("🛡️  Félicitations : Aucune vulnérabilité connue détectée.");
    }
    Ok(detected_vulnerabilities)
}
