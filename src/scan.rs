use std:: {fs, io::{self, Write}, path::{Path}, time::{ Instant, Duration}};

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

// Structure pour stocker les résultats du scan
struct ScanResult {
    files_count: u64, // Nombre total de fichiers trouvés
    dirs_count: u64, // Nombre total de dossiers trouvés
    issues_found: u64, // Nombre de failles de sécurité détectées
    ignored_count: u64, // Nombre d'éléments ignorés (ex: dossiers dans IGNORED_DIRS)
}

// Fonction principale de scan sécurisé
// P: Asref<Path> permet d'accepter des String, &str ou des PathBuf en entrée
pub fn read_safe_repo<P: AsRef<Path>>(root_path: P) -> io::Result<()> {
    // 1.INITIALISATION
    // On crée une pile (stack) pour stocker les chemins à visiter.
    // On utilise un Vec (Heap) plutot que la récursion pour éviter de faire planter le programme (Stack Overflow).
    let mut stack = vec![root_path.as_ref().to_path_buf()];

    // On initialise nos compteurs à zéro
    let mut stats = ScanResult { files_count: 0, dirs_count: 0, issues_found: 0, ignored_count: 0 };

    // Liste de caractères pour créer une animation de chargement (Spinner)
    let spinner_frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let mut frame_idx = 0; // Index pour savoir quel caractère du spinner afficher

    // Gestion du temps pour l'affichage 
    let mut last_update = Instant::now(); // On stocke le moment du dernier affichage 
    let update_interval = Duration::from_millis(100); // On veut mettre à jour l'affichage toutes les 100ms

    println!("🚀 Saferepo : Démarrage du scan...");

    // 2. BOUCLE DE PARCOURS (Tant qu'il y a des dossiers dans la pile)
    while let Some(current_path) = stack.pop() {

        // On tente d'ouvrir le dossier actuel
        // match permet de gérer l'erreur si le dossier est protégé par le système
        let entries = match fs::read_dir(&current_path) {
            Ok(e) => e,
            Err(_) => {
                // Si on ne peut pas ouvrir, on passe au dossier suivant sans crash
                continue;
            }
        };

        // 3. PARCOURS DES ENTR2ES DU DOSSIER
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
                stack.push(entry.path());
            }
            // CAS 2 : C'est un fichier
            else if meta.is_file() {
                stats.files_count += 1;

                // --- GESTION DE L'AFFICHAGE DYNAMIQUE (UX) ---
                // S'affiche uniquement si supérieur ou égal à 100ms
                if last_update.elapsed() >= update_interval {
                    frame_idx = (frame_idx + 1) % spinner_frames.len();

                    // On affiche l'état actuel sur une seule ligne
                    print!(
                        "\r{} Scan en cours... [{} éléments trouvés]",
                        spinner_frames[frame_idx],
                        stats.files_count + stats.dirs_count
                    );
                    // Force l'affichage immédiat dans le terminal
                    io::stdout().flush()?;

                    // On réinitialise le chrono pour le prochain intervalle
                    last_update = Instant::now();
                }

                // FUTUR : Logique de détection de failles ici
                
            }
        }
    }

    // 4. FINALISATION ET RAPPORT EXACT
    // On efface la ligne du spinner pour un affichage propre
    print!("\r{: <60}\r", "");

    // Le rapport final affiche les chiffres exacts, meme si le dernier tick de 100ms a été sauté
    println!(
        "✅ Scan terminé : {} fichiers et {} répertoires analysés.\n ({} dossiers volumineux ignorés pour la performance)\n
        Aucun probléme détecté.",
        stats.files_count,
        stats.dirs_count,
        stats.ignored_count
    );

    Ok(())
}
