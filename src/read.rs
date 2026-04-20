// Fichier pour la lecture du dossier actuel et de ses sous-dossiers de manière sécurisée et robuste
// importer les modules nécessaires pour la lecture du dossier et la gestion des erreurs
use std::{fs::{self}, io, path::Path};

// Fonction pour lire le contenu du dossier actuel de facon robuste et afficher les fichiers et répertoires qu'il contient avec verification
// Si il detecte des repartoires il doit aller dedans est affichier chaque fichier qu'il contient et ainsi de suite pour les sous repartoires.
// La fonction doit intégrer les bonne pratique de sécurité et éviter les faille de sécurité. 
pub fn read_safe_repo<P: AsRef<Path>>(path: P) -> io::Result<()> {
    // Définir le chemin du dossier à lire
    let path: &Path  = path.as_ref();
    // Déclarer la variable pour stocker le chemin du projet de manière dynamique
    let current_dir: std::path::PathBuf = std::env::current_dir()?;

    // Vérifier que le chemin existe et possède un répertoire avant de tenter de le lire pour éviter les erreurs de lecture
    let entries: fs::ReadDir = fs::read_dir(path).map_err(|e| {
        io::Error::new( // Créer une nouvelle erreur d'entrée/sortie avec un message d'erreur détaillé en cas d'échec de la lecture du dossier
            e.kind(), // Utiliser le même type d'erreur que celle générée par la tentative de lecture du dossier pour une gestion cohérente des erreurs
            format!("Erreur lors de la lecture du projet '{}'. Détails: {}", current_dir.display(), e) // Afficher le chemin du projet dans le message d'erreur pour aider à identifier le problème
        )
    })?;

    // Parcourir les entrées du projet
    for entry in entries {
        let entry: fs::DirEntry = entry?; // Gérer les erreurs lors de la lecture des entrées
        let meta: fs::Metadata = entry.path().symlink_metadata()?; // Utiliser symlink_metadata pour obtenir les métadonnées sans suivre les liens symboliques
        let file_type: fs::FileType = meta.file_type(); // Obtenir le type de l'entrée (fichier, répertoire, lien symbolique, etc.)
        let file_name: std::ffi::OsString = entry.file_name(); // Obtenir le nom du fichier
        let file_name_str: std::borrow::Cow<'_, str> = file_name.to_string_lossy(); // Convertir le nom du fichier en une chaîne de caractères pour l'affichage
        
        // Ignorer les liens symboliques pour éviter les problèmes de sécurité liés aux liens symboliques
        if file_type.is_symlink() {
            continue; 
        }

        // Afficher le nom de l'entrée et son type (fichier ou répartoire) et lire les répartoires de manière récursive 
        // pour afficher les fichiers qu'ils contiennent
        if file_type.is_dir() {
            // Afficher le nom du répartoire
            println!("Répartoire: {}", file_name_str);
                // Appeler la fonction de manière récursive pour lire le contenu du répartoire
                let sub_path: std::path::PathBuf = entry.path();
                // Gérer les erreurs lors de la lecture du répartoire de manière appropriée
                if let Err(e) = read_safe_repo(&sub_path) {
                    eprintln!("Erreur lors de la lecture du répartoire '{}'. Détails: {}", sub_path.display(), e);
                }
        // Si c'est un fichier, afficher son nom sinon afficher le nom de l'entrée et indiquer que c'est un autre type d'entrée
        } else if file_type.is_file() {
            println!("Fichier: {}", file_name_str);
        } else {
            println!("Autre type d'entrée: {}", file_name_str);
        }
    }
    Ok(())
}