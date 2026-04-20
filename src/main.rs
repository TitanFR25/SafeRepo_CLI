// Fichier principal du projet SafeRepo_CLI

use std::{fs, io};

// Fonction pour lire le contenu du dossier actuel de facon robuste et afficher les fichiers et répertoires qu'il contient avec verification
// Si il detecte des repartoires il doit aller dedans est affichier chaque fichier qu'il contient et ainsi de suite pour les sous repartoires.
// La fonction doit compter les bonne pratique de sécurité et eviter les faille de sécurité de base. 
fn read_safe_repo<P: AsRef<std::path::Path>>(path: P) -> io::Result<()> {
    // Définir le chemin du dossier à lire
    let path = path.as_ref();

    // Vérifier si le dossier existe avant de tenter de le lire
    if !fs::metadata(path).is_ok() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "Le dossier 'SafeRepo_CLI' n'existe pas."));
    }

    // Lire le contenu du dossier
    let entries = fs::read_dir(path)?;
    
    // Parcourir les entrées du dossier
    for entry in entries {
        let entry: fs::DirEntry = entry?; // Gérer les erreurs lors de la lecture des entrées
        let file_type: fs::FileType = entry.file_type()?;
        let file_name: std::ffi::OsString = entry.file_name();
        let file_name_str: std::borrow::Cow<'_, str> = file_name.to_string_lossy();

        // Afficher le nom de l'entrée et son type (fichier ou répartoire) et lire les répartoires de manière récursive pour afficher les fichiers qu'ils contiennent
        if file_type.is_dir() {
            println!("Répartoire: {}", file_name_str);
                // Appeler la fonction de manière récursive pour lire le contenu du répartoire
                let sub_path: std::path::PathBuf = entry.path();
                if let Err(e) = read_safe_repo(&sub_path) {
                    eprintln!("Erreur lors de la lecture du répartoire '{}'. Détails: {}", sub_path.display(), e);
                }
        } else if file_type.is_file() {
            println!("Fichier: {}", file_name_str);
        } else {
            println!("Autre type d'entrée: {}", file_name_str);
        }
    }
    Ok(())
}

// Point d'entrée du programme avec gestion des erreurs lors de la lecture du dossier "SafeRepo CLI"
fn main() {
    // Appeler la fonction pour lire le dossier Actuel et gérer les erreurs de manière appropriée
    if let Err(e) = read_safe_repo(".") {
        eprintln!("Erreur lors de la lecture du dossier '.'). Détails: {}", e);
    } else {
        println!("Lecture du dossier actuel terminée avec succès.");
    }
}