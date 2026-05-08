// Fichier principal du projet
#![allow(dead_code)]

// Importer depuis la bibliothèque
use SafeRepo_CLI::scaning::scan;
use SafeRepo_CLI::secure::security::SecurityManager;

// Point d'entrée du programme avec gestion des erreurs lors de la lecture du dossier dans lequel le programme est exécuté
fn main() {
    let start_path = ".";
    let mut manager = SecurityManager::new("vulnera_db");
    // Appeler la fonction pour lire le dossier Actuel et gérer les erreurs de manière appropriée
    match scan::scan_repo(start_path, &mut manager) {
        Ok(()) => println!("\n[Succès] L'arborescence à été scannée avec succès."),
        Err(e) => eprint!(
            "\n[Erreur] Une erreur est survenue lors de la lecture du dossier. Détails: {}",
            e
        ),
    }
}
