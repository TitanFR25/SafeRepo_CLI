// Fichier principal du projet 

// Importer les dossiers pour les fichier rs
mod scaning;
mod database;
mod secure;
// Importer les fichier rs dans les differents dossiers
use secure::security::SecurityManager;
use scaning::scan;

// Point d'entrée du programme avec gestion des erreurs lors de la lecture du dossier dans lequel le programme est exécuté
fn main() {
    let start_path = ".";
    let manager = SecurityManager::new("vulnera_db");
    // Appeler la fonction pour lire le dossier Actuel et gérer les erreurs de manière appropriée
    match scan::scan_repo(start_path, &manager) {
        Ok(()) => println!("\n[Succès] L'arborescence à été scannée avec succès."),
        Err(e) => eprint!("\n[Erreur] Une erreur est survenue lors de la lecture du dossier. Détails: {}", e),
    }
}