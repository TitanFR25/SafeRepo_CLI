// Fichier principal du projet 

// Importer les modules nécessaires pour la lecture du dossier
mod scan;

// Point d'entrée du programme avec gestion des erreurs lors de la lecture du dossier dans lequel le programme est exécuté
fn main() {
    let start_path = ".";
    // Appeler la fonction pour lire le dossier Actuel et gérer les erreurs de manière appropriée
    match scan::read_safe_repo(start_path) {
        Ok(()) => println!("\n[Succès] L'arborescence à été scannée avec succès."),
        Err(e) => eprint!("\n[Erreur] Une erreur est survenue lors de la lecture du dossier. Détails: {}", e),
    }
}