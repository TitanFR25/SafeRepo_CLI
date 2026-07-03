// Fichier principal du projet
#![allow(dead_code)]

// Importer depuis la bibliothèque
use SafeRepo_CLI::scaning::scan;
use SafeRepo_CLI::secure::security::SecurityManager;
use std::process;

// Point d'entrée du programme avec gestion des erreurs cohérente et lisible
fn main() {
    let start_path = ".";
    let mut manager = SecurityManager::new("vulnera_db");
    
    // Exécuter le scan et gérer les erreurs de manière professionnelle
    match scan::scan_repo(start_path, &mut manager) {
        Ok(()) => {
            println!("\n✅ [Succès] L'arborescence a été scannée avec succès.");
            process::exit(0);
        }
        Err(e) => {
            eprintln!("\n❌ Erreur lors du scan: {}", e);
            eprintln!("💡 Conseil: Vérifiez les permissions et les chemins d'accès.");
            process::exit(1);
        }
    }
}
