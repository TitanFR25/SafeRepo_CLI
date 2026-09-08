// Fichier principal du projet
#![allow(dead_code)]

use SafeRepo_CLI::command::cli::Cli;
use std::process;

// Point d'entrée du programme avec gestion des erreurs cohérente et lisible
fn main() {
    let cli = Cli::parse_args();

    if let Err(error) = cli.execute() {
        eprintln!("\n❌ Erreur: {error}");
        process::exit(1);
    }
}
