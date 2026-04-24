use crate::database::db::{VulnerabilityDB, Advisory};
use serde::Deserialize;
use std::path::Path;
use std::fs;
use semver::Version;

// Struture temporaire pour parser le fichier Cargo.lock
// Le format Cargo.lock utilise des blocs [[package]]
#[derive(Deserialize)]
struct CargoLock { #[serde(rename = "package")]
    packages: Vec<PackageEntry>,    
}

#[derive(Deserialize)]
struct PackageEntry {
    name: String,
    version: String,
}

// Gére la logique de sécurité et l'orchestration des analyses
pub struct SecurityManager {
    db: VulnerabilityDB,
}

impl SecurityManager {
    // Initialise le manager et charge la base de données
    pub fn new(db_path: &str) -> Self {
        let mut db = VulnerabilityDB::new();
        if let Err(e) = db.load_from_dir(db_path) {
            eprintln!("⚠️ [security] Erreur de chargement de la DB : {}", e);
        }
        Self { db }
    }

    // Point d'entrée principal pour analyser un fichier détecté
    pub fn analyze_file(&self, path: &Path) -> u64{
        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

        match file_name {
            "Cargo.lock" => self.process_cargo_lock(path),
            // On pourra ajouter package-lock.json ect ici
            _ => 0,
        }
    }

    // Parse le Cargo.lock et vérifie chaque dépendance contre la DB
    fn process_cargo_lock(&self, path: &Path) -> u64 {
        let mut count = 0;
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return 0,
        };

        // Désérialisation sécurisée du lockfile
        if let Ok(lock) = toml::from_str::<CargoLock>(&content) {
            for pkg in lock.packages {
                if let Ok(current_ver) = Version::parse(&pkg.version) {
                    let issues = self.db.check_vulnerability(&pkg.name, &current_ver);

                    for issue in issues {
                        self.report_vulnerability(&pkg.name, &pkg.version, issue);
                        count += 1;
                    }
                }
            }
        }
        count
    } 

    // Affiche une alerte formatée pour le développeur
    fn report_vulnerability(&self, name: &str, ver: &str, adv: &Advisory) {
        println!(
            "\n[!] VULNÉRABILITÉ DÉTECTÉE\n\
            Package  : {} (v{})\n\
            ID       : {}\n\
            Sévérité : {:?}\n\
            Titre    : {}\n\
            Détails  : {}",
            name, ver, adv.id, adv.severity, adv.title, adv.description
        );
    }
}