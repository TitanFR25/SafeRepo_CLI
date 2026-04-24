use serde::Deserialize;
use semver::{Version, VersionReq};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

// Représente les niveaux de sévérité d'une faille de sécurité
// Utilisation d'un Enum pour garantir la sécurité des types et faciliter le filtrage
#[derive(Deserialize, Debug, Clone, PartialEq, PartialOrd)] #[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

// Structure principale d'une vulnérabilité (Advisory)
// Conçue pour être compatible avec le format RustSec tout en étant extensible
#[derive(Deserialize, Debug, Clone)]
pub struct Advisory {
    pub id: String, // Identifiant unique de la vulnérabilité
    pub package: String, // Nom de la bibliothéque concernée
    pub severity: Severity, // Niveau d'importance (Crucial pour le dev)
    pub title: String, // Résumé court de la faille
    pub description: String, // Détails techniques 

    // Le block [versions]
    #[serde(skip)]
    pub versions: Versions,
}

// Détails des versions pour le moteur de comparaison SemVer
#[derive(Deserialize, Debug, Clone)]
pub struct Versions {
    pub patched: Vec<String>, // Versions contenant le correctif
    pub unaffected: Option<Vec<String>>, // Versions non affectées
}

impl Default for Versions {
    fn default() -> Self {
        Self { patched: vec![], unaffected: None }
    }
}

// Struture qui gére les fichier de vulnerability
#[derive(Deserialize, Debug)]
pub struct VulnerabilityFile {
    pub advisory : Advisory,
    pub versions: Versions,
}

// La base de données en mémoire
// On utilise une HashMap pour des recherches en O(1) : le nom du package est la clé
// C'est indispensable pour la performance lors de l'analyse de projets avec de nombreuses dépendances
pub struct VulnerabilityDB {
    // Clé : nom du package, Valeur : Liste des vulnérabilités associées
    pub advisories: HashMap<String, Vec<Advisory>>,
}

impl VulnerabilityDB {
    // Initialise une nouvelle base de données vide
    pub fn new() -> Self {
        Self {
            advisories: HashMap::new(),
        }
    }

    // Charge récursivement les fichiers TOML de vulnérabilités
    // Sécurité : Cette fonction ne plante pas, si un fichier est corrompu il est ignoré
    // L'erreur et log pour ne pas interrompre le scan
    pub fn load_from_dir<P: AsRef<Path>>(&mut self, path: P) -> std::io::Result<()> {
        let db_path = path.as_ref();
        if !db_path.exists() {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Dossier DB introuvable"));
        }

        let entries = fs::read_dir(db_path)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            // On ne traite que les fichers .toml
            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                let content = fs::read_to_string(&path)?;


                // Tentative de désérialisation sécurisée
                match toml::from_str::<VulnerabilityFile>(&content) {
                    Ok(mut file_data) => {
                        // Injection du bloc versions dans la structure Advisory
                        file_data.advisory.versions = file_data.versions;

                        let pkg_name = file_data.advisory.package.clone();
                        self.advisories
                        .entry(pkg_name)
                        .or_insert_with(Vec::new)
                        .push(file_data.advisory);
                    }
                    Err(e) => {
                        // Debug utilisateur
                        eprintln!("⚠️ Erreur de parsing dans {:?}: {}", path, e);
                    }
                }
            }
        }
        Ok(())
    }

    // Moteur de matching : Compare une version de crate avec la bdd
    // Retourne une liste de toutes les failles trouvées pour cette version spécifique
    pub fn check_vulnerability(&self, package_name: &str, version: &Version) -> Vec<&Advisory> {
        let mut found_vulnerability = Vec::new();

        // Si le package existe dans notre base de données
        if let Some(list) = self.advisories.get(package_name) {
            for advisory in list {
                // Si la version actuelle n'est pas dans les version patchées, elle est vulnérable
                let is_patched = advisory.versions.patched.iter().any(|v_req| {
                    VersionReq::parse(v_req)
                        .map(|req| req
                        .matches(version))
                        .unwrap_or(false)
                });

                if !is_patched {
                    found_vulnerability.push(advisory);
                }
            }
        }
        found_vulnerability
    }
}