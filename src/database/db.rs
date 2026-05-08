use crate::errorhandle::errors::{SafeRepoError, SafeRepoResult};
use semver::{Version, VersionReq};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::SystemTime;
use std::{collections::HashMap, time::UNIX_EPOCH};

// Représente les niveaux de sévérité d'une faille de sécurité
// Utilisation d'un Enum pour garantir la sécurité des types et faciliter le filtrage
#[derive(Deserialize, Debug, Clone, PartialEq, PartialOrd)]
#[serde(rename_all = "lowercase")]
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
    pub id: String,          // Identifiant unique de la vulnérabilité
    pub package: String,     // Nom de la bibliothéque concernée
    pub severity: Severity,  // Niveau d'importance (Crucial pour le dev)
    pub title: String,       // Résumé court de la faille
    pub description: String, // Détails techniques

    // Le block [versions]
    #[serde(skip)]
    pub versions: Versions,
}

// Détails des versions pour le moteur de comparaison SemVer
#[derive(Deserialize, Debug, Clone)]
pub struct Versions {
    pub patched: Vec<String>,            // Versions contenant le correctif
    pub unaffected: Option<Vec<String>>, // Versions non affectées
}

impl Default for Versions {
    fn default() -> Self {
        Self {
            patched: vec![],
            unaffected: None,
        }
    }
}
// Structure pour stocker l'intégriter des fichiers
#[derive(Debug, Clone)]
pub struct FileIntegrity {
    pub file_path: String,   // Chemin du fichier
    pub sha256_hash: String, // Hash SHA-256
    pub file_size: u64,      // Taille du fichier
    pub last_modified: i64,  // Timestamp en ms
}

// Structure pour l'audit de la DB
#[derive(Debug, Clone)]
pub struct DatabaseAudit {
    pub advisories: Vec<FileIntegrity>, // Hash de tout les fichiers valides
    pub total_files: u64,               // Nombres de fichier chargés
    pub failed_files: u64,              // Nombre de fichiers échoués
    pub last_loaded: i64,               // Timestamp du dernier chargement
}

// Struture qui gére les fichier de vulnerability
#[derive(Deserialize, Debug)]
pub struct VulnerabilityFile {
    pub advisory: Advisory,
    pub versions: Versions,
}

// La base de données en mémoire
// On utilise une HashMap pour des recherches en O(1) : le nom du package est la clé
// C'est indispensable pour la performance lors de l'analyse de projets avec de nombreuses dépendances
pub struct VulnerabilityDB {
    // Clé : nom du package, Valeur : Liste des vulnérabilités associées
    pub advisories: HashMap<String, Vec<Advisory>>,
    pub integrity_log: Option<DatabaseAudit>, // Ajouter le log d'audit
}

impl VulnerabilityDB {
    // Initialise une nouvelle base de données vide
    pub fn new() -> Self {
        Self {
            advisories: HashMap::new(),
            integrity_log: None,
        }
    }

    // Calcule le hash256 d'un fichier
    // Retourne le hash en format hexadecimal
    pub fn calculate_file_hash(file_path: &Path) -> SafeRepoResult<String> {
        // Lire le fichier avec gestion d'erreur
        let data = fs::read(file_path).map_err(|e| SafeRepoError::IoError {
            context: format!("reading file for hash: {}", file_path.display()),
            source: e,
        })?;

        // Créer le hasher
        let mut hasher = Sha256::new();
        hasher.update(&data);

        // Convertir en hexadecimal
        let result = hasher.finalize();
        let hex_string = result
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        Ok(hex_string)
    }

    // Valide l'intégrité d'un fichier contre un hash connu
    // retourne true si le hash correspond
    pub fn verify_file_integrity(file_path: &Path, expected_hash: &str) -> SafeRepoResult<bool> {
        // Calculer le hash - propager l'erreur
        let current_hash = Self::calculate_file_hash(file_path)?;

        let matches = current_hash == expected_hash;

        if !matches {
            eprintln!(
                "🚨 ALERTE INTÉGRITÉ : Fichier modifié détecté!\n\
                 Fichier: {}\n\
                 Hash attendu: {}\n\
                 Hash calculé: {}",
                file_path.display(),
                expected_hash,
                current_hash
            );
        }

        Ok(matches)
    }

    // Créer un manifeste d'intégrité
    // Ce fichier est stocké pour auditer les changements de DB
    fn generate_integrity_manifest(
        db_path: &Path,
        file_hashes: Vec<FileIntegrity>,
    ) -> Result<(), String> {
        let manifest_path = db_path.join(".integrity_manifest");

        let mut manifest_content = String::new();
        manifest_content.push_str("# Database Integrity Manifest\n");
        manifest_content.push_str(&format!("# Generated: {}\n\n", chrono::Local::now()));

        for file_integrity in &file_hashes {
            manifest_content.push_str(&format!(
                "{}\n  SHA256: {}\n  Size: {} bytes\n\n",
                file_integrity.file_path, file_integrity.sha256_hash, file_integrity.file_size
            ));
        }

        match std::fs::write(&manifest_path, manifest_content) {
            Ok(_) => {
                println!(
                    "✅ Manifeste d'intégrité créé : {}",
                    manifest_path.display()
                );
                Ok(())
            }
            Err(e) => Err(format!("❌ Impossible de créer le manifeste : {}", e)),
        }
    }

    // 🔍 Valide un fichier TOML et retourne une structure typée ou une erreur explicite
    // Cette fonction refuse tout TOML malformé et log l'erreur de manière détaillée
    fn validate_vulnerability_file(
        file_path: &Path,
        content: &str,
    ) -> Result<VulnerabilityFile, String> {
        // 1. Vérifier que le fichier est pas vide
        if content.trim().is_empty() {
            return Err(format!(
                "❌ Fichier vide : {} - Les fichiers de vulnérabilités doivent contenir des données",
                file_path.display()
            ));
        }

        // 2. Parser le TOML et capturer l'erreur
        match toml::from_str::<VulnerabilityFile>(content) {
            Ok(file_data) => {
                // Validation sémantique (même si c'est un TOML valide syntaxiquement)

                // Vérifier que l'ID de vulnérabilité n'est pas vide
                if file_data.advisory.id.trim().is_empty() {
                    return Err(format!(
                        "❌ Validation échouée dans {} : Le champ 'id' est vide",
                        file_path.display()
                    ));
                }

                // Vérifier que le package n'est pas vide
                if file_data.advisory.package.trim().is_empty() {
                    return Err(format!(
                        "❌ Validation échouée dans {} : Le champ 'package' est vide",
                        file_path.display()
                    ));
                }

                // Vérifier que la liste des versions patchées n'est pas vide
                if file_data.versions.patched.is_empty() {
                    return Err(format!(
                        "⚠️ AVERTISSEMENT : {} - Aucune version patchée définie (champ 'patched' vide)",
                        file_path.display()
                    ));
                }

                // out est valide
                Ok(file_data)
            }
            Err(e) => {
                // Capturer l'erreur TOML détaillée
                Err(format!(
                    "❌ Cargo.lock INVALIDE dans {} : {}",
                    file_path.display(),
                    e
                ))
            }
        }
    }

    // Détermine la sécurité d'une erreur TOML
    fn is_critical_toml_error(error_msg: &str) -> bool {
        // Erreur critiques qui empechent le scan de continuer
        let critical_patterns = [
            "duplicate",      // Clé dupliqué
            "invalid syntax", // Syntaxe invalide
            "expected",       // Structure invalide
        ];
        critical_patterns
            .iter()
            .any(|pattern| error_msg.to_lowercase().contains(pattern))
    }

    // Charge récursivement les fichiers TOML de vulnérabilités
    // Sécurité : Cette fonction ne plante pas, si un fichier est corrompu il est ignoré
    // L'erreur et log pour ne pas interrompre le scan
    pub fn load_from_dir<P: AsRef<Path>>(&mut self, path: P) -> SafeRepoResult<()> {
        let db_path = path.as_ref();
        if !db_path.exists() {
            return Err(SafeRepoError::DatabaseError {
                operation: "load_from_dir".to_string(),
                reason: format!("Database path does not exist: {}", db_path.display()),
            });
        }

        let entries = fs::read_dir(db_path).map_err(|e| SafeRepoError::IoError {
            context: format!("reading database directory: {}", db_path.display()),
            source: e,
        })?;
        let mut integrity_hashes = Vec::new(); // Stocker les hash
        let mut error_count = 0; // Compteur d'erreurs
        let mut success_count = 0; // Compteur de fichier traité avec succées
        let mut errors_log: Vec<String> = Vec::new(); // Logger les erreurs pour le rapport

        for entry in entries {
            // Gérer les erreurs de lecture d'entrée
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("⚠️ Erreur lecture entrée: {}", e);
                    error_count += 1;
                    continue; // Continuer au prochain fichier, pas de crash
                }
            };
            let file_path = entry.path();

            // On ne traite que les fichers .toml
            if file_path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            // Calculer le hash avant de le parser avec gestion d'erreur
            let file_hash = match Self::calculate_file_hash(&file_path) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!(
                        "⚠️ Impossible de calculer hash pour {}: {}",
                        file_path.display(),
                        e
                    );
                    error_count += 1;
                    errors_log.push(e.to_string());
                    continue; // Continuer sans crash
                }
            };

            // Lire le contenu du fichier avec gestion d'erreur
            let content = match fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(e) => {
                    let err = SafeRepoError::IoError {
                        context: format!("reading: {}", file_path.display()),
                        source: e,
                    };
                    eprintln!("⚠️ {}", err);
                    error_count += 1;
                    errors_log.push(err.to_string());
                    continue; // Continuer sans crash
                }
            };

            // Tentative de désérialisation sécurisée
            match Self::validate_vulnerability_file(&file_path, &content) {
                Ok(mut file_data) => {
                    // Injection du bloc versions dans la structure Advisory
                    file_data.advisory.versions = file_data.versions;

                    let pkg_name = file_data.advisory.package.clone();

                    self.advisories
                        .entry(pkg_name)
                        .or_insert_with(Vec::new)
                        .push(file_data.advisory);

                    // Stocker le hash et les métadonnées
                    if let Ok(metadata) = fs::metadata(&file_path) {
                        integrity_hashes.push(FileIntegrity {
                            file_path: file_path.display().to_string(),
                            sha256_hash: file_hash.clone(),
                            file_size: metadata.len(),
                            last_modified: metadata
                                .modified()
                                .ok()
                                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                                .map(|d| d.as_millis() as i64)
                                .unwrap_or(0),
                        });
                        success_count += 1;
                    } else {
                        error_count += 1;
                    }
                }
                Err(e) => {
                    // ✅ Erreur validée - log et continuer
                    eprintln!("⚠️ {}", e);
                    error_count += 1;
                    errors_log.push(e);

                    if let Some(last_err) = errors_log.last() {
                        if Self::is_critical_toml_error(last_err) {
                            eprintln!("🚨 ALERTE: Erreur TOML critique détectée");
                        }
                    }
                }
            }
        }

        // Créer l'audit et le manifeste (après avoir traité tous les fichiers)
        self.integrity_log = Some(DatabaseAudit {
            advisories: integrity_hashes.clone(),
            total_files: success_count,
            failed_files: error_count,
            last_loaded: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
        });

        // Génerer le manifest
        if !integrity_hashes.is_empty() {
            // On ignore l'erreur de manifeste (pas critique)
            if let Err(e) = Self::generate_integrity_manifest(db_path, integrity_hashes) {
                eprintln!("⚠️ Manifeste non généré: {}", e);
            }
        }

        // Rapport final informatif
        println!("✅ Chargement DB terminé:");
        println!("   ✓ {} fichier(s) valide(s)", success_count);
        println!("   ⚠️ {} erreur(s)", error_count);

        if !errors_log.is_empty() {
            println!("\n📋 Erreurs rencontrées:");
            for err in &errors_log {
                println!("   - {}", err);
            }
        }

        // Retourner Error si tout a échoué
        if success_count == 0 && error_count > 0 {
            return Err(SafeRepoError::DatabaseError {
                operation: "load_from_dir".to_string(),
                reason: format!("Database corrupted: {} file(s) failed to load", error_count),
            });
        }

        Ok(())
    }

    // Vérifier la DB contre le manifeste précédent
    pub fn verify_database_integrity(&self, db_path: &Path) -> Result<bool, String> {
        let manifest_path = db_path.join(".integrity_manifest");

        if !manifest_path.exists() {
            return Err(
                "❌ Aucun manifeste d'intégrité trouvé - DB n'a jamais été vérifiée".to_string(),
            );
        }

        match &self.integrity_log {
            Some(audit) => {
                println!("🔍 Vérification d'intégrité de la DB...");
                println!("   Fichiers enregistrés : {}", audit.total_files);

                // Vérifier chaque fichier
                for file_integrity in &audit.advisories {
                    match Self::verify_file_integrity(
                        std::path::Path::new(&file_integrity.file_path),
                        &file_integrity.sha256_hash,
                    ) {
                        Ok(false) => return Ok(false), // Modification détectée
                        Err(e) => return Err(format!("Erreur vérification: {}", e)),
                        _ => {}
                    }
                }

                println!("✅ Toute la DB a été vérifiée - Aucune modification détectée");
                Ok(true) // Intégrité confirmée
            }
            None => Err("⚠️ Aucun audit d'intégrité disponible".to_string()),
        }
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
                        .map(|req| req.matches(version))
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
