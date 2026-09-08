use crate::errorhandle::{SafeRepoError, SafeRepoResult};
use ed25519_dalek::{Signature, VerifyingKey};
use semver::{Version, VersionReq};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::SystemTime;
use std::{collections::HashMap, time::UNIX_EPOCH};

const MAX_DATABASE_FILE_SIZE: u64 = 2 * 1024 * 1024;
const INTEGRITY_MANIFEST_FILE: &str = ".integrity_manifest";
const INTEGRITY_MANIFEST_SIGNATURE_FILE: &str = ".integrity_manifest.sig";
const DB_MANIFEST_PUBLIC_KEY: [u8; 32] = [
    0xaf, 0xc2, 0x76, 0x84, 0x99, 0x10, 0x85, 0xea, 0x42, 0x16, 0xab, 0x1a, 0xfe, 0xba, 0x40, 0xac,
    0x51, 0x42, 0x64, 0x5e, 0x5e, 0x31, 0x6c, 0xd0, 0x96, 0xcc, 0xf5, 0x65, 0x77, 0x66, 0x13, 0x71,
];

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
#[derive(Deserialize, Debug, Clone, Default)]
pub struct Versions {
    #[serde(default)]
    pub introduced: Vec<String>, // Versions à partir desquelles l'advisory s'applique
    #[serde(default)]
    pub fixed: Vec<String>, // Versions à partir desquelles l'advisory est corrigé
    #[serde(default)]
    pub patched: Vec<String>, // Versions contenant le correctif
    #[serde(default)]
    pub unaffected: Option<Vec<String>>, // Versions non affectées
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
        let data = fs::read(file_path).map_err(|e| SafeRepoError::ScanError {
            file_path: file_path.display().to_string(),
            reason: format!("Failed to read file for hashing: {}", e),
        })?;

        Ok(Self::hash_bytes(&data))
    }

    fn hash_bytes(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub(crate) fn hash_bytes_for_update(data: &[u8]) -> String {
        Self::hash_bytes(data)
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

    fn embedded_manifest_verifying_key() -> SafeRepoResult<VerifyingKey> {
        VerifyingKey::from_bytes(&DB_MANIFEST_PUBLIC_KEY).map_err(|error| {
            SafeRepoError::DatabaseError {
                operation: "loading embedded integrity public key".to_string(),
                reason: error.to_string(),
            }
        })
    }

    fn read_verified_integrity_manifest(
        db_path: &Path,
        verifying_key: &VerifyingKey,
    ) -> SafeRepoResult<String> {
        let manifest_path = db_path.join(INTEGRITY_MANIFEST_FILE);
        let signature_path = db_path.join(INTEGRITY_MANIFEST_SIGNATURE_FILE);
        let manifest = fs::read(&manifest_path).map_err(|error| SafeRepoError::DatabaseError {
            operation: "reading integrity manifest".to_string(),
            reason: format!("{}: {}", manifest_path.display(), error),
        })?;
        let signature_bytes =
            fs::read(&signature_path).map_err(|error| SafeRepoError::DatabaseError {
                operation: "reading integrity manifest signature".to_string(),
                reason: format!("{}: {}", signature_path.display(), error),
            })?;
        let signature_bytes: [u8; 64] =
            signature_bytes
                .try_into()
                .map_err(|_| SafeRepoError::DatabaseError {
                    operation: "validating integrity manifest signature".to_string(),
                    reason: format!("{} must contain exactly 64 bytes", signature_path.display()),
                })?;
        verifying_key
            .verify_strict(&manifest, &Signature::from_bytes(&signature_bytes))
            .map_err(|error| SafeRepoError::DatabaseError {
                operation: "verifying integrity manifest signature".to_string(),
                reason: error.to_string(),
            })?;

        String::from_utf8(manifest).map_err(|error| SafeRepoError::DatabaseError {
            operation: "decoding integrity manifest".to_string(),
            reason: error.to_string(),
        })
    }

    fn parse_integrity_manifest(content: &str) -> Result<Vec<FileIntegrity>, String> {
        let mut entries = Vec::new();
        let mut pending_path: Option<String> = None;
        let mut pending_hash: Option<String> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(path) = line.strip_prefix("SHA256: ") {
                if pending_path.is_none() {
                    return Err("SHA256 entry without a file path".to_string());
                }
                pending_hash = Some(path.to_string());
            } else if let Some(size) = line.strip_prefix("Size: ") {
                let size = size
                    .strip_suffix(" bytes")
                    .ok_or_else(|| "Invalid file size entry".to_string())?
                    .parse::<u64>()
                    .map_err(|_| "Invalid file size value".to_string())?;
                let file_path = pending_path
                    .take()
                    .ok_or_else(|| "Size entry without a file path".to_string())?;
                let sha256_hash = pending_hash
                    .take()
                    .ok_or_else(|| "Size entry without a SHA256 hash".to_string())?;
                entries.push(FileIntegrity {
                    file_path,
                    sha256_hash,
                    file_size: size,
                    last_modified: 0,
                });
            } else if pending_path.is_some() {
                return Err("Invalid integrity manifest entry".to_string());
            } else {
                pending_path = Some(line.to_string());
            }
        }

        if pending_path.is_some() || pending_hash.is_some() {
            return Err("Incomplete integrity manifest entry".to_string());
        }

        Ok(entries)
    }

    fn integrity_entries_match(expected: &[FileIntegrity], actual: &[FileIntegrity]) -> bool {
        expected.len() == actual.len()
            && expected.iter().all(|expected_entry| {
                actual.iter().any(|actual_entry| {
                    (actual_entry.file_path == expected_entry.file_path
                        || (!Path::new(&expected_entry.file_path).is_absolute()
                            && Path::new(&actual_entry.file_path).file_name().is_some_and(
                                |name| name == Path::new(&expected_entry.file_path).as_os_str(),
                            )))
                        && actual_entry.sha256_hash == expected_entry.sha256_hash
                        && actual_entry.file_size == expected_entry.file_size
                })
            })
    }

    // 🔍 Valide un fichier TOML et retourne une structure typée ou une erreur explicite
    // Cette fonction refuse tout TOML malformé et log l'erreur de manière détaillée
    pub fn validate_vulnerability_file_for_release(
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

        // 2. Normaliser la forme d'alias produite par certains exports PowerShell.
        let normalized_content = Self::normalize_legacy_alias_array_syntax(content);

        // 3. Parser le TOML et capturer l'erreur
        match toml::from_str::<VulnerabilityFile>(&normalized_content) {
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

                // Une advisory doit décrire au moins une borne ou un correctif.
                if file_data.versions.patched.is_empty()
                    && file_data.versions.fixed.is_empty()
                    && file_data.versions.introduced.is_empty()
                {
                    return Err(format!(
                        "⚠️ AVERTISSEMENT : {} - Aucune version affectée ou corrigée définie",
                        file_path.display()
                    ));
                }

                // out est valide
                Ok(file_data)
            }
            Err(local_error) => {
                let osv_data =
                    toml::from_str::<crate::osv::client::OsvVulnerability>(&normalized_content)
                    .map_err(|osv_error| {
                        format!(
                            "❌ Fichier de vulnérabilité INVALIDE dans {} : format local: {}; format OSV: {}",
                            file_path.display(),
                            local_error,
                            osv_error
                        )
                    })?;
                let advisory = crate::osv::client::OsvClient::convert_to_advisory(&osv_data)
                    .ok_or_else(|| {
                        format!(
                            "❌ Aucun package affecté exploitable dans {}",
                            file_path.display()
                        )
                    })?;
                if advisory.package == "unknown"
                    || (advisory.versions.introduced.is_empty()
                        && advisory.versions.fixed.is_empty()
                        && advisory.versions.patched.is_empty())
                {
                    return Err(format!(
                        "⚠️ Aucun package ou événement de version exploitable dans {}",
                        file_path.display()
                    ));
                }
                Ok(VulnerabilityFile {
                    versions: advisory.versions.clone(),
                    advisory,
                })
            }
        }
    }

    fn normalize_legacy_alias_array_syntax(content: &str) -> String {
        content
            .lines()
            .map(|line| {
                let trimmed = line.trim_start();
                if trimmed.starts_with("aliases = @(") && trimmed.trim_end().ends_with(')') {
                    let prefix_len = line.len() - trimmed.len();
                    let body = &trimmed["aliases = @(".len()..trimmed.trim_end().len() - 1];
                    format!(
                        "{}aliases = [{}]{}",
                        &line[..prefix_len],
                        body,
                        &trimmed[trimmed.trim_end().len()..]
                    )
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
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
        let verifying_key = Self::embedded_manifest_verifying_key()?;
        self.load_from_dir_with_verifying_key(path, &verifying_key)
    }

    pub fn load_from_dir_with_verifying_key<P: AsRef<Path>>(
        &mut self,
        path: P,
        verifying_key: &VerifyingKey,
    ) -> SafeRepoResult<()> {
        let db_path = path.as_ref();
        if !db_path.exists() {
            return Err(SafeRepoError::DatabaseError {
                operation: "load_from_dir".to_string(),
                reason: format!("Database path does not exist: {}", db_path.display()),
            });
        }

        let manifest_content = Self::read_verified_integrity_manifest(db_path, verifying_key)?;
        let expected_manifest =
            Self::parse_integrity_manifest(&manifest_content).map_err(|reason| {
                SafeRepoError::DatabaseError {
                    operation: "parsing integrity manifest".to_string(),
                    reason,
                }
            })?;

        let entries = fs::read_dir(db_path).map_err(|e| SafeRepoError::DatabaseError {
            operation: "reading database directory".to_string(),
            reason: format!("{}: {}", db_path.display(), e),
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

            let file_size = match fs::metadata(&file_path) {
                Ok(metadata) => metadata.len(),
                Err(e) => {
                    let err = SafeRepoError::IoError {
                        context: format!("reading metadata: {}", file_path.display()),
                        source: e,
                    };
                    eprintln!("⚠️ {}", err);
                    error_count += 1;
                    errors_log.push(err.to_string());
                    continue;
                }
            };
            if file_size > MAX_DATABASE_FILE_SIZE {
                let err = format!(
                    "Database file too large: {} ({} bytes, maximum {} bytes)",
                    file_path.display(),
                    file_size,
                    MAX_DATABASE_FILE_SIZE
                );
                eprintln!("⚠️ {}", err);
                error_count += 1;
                errors_log.push(err);
                continue;
            }

            // Lire une seule fois le contenu du fichier pour éviter un double I/O
            let file_bytes = match fs::read(&file_path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    let err = SafeRepoError::IoError {
                        context: format!("reading: {}", file_path.display()),
                        source: e,
                    };
                    eprintln!("⚠️ {}", err);
                    error_count += 1;
                    errors_log.push(err.to_string());
                    continue;
                }
            };

            let file_hash = Self::hash_bytes(&file_bytes);
            let content = match std::str::from_utf8(&file_bytes) {
                Ok(c) => c.to_string(),
                Err(e) => {
                    let err = SafeRepoError::IoError {
                        context: format!("decoding UTF-8: {}", file_path.display()),
                        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
                    };
                    eprintln!("⚠️ {}", err);
                    error_count += 1;
                    errors_log.push(err.to_string());
                    continue;
                }
            };

            // Tentative de désérialisation sécurisée
            match Self::validate_vulnerability_file_for_release(&file_path, &content) {
                Ok(mut file_data) => {
                    // Injection du bloc versions dans la structure Advisory
                    file_data.advisory.versions = file_data.versions;

                    let pkg_name = file_data.advisory.package.clone();

                    self.advisories
                        .entry(pkg_name)
                        .or_default()
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

                    if let Some(last_err) = errors_log.last()
                        && Self::is_critical_toml_error(last_err)
                    {
                        eprintln!("🚨 ALERTE: Erreur TOML critique détectée");
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

        if !Self::integrity_entries_match(&expected_manifest, &integrity_hashes) {
            return Err(SafeRepoError::DatabaseError {
                operation: "verifying integrity manifest".to_string(),
                reason: "database files differ from the recorded manifest".to_string(),
            });
        }

        // Rapport final informatif
        eprintln!("✅ Chargement DB terminé:");
        eprintln!("   ✓ {} fichier(s) valide(s)", success_count);
        eprintln!("   ⚠️ {} erreur(s)", error_count);

        if !errors_log.is_empty() {
            eprintln!("\n📋 Erreurs rencontrées:");
            for err in &errors_log {
                eprintln!("   - {}", err);
            }
        }

        // Une base vide ne peut pas produire de résultats de sécurité fiables.
        if success_count == 0 {
            return Err(SafeRepoError::DatabaseError {
                operation: "load_from_dir".to_string(),
                reason: format!(
                    "No valid advisory files were loaded ({} file errors)",
                    error_count
                ),
            });
        }

        Ok(())
    }

    // Vérifier la DB contre le manifeste précédent
    pub fn verify_database_integrity(&self, db_path: &Path) -> Result<bool, String> {
        let verifying_key =
            Self::embedded_manifest_verifying_key().map_err(|error| error.to_string())?;
        self.verify_database_integrity_with_verifying_key(db_path, &verifying_key)
    }

    pub fn verify_database_integrity_with_verifying_key(
        &self,
        db_path: &Path,
        verifying_key: &VerifyingKey,
    ) -> Result<bool, String> {
        match Self::read_verified_integrity_manifest(db_path, verifying_key) {
            Ok(content) if !content.trim().is_empty() => {
                let expected = Self::parse_integrity_manifest(&content)?;
                let mut actual = Vec::new();
                let entries = fs::read_dir(db_path)
                    .map_err(|e| format!("Impossible de lire la DB: {}", e))?;

                for entry in entries {
                    let file_path = entry
                        .map_err(|e| format!("Impossible de lire une entrée: {}", e))?
                        .path();
                    if file_path.extension().and_then(|s| s.to_str()) != Some("toml") {
                        continue;
                    }
                    let metadata = fs::metadata(&file_path)
                        .map_err(|e| format!("Impossible de lire les métadonnées: {}", e))?;
                    actual.push(FileIntegrity {
                        file_path: file_path.display().to_string(),
                        sha256_hash: Self::calculate_file_hash(&file_path)
                            .map_err(|e| format!("Erreur de hash: {}", e))?,
                        file_size: metadata.len(),
                        last_modified: 0,
                    });
                }

                if !Self::integrity_entries_match(&expected, &actual) {
                    return Ok(false);
                }

                eprintln!("✅ Toute la DB a été vérifiée - Aucune modification détectée");
                Ok(true)
            }
            Ok(_) => Err("⚠️ Le manifeste d'intégrité est vide".to_string()),
            Err(error) => Err(error.to_string()),
        }
    }

    // Moteur de matching : Compare une version de crate avec la bdd
    // Retourne une liste de toutes les failles trouvées pour cette version spécifique
    pub fn check_vulnerability(&self, package_name: &str, version: &Version) -> Vec<&Advisory> {
        let mut found_vulnerability = Vec::new();

        // Si le package existe dans notre base de données
        if let Some(list) = self.advisories.get(package_name) {
            for advisory in list {
                if advisory_affects_version(advisory, version) {
                    found_vulnerability.push(advisory);
                }
            }
        }
        found_vulnerability
    }
}

fn advisory_affects_version(advisory: &Advisory, version: &Version) -> bool {
    if advisory
        .versions
        .unaffected
        .as_ref()
        .is_some_and(|requirements| {
            requirements
                .iter()
                .any(|req| matches_requirement(req, version))
        })
    {
        return false;
    }

    if !advisory.versions.introduced.is_empty() || !advisory.versions.fixed.is_empty() {
        let range_count = advisory
            .versions
            .introduced
            .len()
            .max(advisory.versions.fixed.len());
        return (0..range_count).any(|index| {
            let introduced = advisory
                .versions
                .introduced
                .get(index)
                .and_then(|value| parse_version(value));
            let fixed = advisory
                .versions
                .fixed
                .get(index)
                .and_then(|value| parse_version(value));

            introduced.as_ref().is_none_or(|lower| version >= lower)
                && fixed.as_ref().is_none_or(|upper| version < upper)
                && (introduced.is_some() || fixed.is_some())
        });
    }

    !advisory
        .versions
        .patched
        .iter()
        .any(|requirement| matches_requirement(requirement, version))
}

fn parse_version(value: &str) -> Option<Version> {
    Version::parse(value).ok().or_else(|| {
        let normalized = value.trim().trim_start_matches('v');
        let parts: Vec<&str> = normalized.split('.').collect();
        if parts.len() == 1 {
            format!("{}.0.0", normalized).parse().ok()
        } else if parts.len() == 2 {
            format!("{}.0", normalized).parse().ok()
        } else {
            None
        }
    })
}

fn matches_requirement(requirement: &str, version: &Version) -> bool {
    VersionReq::parse(requirement)
        .map(|parsed| parsed.matches(version))
        .unwrap_or_else(|_| parse_version(requirement).is_some_and(|exact| &exact == version))
}

impl Default for VulnerabilityDB {
    fn default() -> Self {
        Self::new()
    }
}
