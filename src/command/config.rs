use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use log::{info, debug};

use crate::errorhandle::{SafeRepoError, SafeRepoResult};

// Struture pour répresenter la configuration SafeRepo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeRepoConfig {
    // Patterns à ignorer lors du scan
    #[serde(default)]
    pub ignore_patterns: Vec<String>,

    // Sévérité minimale pour les vulnérabilités (critical, high, medium, low)
    #[serde(default = "default_min_severity")]
    pub min_severity: String,

    // Extensions de fichiers à scanner
    #[serde(default = "default_manifest_files")]
    pub manifest_files: Vec<String>,

    // Chemins personnalisés à ignorer
    #[serde(default)]
    pub exclude_paths: Vec<String>,

    // Limite de profondeur de récursion
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,

    // Taille maximale des fichiers (en bytes)
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,

    // Nombre de threads pour le scan parallèle
    #[serde(default)]
    pub threads: Option<usize>,

    // Activer le logging verbeux par défaut
    #[serde(default)]
    pub verbose: bool,

    // Format de sortie par défaut (text, json, html)
    #[serde(default = "default_output_format")]
    pub output_format: String,

    // Activer la vérification des signatures GPG
    #[serde(default)]
    pub verify_signatures: bool,

    // Chemin de la base de données de vulnérabilités
    #[serde(default = "default_db_path")]
    pub db_path: String,
}

// Valeur par défaut
fn default_min_severity() -> String {
    "medium".to_string()
}

fn default_manifest_files() -> Vec<String> {
    vec![
        "Cargo.lock".to_string(),
        "Cargo.toml".to_string(),
        "package.json".to_string(),
        "package-lock.json".to_string(),
        "requirements.txt".to_string(),
        "go.mod".to_string(),
    ]
}

fn default_max_depth() -> usize {
    40
}

fn default_max_file_size() -> u64 {
    2 * 1024 * 1024 // 2 MB
}

fn default_output_format() -> String {
    "text".to_string()
}

fn default_db_path() -> String {
    "vulnera_db".to_string()
}

impl Default for SafeRepoConfig {
    fn default() -> Self {
        Self {
            ignore_patterns: vec![
                "node_modules".to_string(),
                "target".to_string(),
                ".git".to_string(),
                ".cache".to_string(),
            ],
            min_severity: default_min_severity(),
            manifest_files: default_manifest_files(),
            exclude_paths: vec![],
            max_depth: default_max_depth(),
            max_file_size: default_max_file_size(),
            threads: None,
            verbose: false,
            output_format: default_output_format(),
            verify_signatures: false,
            db_path: default_db_path(),
        }
    }
}

impl SafeRepoConfig {
    // Charge la configuration depuis un fichier .saferepo.toml
    // Retourne la config par défaut si le fichier n'existe pas
    pub fn load(path: &Path) -> SafeRepoResult<Self> {
        if path.exists() {
            debug!("Chargement configuration depuis: {:?}", path);
            let content = fs::read_to_string(path)
                .map_err(|e| SafeRepoError::FileNotFound {
                    file_path: path.display().to_string(),
                    suggestion: format!("Cannot read config file: {}", e),
                })?;

            let config: SafeRepoConfig = toml::from_str(&content)
                .map_err(|e| SafeRepoError::ConfigError {
                    key: "config file".to_string(),
                    reason: format!("Invalid TOML syntax: {}", e),
                })?;

            info!("Configuration chargée avec succès depuis: {:?}", path);
            Ok(config)
        } else {
            debug!("Fichier config non trouvé, utilisation des valeurs par défaut");
            Ok(Self::default())
        }
    }

    // Charge la configuration depuis le chemin standard ou un chemin custom
    pub fn load_or_default(custom_path: Option<&Path>) -> SafeRepoResult<Self> {
        if let Some(path) = custom_path {
            Self::load(path)
        } else {
            // Chercher dans les emplacements standards
            let standard_paths = vec![
                PathBuf::from(".saferepo.toml"),
                PathBuf::from(".config/saferepo.toml"),
                Self::get_config_dir()?.join("saferepo.toml"),
            ];

            for path in standard_paths {
                if path.exists() {
                    return Self::load(&path);
                }
            }

            Ok(Self::default())
        }
    }

    // Sauvegarde la configuration dans un fichier
    pub fn save(&self, path: &Path) -> SafeRepoResult<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| SafeRepoError::ConfigError {
                key: "serialization".to_string(),
                reason: format!("Failed to convert config to TOML: {}", e),
            })?;

        fs::write(path, content)
            .map_err(|_| SafeRepoError::PermissionDenied {
                file_path: path.display().to_string(),
                operation: "write".to_string(),
            })?;

        info!("Configuration sauvegardée dans: {:?}", path);
        Ok(())
    }

    // Retourne le répertoire de configuration de l'utilisateur
    pub fn get_config_dir() -> SafeRepoResult<PathBuf> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| SafeRepoError::ConfigError {
                key: "HOME directory".to_string(),
                reason: "Could not determine home directory - environment variable not set".to_string(),
            })?;

        let config_dir = PathBuf::from(home).join(".config/saferepo");
        fs::create_dir_all(&config_dir).ok();
        Ok(config_dir)
    }

    // Génère un fichier config par défaut
    pub fn generate_default() -> SafeRepoResult<PathBuf> {
        let config_dir = Self::get_config_dir()?;
        let config_path = config_dir.join("saferepo.toml");

        let config = Self::default();
        config.save(&config_path)?;

        info!("Fichier de configuration par défaut généré: {:?}", config_path);
        Ok(config_path)
    }

    // Fusionne deux configurations (self = base, other = overrides)
    pub fn merge(mut self, other: SafeRepoConfig) -> Self {
        if !other.ignore_patterns.is_empty() {
            self.ignore_patterns = other.ignore_patterns;
        }
        if other.min_severity != default_min_severity() {
            self.min_severity = other.min_severity;
        }
        if !other.manifest_files.is_empty() {
            self.manifest_files = other.manifest_files;
        }
        if !other.exclude_paths.is_empty() {
            self.exclude_paths = other.exclude_paths;
        }
        if other.max_depth != default_max_depth() {
            self.max_depth = other.max_depth;
        }
        if other.max_file_size != default_max_file_size() {
            self.max_file_size = other.max_file_size;
        }
        if other.threads.is_some() {
            self.threads = other.threads;
        }
        if other.verbose {
            self.verbose = other.verbose;
        }
        if other.output_format != default_output_format() {
            self.output_format = other.output_format;
        }
        if other.verify_signatures {
            self.verify_signatures = other.verify_signatures;
        }
        if other.db_path != default_db_path() {
            self.db_path = other.db_path;
        }
        self
    }

    /// Valide la configuration
    pub fn validate(&self) -> SafeRepoResult<()> {
        // Vérifier que la sévérité est valide
        let valid_severities = ["critical", "high", "medium", "low"];
        if !valid_severities.contains(&self.min_severity.as_str()) {
            return Err(SafeRepoError::ConfigError {
                key: "min_severity".to_string(),
                reason: format!("Invalid severity level '{}'. Must be one of: critical, high, medium, low",
                    self.min_severity),
            });
        }

        // Vérifier que max_depth est positif
        if self.max_depth == 0 {
            return Err(SafeRepoError::ConfigError {
                key: "max_depth".to_string(),
                reason: "max_depth must be greater than 0 to allow scanning at least the root directory".to_string(),
            });
        }

        // Vérifier que max_file_size est positif
        if self.max_file_size == 0 {
            return Err(SafeRepoError::ConfigError {
                key: "max_file_size".to_string(),
                reason: "max_file_size must be greater than 0 to process files".to_string(),
            });
        }

        // Vérifier output_format
        let valid_formats = ["text", "json", "html", "csv"];
        if !valid_formats.contains(&self.output_format.as_str()) {
            return Err(SafeRepoError::ConfigError {
                key: "output_format".to_string(),
                reason: format!("Invalid output format '{}'. Supported formats: text, json, html, csv",
                    self.output_format),
            });
        }

        debug!("Configuration validée avec succès");
        Ok(())
    }
}