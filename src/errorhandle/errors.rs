use std::fmt;
use std::io;

// Type d'erreur perssonalisé pour SafeRepo
// Permet de capturer tous les types d'erreurs possible de les traiter
// de maniére cohérente sans jamais utiliser panic!
#[derive(Debug)]
pub enum SafeRepoError {
    // Erreurs d'I/O
    IoError {
        context: String,   // Où l'erreur s'est produite
        source: io::Error, // Erreur système d'origine
    },

    // Erreurs de parsing TOML
    TomlError {
        context: String,         // Quel fichier ?
        source: toml::de::Error, // Erreur TOML exacte
    },

    // Erreurs de validation de fichier
    ValidationError {
        file_path: String, // Chemin du fichier
        reason: String,    // Pourquoi l'erreur
    },

    // Erreurs de sécurité (Path Traversal, etc)
    SecurityError {
        error_type: String, // Type d'erreur sécurité
        details: String,    // Détails
    },

    // Erreurs de database
    DatabaseError {
        operation: String, // Quelle opération
        reason: String,    // Pourquoi
    },

    // Erreurs de scanning
    ScanError {
        file_path: String, // Fichier scanné
        reason: String,    // Raison de l'erreur
    },

    // Erreurs OSV (Open Source Vulnerabilities)
    OSVError {
        operation: String, // Quelle opération OSV
        reason: String,    // Détails
    },

    // Erreurs de configuration
    ConfigError {
        key: String,    // Clé de config manquante/invalide
        reason: String, // Raison
    },

    // Erreurs d'arguments CLI
    CliError {
        message: String,    // Message d'erreur
        suggestion: String, // Suggestion pour corriger
    },

    // Fichier non trouvé
    FileNotFound {
        file_path: String,
        suggestion: String,
    },

    // Permission d'accès refusée
    PermissionDenied {
        file_path: String,
        operation: String,
    },

    // Erreurs générales
    Generic {
        message: String,
    },
}

// Implémenter display pour afficher les erreurs lisiblement avec contexte et suggestions
impl fmt::Display for SafeRepoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // Erreur I/O avec contexte clair
            SafeRepoError::IoError { context, source } => {
                let suggestion = match source.kind() {
                    io::ErrorKind::PermissionDenied => {
                        "\n💡 Conseil: Vérifiez les permissions du fichier ou du dossier."
                    }
                    io::ErrorKind::NotFound => {
                        "\n💡 Conseil: Le fichier ou le dossier n'existe pas."
                    }
                    _ => "",
                };
                write!(
                    f,
                    "❌ Erreur I/O {}: {}{}", 
                    context, source, suggestion
                )
            }

            // Erreur TOML avec point d'erreur exact
            SafeRepoError::TomlError { context, source } => {
                write!(
                    f,
                    "❌ Erreur TOML dans {}\n   Détails: {}\n💡 Conseil: Vérifiez la syntaxe TOML du fichier (indentation, guillemets, etc.)",
                    context,
                    source.message()
                )
            }

            // Validation échouée
            SafeRepoError::ValidationError { file_path, reason } => {
                write!(
                    f,
                    "❌ Validation échouée ({})\n   Raison: {}\n💡 Conseil: Vérifiez le format du fichier.",
                    file_path, reason
                )
            }

            // Erreur de sécurité
            SafeRepoError::SecurityError {
                error_type,
                details,
            } => {
                write!(
                    f,
                    "🚨 Erreur sécurité ({}): {}\n💡 Conseil: Une tentative d'accès non autorisée a été bloquée (path traversal, dossier interdit, etc.).",
                    error_type, details
                )
            }

            // Erreur database
            SafeRepoError::DatabaseError { operation, reason } => {
                write!(
                    f,
                    "❌ Erreur BD ({}) : {}\n💡 Conseil: Essayez de mettre à jour la base de données avec 'saferepo update'",
                    operation, reason
                )
            }

            // Erreur de scanning
            SafeRepoError::ScanError { file_path, reason } => {
                write!(
                    f,
                    "❌ Erreur de scan ({}): {}\n💡 Conseil: Vérifiez que le fichier est lisible et dans un format supporté.",
                    file_path, reason
                )
            }

            // Erreur OSV
            SafeRepoError::OSVError { operation, reason } => {
                write!(
                    f,
                    "❌ Erreur OSV ({}) : {}\n💡 Conseil: Vérifiez votre connexion Internet ou essayez 'saferepo update'",
                    operation, reason
                )
            }

            // Erreur de configuration
            SafeRepoError::ConfigError { key, reason } => {
                write!(
                    f,
                    "❌ Erreur configuration - Clé '{}': {}\n💡 Conseil: Vérifiez le fichier .saferepo.toml",
                    key, reason
                )
            }

            // Erreur CLI
            SafeRepoError::CliError { message, suggestion } => {
                write!(
                    f,
                    "❌ Erreur ligne de commande: {}\n💡 {}\n\n💻 Utilisez 'saferepo --help' pour l'aide complète.",
                    message, suggestion
                )
            }

            // Fichier non trouvé
            SafeRepoError::FileNotFound { file_path, suggestion } => {
                write!(
                    f,
                    "❌ Fichier non trouvé: {}\n💡 {}\n💡 Vérifiez le chemin et les permissions.",
                    file_path, suggestion
                )
            }

            // Permission d'accès refusée
            SafeRepoError::PermissionDenied { file_path, operation } => {
                write!(
                    f,
                    "❌ Accès refusé lors de l'opération '{}' sur: {}\n💡 Conseil: Vérifiez les permissions du fichier/dossier ou exécutez avec les droits appropriés.",
                    operation, file_path
                )
            }

            // Erreur générique
            SafeRepoError::Generic { message } => {
                write!(f, "❌ Erreur: {}", message)
            }
        }
    }
}

// Implémenter std::error::Error pour etre compatible avec les crates
impl std::error::Error for SafeRepoError {}

impl SafeRepoError {
    /// Retourner un code de sortie approprié selon le type d'erreur
    pub fn exit_code(&self) -> i32 {
        match self {
            SafeRepoError::SecurityError { .. } => 2,          // Erreur de sécurité critique
            SafeRepoError::ValidationError { .. } => 3,        // Erreur de validation
            SafeRepoError::FileNotFound { .. } => 4,           // Fichier non trouvé
            SafeRepoError::PermissionDenied { .. } => 5,       // Permission refusée
            SafeRepoError::CliError { .. } => 6,               // Erreur CLI
            SafeRepoError::DatabaseError { .. } => 7,          // Erreur BD
            SafeRepoError::ConfigError { .. } => 8,            // Erreur config
            SafeRepoError::OSVError { .. } => 9,               // Erreur OSV
            SafeRepoError::ScanError { .. } => 10,             // Erreur scan
            SafeRepoError::TomlError { .. } => 11,             // Erreur TOML
            SafeRepoError::IoError { .. } => 1,                // Erreur I/O générale
            SafeRepoError::Generic { .. } => 1,                // Erreur générique
        }
    }

    /// Formater l'erreur de manière lisible pour l'utilisateur final
    pub fn user_friendly(&self) -> String {
        format!("{}", self)
    }

    /// Formater l'erreur avec contexte de debugging (à utiliser en mode verbose)
    pub fn debug_info(&self) -> String {
        format!("🔍 [Debug] {:?}", self)
    }
}

// Conversion automatique de io::Error vers SafeRepoError
// Cela permet d'utiliser ? dans les fonctions et convertir automatiquement
impl From<io::Error> for SafeRepoError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::NotFound => SafeRepoError::FileNotFound {
                file_path: String::from("(unknown)"),
                suggestion: String::from("Le fichier ou dossier recherché n'existe pas."),
            },
            io::ErrorKind::PermissionDenied => SafeRepoError::PermissionDenied {
                file_path: String::from("(unknown)"),
                operation: String::from("file operation"),
            },
            _ => SafeRepoError::IoError {
                context: String::from("I/O operation"),
                source: error,
            },
        }
    }
}

// Convertion automatique de toml::de::Error vers SafeRepoError
impl From<toml::de::Error> for SafeRepoError {
    fn from(error: toml::de::Error) -> Self {
        SafeRepoError::TomlError {
            context: String::from("Configuration file"),
            source: error,
        }
    }
}

// Type alias pour simplifier l'écriture partout
pub type SafeRepoResult<T> = Result<T, SafeRepoError>;

/// Affiche une erreur de SafeRepo de manière formatée et retourne le code de sortie
pub fn handle_error(error: &SafeRepoError) -> i32 {
    eprintln!("\n{}\n", error.user_friendly());
    error.exit_code()
}
