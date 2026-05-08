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

    // Erreurs générales
    Generic {
        message: String,
    },
}

// Implémenter display pour afficher les erreurs lisiblement
impl fmt::Display for SafeRepoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // Erreur I/O avec contexte clair
            SafeRepoError::IoError { context, source } => {
                write!(f, "❌ Erreur I/O {}: {}", context, source)
            }

            // Erreur TOML avec point d'erreur exact
            SafeRepoError::TomlError { context, source } => {
                write!(
                    f,
                    "❌ Erreur TOML dans {}\n   {}",
                    context,
                    source.message()
                )
            }

            // Validation échouée
            SafeRepoError::ValidationError { file_path, reason } => {
                write!(f, "❌ Validation échouée ({}): {}", file_path, reason)
            }

            // Erreur de sécurité
            SafeRepoError::SecurityError {
                error_type,
                details,
            } => {
                write!(f, "🚨 Erreur sécurité ({}): {}", error_type, details)
            }

            // Erreur database
            SafeRepoError::DatabaseError { operation, reason } => {
                write!(f, "❌ Erreur DB ({}) : {}", operation, reason)
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

// Conversion automatique de io::Error vers SafeRepoError
// Cela permet d'utiliser ? dans les fonctions et convertir automatiquement
impl From<io::Error> for SafeRepoError {
    fn from(error: io::Error) -> Self {
        SafeRepoError::IoError {
            context: String::from("I/O operation"),
            source: error,
        }
    }
}

// Convertion automatique de toml::de::Error vers SafeRepoError
impl From<toml::de::Error> for SafeRepoError {
    fn from(error: toml::de::Error) -> Self {
        SafeRepoError::TomlError {
            context: String::from("Unknow TOML file"),
            source: error,
        }
    }
}

// Type alias pour simplifier l'écriture partout
pub type SafeRepoResult<T> = Result<T, SafeRepoError>;
