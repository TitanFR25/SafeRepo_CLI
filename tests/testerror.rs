// TESTS pour le systéme d'erreur
#[cfg(test)]
mod error_handling_tests {
    use SafeRepo_CLI::database::db::VulnerabilityDB;
    use SafeRepo_CLI::errorhandle::errors::SafeRepoError;
    use std::io;
    use std::path::Path;

    // TEST 1: error display
    #[test]
    fn test_display_io_error() {
        let err = SafeRepoError::IoError {
            context: "Reading file".to_string(),
            source: io::Error::new(io::ErrorKind::NotFound, "file not found"),
        };
        let message = err.to_string();
        assert!(message.contains("❌"));
        assert!(message.contains("I/O"));
    }

    // TEST 2: Security error
    #[test]
    fn test_display_security_error() {
        let err = SafeRepoError::SecurityError {
            error_type: "Path Traversal".to_string(),
            details: "Invalid path: ../../etc/passwd".to_string(),
        };
        let message = err.to_string();
        assert!(message.contains("🚨"));
        assert!(message.contains("Path Traversal"));
    }

    // TEST 3 : Charger un dossier qui existe pas
    #[test]
    fn test_load_nonexistent_directory() {
        let mut db = VulnerabilityDB::new();
        let result = db.load_from_dir("/path/that/does/not/exist");

        // Vérifier que c'est une erreur, pas un panic
        assert!(result.is_err());
        match result {
            Err(SafeRepoError::DatabaseError { .. }) => {
                // Type d'erreur correct
            }
            _ => panic!("Expected DatabaseError"),
        }
    }

    // TEST 4 : Charger un fichier avec un toml invalide
    #[test]
    fn test_load_with_invalid_toml() {
        // Créer un fichier TOML invalide
        let temp_dir = tempfile::TempDir::new().unwrap();
        let bad_toml = temp_dir.path().join("bad.toml");

        // Écrire du TOML invalide
        std::fs::write(&bad_toml, "invalid [[ toml [[").unwrap();

        let mut db = VulnerabilityDB::new();
        // Devrait continuer même avec le mauvais fichier
        let result = db.load_from_dir(temp_dir.path());

        // L'important: pas de panic, on retourne une erreur gracieuse
        match result {
            Ok(()) | Err(_) => {
                // ✅ Les deux sont acceptables - pas de panic
            }
        }
    }

    // TEST 5 : Vérifier l'integrité d'un fichier manquant
    #[test]
    fn test_verify_integrity_on_missing_file() {
        let result =
            VulnerabilityDB::verify_file_integrity(Path::new("/path/nonexistent"), "somehash");

        // Retourner une erreur au lieu de panic
        assert!(result.is_err());
    }
}
