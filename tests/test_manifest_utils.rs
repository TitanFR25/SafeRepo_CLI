// DESCRIPTION: Tests des utilitaires de détection et de lecture des manifestes
#[cfg(test)]
mod tests_manifest_utils {
    use SafeRepo_CLI::utils::manifest_utils::{
        file_name_matches, normalize_python_version, normalize_semver, read_manifest_file,
    };
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // TEST 1: Lecture d'un manifeste valide
    // Objectif: Vérifier que le contenu d'un fichier manifeste est retourné
    #[test]
    fn test_read_manifest_file_returns_content_for_valid_file() {
        // Créer un manifeste temporaire contenant un package connu.
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("Cargo.lock");
        fs::write(&file_path, "[[package]]\nname = \"serde\"\n").unwrap();

        // Lire le manifeste avec le contexte d'erreur fourni par l'appelant.
        let content = read_manifest_file(&file_path, "reading Cargo.lock").unwrap();

        // Vérifier que le contenu lu correspond au fichier créé.
        assert!(content.contains("serde"));
    }

    // TEST 2: Correspondance du nom de fichier
    // Objectif: Vérifier qu'un nom attendu est reconnu et qu'un autre est refusé
    #[test]
    fn test_file_name_matches_detects_expected_name() {
        // Préparer un chemin représentant un manifeste NPM.
        let path = PathBuf::from("package-lock.json");

        // Le nom attendu doit être reconnu, tandis qu'un autre nom doit être refusé.
        assert!(file_name_matches(&path, "package-lock.json"));
        assert!(!file_name_matches(&path, "Cargo.lock"));
    }

    // TEST 3: Normalisation des versions semver courtes
    // Objectif: Vérifier que les composants manquants sont complétés
    #[test]
    fn test_normalize_semver_pads_short_versions() {
        // Vérifier qu'une version majeure ou majeure/mineure est complétée en semver.
        assert_eq!(normalize_semver("1"), Some("1.0.0".to_string()));
        assert_eq!(normalize_semver("^1.2"), Some("1.2.0".to_string()));
    }

    // TEST 4: Normalisation des suffixes de version Python
    // Objectif: Vérifier la conversion des suffixes post-release et release candidate
    #[test]
    fn test_normalize_python_version_handles_common_suffixes() {
        // Les suffixes Python doivent être convertis vers la forme utilisée par semver.
        assert_eq!(
            normalize_python_version("1.2.3.post1"),
            Some("1.2.3-post1".to_string())
        );
        assert_eq!(
            normalize_python_version("1.2.3rc1"),
            Some("1.2.3-rc1".to_string())
        );
    }
}
