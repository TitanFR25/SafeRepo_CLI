#[cfg(test)]
mod tests_manifest_utils {
    use SafeRepo_CLI::utils::manifest_utils::{
        file_name_matches, normalize_python_version, normalize_semver, read_manifest_file,
    };
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_read_manifest_file_returns_content_for_valid_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("Cargo.lock");
        fs::write(&file_path, "[[package]]\nname = \"serde\"\n").unwrap();

        let content = read_manifest_file(&file_path, "reading Cargo.lock").unwrap();

        assert!(content.contains("serde"));
    }

    #[test]
    fn test_file_name_matches_detects_expected_name() {
        let path = PathBuf::from("package-lock.json");
        assert!(file_name_matches(&path, "package-lock.json"));
        assert!(!file_name_matches(&path, "Cargo.lock"));
    }

    #[test]
    fn test_normalize_semver_pads_short_versions() {
        assert_eq!(normalize_semver("1"), Some("1.0.0".to_string()));
        assert_eq!(normalize_semver("^1.2"), Some("1.2.0".to_string()));
    }

    #[test]
    fn test_normalize_python_version_handles_common_suffixes() {
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
