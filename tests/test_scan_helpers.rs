#[cfg(test)]
mod tests_scan_helpers {
    use SafeRepo_CLI::scaning::scan::{is_ignored_dir, is_manifest_file, scan_repo};
    use SafeRepo_CLI::secure::security::SecurityManager;

    #[test]
    fn recognizes_common_manifest_files() {
        assert!(is_manifest_file("Cargo.lock"));
        assert!(is_manifest_file("package-lock.json"));
        assert!(!is_manifest_file("README.md"));
    }

    #[test]
    fn recognizes_common_ignored_directories() {
        assert!(is_ignored_dir("target"));
        assert!(is_ignored_dir("node_modules"));
        assert!(!is_ignored_dir("src"));
    }

    #[test]
    fn scan_repo_accepts_empty_directory() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let mut manager = SecurityManager::new("vulnera_db");

        let result = scan_repo(temp_dir.path(), &mut manager);

        assert!(result.is_ok());
    }
}
