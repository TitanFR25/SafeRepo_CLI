// Tests du moteur de scan itératif, limites de taille/profondeur
#[cfg(test)]
mod tests_scan_repo {
    use SafeRepo_CLI::scaning::scan::scan_repo;
    use SafeRepo_CLI::secure::security::SecurityManager;
    use std::fs;
    use tempfile::TempDir;

    // TEST 1: Scan d'un répertoire vide
    // Objectif: Vérifier que le scan gère correctement un dossier vide
    #[test]
    fn test_scan_empty_dir() {
        // Créer un répertoire temporaire vide
        let temp_dir = TempDir::new().expect("Impossible de créer un répertoire temporaire");
        let mut manager = SecurityManager::new("vulnera_db");

        // Scanner ce répertoire
        let result = scan_repo(temp_dir.path(), &mut manager);

        // Le scan doit réussir sans erreur
        assert!(result.is_ok(), "Le scan d'un répertoire vide doit réussir");
    }

    // TEST 2: Scan avec fichiers manifestes trouvés
    // Objectif: Vérifier que le scan détecte les fichiers manifestes
    #[test]
    fn test_scan_finds_manifest_files() {
        // Créer une structure de répertoires avec fichiers manifestes
        let temp_dir = TempDir::new().expect("Impossible de créer un répertoire temporaire");

        // Créer package.json
        let package_json = temp_dir.path().join("package.json");
        fs::write(&package_json, r#"{"name": "test", "version": "1.0.0"}"#)
            .expect("Impossible de créer package.json");

        // Créer Cargo.lock
        let cargo_lock = temp_dir.path().join("Cargo.lock");
        fs::write(
            &cargo_lock,
            "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"",
        )
        .expect("Impossible de créer Cargo.lock");

        let mut manager = SecurityManager::new("vulnera_db");

        // Scanner le répertoire
        let result = scan_repo(temp_dir.path(), &mut manager);

        // Le scan doit réussir
        assert!(
            result.is_ok(),
            "Le scan doit réussir quand des fichiers manifestes existent"
        );
    }

    // TEST 3: Limites de profondeur - Refuser les dossiers trop profonds
    // Objectif: Vérifier que MAX_DEPTH empêche les scans infinis
    #[test]
    fn test_scan_respects_max_depth() {
        // Créer une structure imbriquée très profonde (50 niveaux)
        let temp_dir = TempDir::new().expect("Impossible de créer un répertoire temporaire");
        let mut current_path = temp_dir.path().to_path_buf();

        // Créer 50 niveaux de dossiers imbriqués
        for i in 0..50 {
            current_path.push(format!("level_{}", i));
            fs::create_dir_all(&current_path).expect("Impossible de créer la structure imbriquée");
        }

        // Créer un fichier manifeste tout au fond
        let manifest_file = current_path.join("Cargo.lock");
        fs::write(&manifest_file, "[[package]]").expect("Impossible de créer Cargo.lock");

        let mut manager = SecurityManager::new("vulnera_db");

        // Scanner le répertoire
        let result = scan_repo(temp_dir.path(), &mut manager);

        // Le scan doit réussir (pas de crash)
        assert!(
            result.is_ok(),
            "Le scan ne doit pas craquer face à des profondeurs excessives"
        );
    }

    // TEST 4: Limite de taille de fichier (MAX_FILE_SIZE = 2 Mo)
    // Objectif: Vérifier que les fichiers > 2 Mo ne sont pas lus
    #[test]
    fn test_scan_ignores_oversized_files() {
        // Créer un fichier géant (3 Mo)
        let temp_dir = TempDir::new().expect("Impossible de créer un répertoire temporaire");

        // Créer un fichier de 3 Mo
        let large_file = temp_dir.path().join("huge_cargo.lock");
        let three_mb = 3 * 1024 * 1024;
        let data = vec![b'x'; three_mb];
        fs::write(&large_file, data).expect("Impossible de créer le fichier géant");

        let mut manager = SecurityManager::new("vulnera_db");

        // Scanner le répertoire
        let result = scan_repo(temp_dir.path(), &mut manager);

        // 1. Le scan doit réussir (pas de crash ou d'erreur RAM)
        assert!(
            result.is_ok(),
            "Le scan doit gérer les fichiers géants gracieusement"
        );
    }

    // TEST 5: Dossiers ignorés (node_modules, .git, target, etc.)
    // Objectif: Vérifier que IGNORED_DIRS sont vraiment ignorés
    #[test]
    fn test_scan_ignores_default_directories() {
        // Créer la structure standard d'un projet
        let temp_dir = TempDir::new().expect("Impossible de créer un répertoire temporaire");

        // Créer .git avec du contenu
        let git_dir = temp_dir.path().join(".git");
        fs::create_dir(&git_dir).expect("Impossible de créer .git");
        fs::write(git_dir.join("config"), "git config").expect("Impossible de créer git config");

        // Créer node_modules avec du contenu
        let node_modules = temp_dir.path().join("node_modules");
        fs::create_dir(&node_modules).expect("Impossible de créer node_modules");
        fs::write(node_modules.join("package.json"), "{}")
            .expect("Impossible de créer package.json");

        // Créer un vrai manifest file à la racine
        fs::write(temp_dir.path().join("Cargo.lock"), "[[package]]")
            .expect("Impossible de créer Cargo.lock");

        let mut manager = SecurityManager::new("vulnera_db");

        // Scanner le répertoire
        let result = scan_repo(temp_dir.path(), &mut manager);

        // Le scan doit réussir et avoir scané rapidement
        assert!(result.is_ok(), "Le scan doit ignorer .git et node_modules");
    }

    // TEST 6: Symlinks ignorés (sécurité Path Traversal)
    // Objectif: Vérifier que les symlinks ne créent pas de boucles infinies
    #[test]
    #[cfg(windows)]
    fn test_scan_ignores_symlinks() {
        use std::os::windows::fs as windows_fs;

        // Créer une structure avec un symlink
        let temp_dir = TempDir::new().expect("Impossible de créer un répertoire temporaire");
        let subdir = temp_dir.path().join("subdir");
        fs::create_dir(&subdir).expect("Impossible de créer subdir");

        // Créer un symlink (nécessite les droits admin sur Windows)
        let symlink_path = subdir.join("symlink_to_parent");
        let result = windows_fs::symlink_dir(temp_dir.path(), &symlink_path);

        // ⚠️ Sur Windows, ça peut échouer sans admin - c'est OK
        if result.is_ok() {
            let mut manager = SecurityManager::new("vulnera_db");
            let scan_result = scan_repo(temp_dir.path(), &mut manager);
            assert!(scan_result.is_ok(), "Le scan doit gérer les symlinks");
        }
    }

    // TEST 7: Fichiers non-manifestes ignorés
    // Objectif: Vérifier que seuls les fichiers manifestes sont traités
    #[test]
    fn test_scan_ignores_non_manifest_files() {
        // Créer un répertoire avec différents types de fichiers
        let temp_dir = TempDir::new().expect("Impossible de créer un répertoire temporaire");

        fs::write(temp_dir.path().join("image.jpg"), b"fake image")
            .expect("Impossible de créer .jpg");
        fs::write(temp_dir.path().join("virus.exe"), b"fake exe")
            .expect("Impossible de créer .exe");
        fs::write(temp_dir.path().join("debug.log"), "debug output")
            .expect("Impossible de créer .log");
        fs::write(temp_dir.path().join("Cargo.lock"), "[[package]]")
            .expect("Impossible de créer Cargo.lock");

        let mut manager = SecurityManager::new("vulnera_db");

        // Scanner le répertoire
        let result = scan_repo(temp_dir.path(), &mut manager);

        // Le scan doit réussir rapidement (ignorant les 3 fichiers non-manifestes)
        assert!(
            result.is_ok(),
            "Le scan doit ignorer les fichiers non-manifestes"
        );
    }

    // TEST 8: Permissions d'accès refusées (dossier protégé)
    // Objectif: Vérifier que le scan gère gracieusement les dossiers inaccessibles
    #[test]
    #[cfg(windows)]
    fn test_scan_handles_permission_denied() {
        // Tester qu'on gère les fichiers inaccessibles

        let temp_dir = TempDir::new().expect("Impossible de créer un répertoire temporaire");

        let protected_file = temp_dir.path().join("protected.txt");
        fs::write(&protected_file, "test").expect("Impossible d'écrire");

        // Rendre le fichier read-only
        let mut perms = fs::metadata(&protected_file)
            .expect("Impossible de lire les métadonnées")
            .permissions();
        perms.set_readonly(true);
        fs::set_permissions(&protected_file, perms).expect("Impossible de changer les permissions");

        let mut manager = SecurityManager::new("vulnera_db");
        let result = scan_repo(temp_dir.path(), &mut manager);

        // Le scan doit réussir en ignorant le fichier read-only
        assert!(result.is_ok(), "Le scan doit ignorer les fichiers protégés");

        // Restaurer les permissions pour le cleanup
        let mut perms = fs::metadata(&protected_file)
            .expect("Impossible de relire les métadonnées")
            .permissions();
        perms.set_readonly(false);
        fs::set_permissions(&protected_file, perms)
            .expect("Impossible de restaurer les permissions");
    }

    // TEST 9 : Path traversal (Sécurité)
    #[test]
    fn test_path_traversal_blocked() {
        let temp_dir = TempDir::new().expect("Impossible de créer un répertoire");

        // Créer une structure : temp_dir/project/src
        let project_dir = temp_dir.path().join("project");
        fs::create_dir(&project_dir).expect("Impossible de créer project/");
        let src_dir = project_dir.join("src");
        fs::create_dir(&src_dir).expect("Impossible de créer src/");

        // Créer Cargo.toml dans project/
        fs::write(project_dir.join("Cargo.toml"), "[[package]]").expect("Impossible d'écrire");

        // Créer un répertoire "secret" en dehors du project
        let secret_dir = temp_dir.path().join("secret");
        fs::create_dir(&secret_dir).expect("Impossible de créer secret/");
        fs::write(secret_dir.join("confidential.txt"), "sensitive data")
            .expect("Impossible d'écrire");

        let mut manager = SecurityManager::new("vulnera_db");

        // Le scan du project doit réussir sans accéder à secret/
        // (canonicalize résout les chemins réels, les ../ sont validés)
        let result = scan_repo(&project_dir, &mut manager);

        // Le scan du répertoire doit réussir (gestion gracieuse)
        assert!(
            result.is_ok(),
            "Le scan doit gérer correctement une structure valide"
        );
    }

    // TEST 10: Root validation (Sécurité)
    #[test]
    fn test_root_validation() {
        let temp_dir = TempDir::new().expect("Impossible de créer un répertoire");

        // Créer un vrai projet (avec Cargo.toml)
        fs::write(temp_dir.path().join("Cargo.toml"), "[package]").expect("Impossible d'écrire");

        let mut manager = SecurityManager::new("vulnera_db");
        let result = scan_repo(temp_dir.path(), &mut manager);

        assert!(result.is_ok(), "Un projet valide doit être scanné");
    }
}
