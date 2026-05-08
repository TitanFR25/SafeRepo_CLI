// Tests du module SecurityManager et du parsing Cargo.lock
#[cfg(test)]
mod test_security_manager {
    use SafeRepo_CLI::database::db::{Advisory, Severity, Versions, VulnerabilityDB};
    use SafeRepo_CLI::secure::security::SecurityManager;

    // TEST 1: Création d'un SecurityManager avec une DB valide
    // Objectif: Vérifier qu'un SecurityManager peut être créé et chargé
    #[test]
    fn test_security_manager_new() {
        // Créer un répertoire temporaire avec un fichier de vulnérabilité
        let temp_dir =
            tempfile::TempDir::new().expect("Impossible de créer un répertoire temporaire");
        let vuln_file = temp_dir.path().join("test.toml");

        let toml_content = r#"
            [advisory]
            id = "TEST-001"
            package = "serde"
            severity = "high"
            title = "Test"
            description = "Test"

            [versions]
            patched = ["1.0.0"]"#;

        std::fs::write(&vuln_file, toml_content).expect("Impossible d'écrire le fichier");

        // Créer un SecurityManager pointant vers ce répertoire
        let manager = SecurityManager::new(temp_dir.path().to_str().expect("Chemin invalide"));

        // Le manager doit être créé sans erreur
        // (On ne peut pas vraiment vérifier l'état interne, mais on s'assure que le constructeur ne panic pas)
        assert!(
            manager.db.advisories.len() > 0,
            "La DB ne devrait pas être vide"
        );
    }

    // TEST 2: Analyse d'un fichier Cargo.lock valide
    // Objectif: Vérifier que analyze_file() parse correctement Cargo.lock
    #[test]
    fn test_analyze_cargo_lock_with_vulnerable_dependency() {
        // Créer une base de données avec une vulnérabilité
        let mut db = VulnerabilityDB::new();
        let advisory = Advisory {
            id: "RUSTSEC-2024-0001".to_string(),
            package: "log".to_string(),
            severity: Severity::High,
            title: "Vulnérabilité de sévérité élevée".to_string(),
            description: "Description test".to_string(),
            versions: Versions {
                patched: vec!["0.4.20".to_string()],
                unaffected: None,
            },
        };
        db.advisories.insert("log".to_string(), vec![advisory]);

        let mut manager = SecurityManager { db };

        // Créer un répertoire temporaire avec un vrai fichier Cargo.lock
        let temp_dir =
            tempfile::TempDir::new().expect("Impossible de créer un répertoire temporaire");
        let cargo_lock_path = temp_dir.path().join("Cargo.lock");
        let cargo_content = r#"
        [[package]]
        name = "log"
        version = "0.4.18"

        [[package]]
        name = "serde"
        version = "1.0.200""#;

        std::fs::write(&cargo_lock_path, cargo_content)
            .expect("Impossible d'écrire dans le fichier");

        // Analyser le fichier Cargo.lock
        let issues_count = manager
            .analyze_file(&cargo_lock_path)
            .expect("Erreur analyse Cargo.lock")
            .len();

        // Au moins une vulnérabilité doit être détectée
        assert!(
            issues_count > 0,
            "Au moins une vulnérabilité devrait être détectée dans Cargo.lock"
        );
        assert_eq!(issues_count, 1, "Exactement 1 vulnérabilité attendue");
    }

    // TEST 3: Analyse d'un Cargo.lock sans vulnérabilités
    // Objectif: Vérifier que analyze_file() retourne 0 si aucune vulnérabilité
    #[test]
    fn test_analyze_cargo_no_vulnera() {
        // Créer une base de données vide (aucune vulnérabilité connue)
        let db = VulnerabilityDB::new();
        let mut manager = SecurityManager { db };

        // Créer un répertoire temporaire avec un vrai fichier Cargo.lock
        let temp_dir =
            tempfile::TempDir::new().expect("Impossible de créer un répertoire temporaire");
        let cargo_lock_path = temp_dir.path().join("Cargo.lock");
        let cargo_content = r#"
        [[package]]
        name = "serde"
        version = "1.0.200"

        [[package]]
        name = "tokio"
        version = "1.40.0""#;

        std::fs::write(&cargo_lock_path, cargo_content)
            .expect("Impossible d'écrire dans le fichier");

        // Analyser le fichier
        let issues_count = manager
            .analyze_file(&cargo_lock_path)
            .expect("Erreur analyse Cargo.lock")
            .len();

        // Aucune vulnérabilité ne doit être trouvée
        assert_eq!(
            issues_count, 0,
            "Aucune vulnérabilité ne devrait être détectée pour des packages sains"
        );
    }

    // TEST 4: Fichier Cargo.lock malformé (TOML invalide)
    // Objectif: Vérifier que analyze_file() gère les fichiers TOML corrompus
    #[test]
    fn test_analyze_cargo_lock_invalid_toml() {
        let db = VulnerabilityDB::new();
        let mut manager = SecurityManager { db };

        // Créer un répertoire temporaire avec un fichier Cargo.lock invalide
        let temp_dir =
            tempfile::TempDir::new().expect("Impossible de créer un répertoire temporaire");
        let cargo_lock_path = temp_dir.path().join("Cargo.lock");
        let invalid_toml = r#"
        [[package]]
        name = "serde"
        version = 1.0.200
        broken_syntax = }{["}""#;

        std::fs::write(&cargo_lock_path, invalid_toml)
            .expect("Impossible d'écrire dans le fichier");

        // Analyser le fichier (ne doit pas planter)
        let issues_count = manager
            .analyze_file(&cargo_lock_path)
            .unwrap_or_default()
            .len();

        // Doit retourner 0 sans paniquer
        assert_eq!(
            issues_count, 0,
            "Un Cargo.lock invalide doit retourner 0, pas paniquer"
        );
    }

    // TEST 5: Analyse d'un fichier avec extension inconnue
    // Objectif: Vérifier que analyze_file() ignore les fichiers non reconnus
    #[test]
    fn test_analyze_unknown_file_type() {
        let db = VulnerabilityDB::new();
        let mut manager = SecurityManager { db };

        // Créer un répertoire temporaire avec un fichier non reconnu
        let temp_dir =
            tempfile::TempDir::new().expect("Impossible de créer un répertoire temporaire");
        let txt_file = temp_dir.path().join("data.txt");
        std::fs::write(&txt_file, b"Ceci n'est pas un fichier manifeste")
            .expect("Impossible d'écrire");

        // ACT: Analyser ce fichier
        let issues_count = manager.analyze_file(&txt_file).unwrap_or_default().len();

        // ASSERT: Doit retourner 0 (fichier non reconnu)
        assert_eq!(
            issues_count, 0,
            "Un fichier avec une extension inconnue doit retourner 0 vulnérabilités"
        );
    }

    // TEST 6: Parsing de version malformée
    // Objectif: Vérifier que le parsing de version gère les erreurs
    #[test]
    fn test_analyze_cargo_lock_invalid_version() {
        let db = VulnerabilityDB::new();
        let mut manager = SecurityManager { db };

        // Créer un répertoire temporaire avec un fichier Cargo.lock invalide
        let temp_dir =
            tempfile::TempDir::new().expect("Impossible de créer un répertoire temporaire");
        let cargo_lock_path = temp_dir.path().join("Cargo.lock");

        let cargo_content = r#"[[package]]
name = "serde"
version = "not.a.valid.version""#;

        std::fs::write(&cargo_lock_path, cargo_content)
            .expect("Impossible d'écrire dans le fichier");

        // Analyser le fichier (ne doit pas planter)
        let issues_count = manager
            .analyze_file(&cargo_lock_path)
            .unwrap_or_default()
            .len();

        // Doit retourner 0 sans lever d'exception
        assert_eq!(
            issues_count, 0,
            "Une version invalide ne doit pas causer de panique"
        );
    }
}

#[cfg(test)]
mod test_multi_parsers {
    use std::fs;
    use tempfile::TempDir;
    use SafeRepo_CLI::secure::security::SecurityManager;

    // TEST 1: Parser un package-lock.json valide
    #[test]
    fn test_parse_package_lock_json_valide() {
        // Créer package-lock.json avec des packages connus (format NPM v3+)
        let temp_dir = TempDir::new().expect("répertoire temp");
        let package_lock = temp_dir.path().join("package-lock.json");

        let content = r#"{
            "packages": {
                "": {
                    "version": "1.0.0"
                },
                "node_modules/express": {
                    "version": "4.18.2"
                },
                "node_modules/lodash": {
                    "version": "4.17.21"
                }
            },
            "dependencies": {}
        }"#;

        fs::write(&package_lock, content).expect("écrire");

        let mut manager = SecurityManager::new("vulnera_db");
        let result = manager.analyze_file(&package_lock);

        match &result {
            Ok(_) => println!("✅ Test OK"),
            Err(e) => println!("❌ Error: {:?}", e),
        }

        assert!(result.is_ok(), "Doit parser package-lock.json valide");
    }

    // TEST 2: Parser un requirements.txt valide
    #[test]
    fn test_parse_requirements_txt_valide() {
        let temp_dir = TempDir::new().expect("répertoire temp");
        let requirements = temp_dir.path().join("requirements.txt");

        let content = r#"
            Django==3.2.15
            requests>=2.25.0,<3.0.0
            pytest==7.0.0"#;

        fs::write(&requirements, content).expect("écrire");

        let mut manager = SecurityManager::new("vulnera_db");
        let result = manager.analyze_file(&requirements);

        assert!(result.is_ok(), "Doit parser requirements.txt valide");
    }

    // TEST 3 : Parser un go.mod valide 
    #[test]
    fn test_parse_go_mod_valide() {
        let temp_dir = TempDir::new().expect("répertoire temp");
        let go_mod = temp_dir.path().join("go.mod");

        let content = r#"module github.com/myapp/main

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/lib/pq v1.10.9
)"#;

        fs::write(&go_mod, content).expect("écrire");

        let mut manager = SecurityManager::new("vulnera_db");
        let result = manager.analyze_file(&go_mod);

        match &result {
            Ok(_) => println!("✅ Test go.mod OK"),
            Err(e) => println!("❌ Error go.mod: {:?}", e),
        }

        assert!(result.is_ok(), "Doit parser go.mod valide");
    }
}
