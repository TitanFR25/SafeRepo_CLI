// Tests du module SecurityManager et du parsing Cargo.lock
#[cfg(test)]
mod test_security_manager {
    use SafeRepo_CLI::database::db::{Advisory, Severity, Versions, VulnerabilityDB};
    use SafeRepo_CLI::secure::security::SecurityManager;

    // TEST 1: Une DB locale non signée est refusée
    // Objectif: Vérifier que le chargement respecte la signature Ed25519 obligatoire
    #[test]
    fn test_security_manager_new_rejects_unsigned_database() {
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

        let result = SecurityManager::new(temp_dir.path().to_str().expect("Chemin invalide"));

        assert!(
            result.is_err(),
            "Une DB sans manifeste signé doit être refusée"
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
                introduced: Vec::new(),
                fixed: Vec::new(),
                patched: vec!["0.4.20".to_string()],
                unaffected: None,
            },
        };
        db.advisories.insert("log".to_string(), vec![advisory]);

        let manager = SecurityManager { db };

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
        let manager = SecurityManager { db };

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
        let manager = SecurityManager { db };

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

        let result = manager.analyze_file(&cargo_lock_path);

        assert!(result.is_err(), "Un Cargo.lock invalide doit être refusé");
    }

    // TEST 5: Analyse d'un fichier avec extension inconnue
    // Objectif: Vérifier que analyze_file() ignore les fichiers non reconnus
    #[test]
    fn test_analyze_unknown_file_type() {
        let db = VulnerabilityDB::new();
        let manager = SecurityManager { db };

        // Créer un répertoire temporaire avec un fichier non reconnu
        let temp_dir =
            tempfile::TempDir::new().expect("Impossible de créer un répertoire temporaire");
        let txt_file = temp_dir.path().join("data.txt");
        std::fs::write(&txt_file, b"Ceci n'est pas un fichier manifeste")
            .expect("Impossible d'écrire");

        let result = manager.analyze_file(&txt_file);

        assert!(
            result.is_err(),
            "Un fichier avec une extension inconnue doit être refusé"
        );
    }

    // TEST 6: Parsing de version malformée
    // Objectif: Vérifier que le parsing de version gère les erreurs
    #[test]
    fn test_analyze_cargo_lock_invalid_version() {
        let db = VulnerabilityDB::new();
        let manager = SecurityManager { db };

        // Créer un répertoire temporaire avec un fichier Cargo.lock invalide
        let temp_dir =
            tempfile::TempDir::new().expect("Impossible de créer un répertoire temporaire");
        let cargo_lock_path = temp_dir.path().join("Cargo.lock");

        let cargo_content = r#"[[package]]
name = "serde"
version = "not.a.valid.version""#;

        std::fs::write(&cargo_lock_path, cargo_content)
            .expect("Impossible d'écrire dans le fichier");

        let issues_count = manager
            .analyze_file(&cargo_lock_path)
            .expect("Une version invalide doit être ignorée sans échec de parsing")
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
    use SafeRepo_CLI::database::db::{Advisory, Severity, Versions, VulnerabilityDB};
    use SafeRepo_CLI::secure::security::SecurityManager;
    use std::fs;
    use tempfile::TempDir;

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

        let manager = SecurityManager {
            db: VulnerabilityDB::new(),
        };
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

        let manager = SecurityManager {
            db: VulnerabilityDB::new(),
        };
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

        let manager = SecurityManager {
            db: VulnerabilityDB::new(),
        };
        let result = manager.analyze_file(&go_mod);

        match &result {
            Ok(_) => println!("✅ Test go.mod OK"),
            Err(e) => println!("❌ Error go.mod: {:?}", e),
        }

        assert!(result.is_ok(), "Doit parser go.mod valide");
    }

    // TEST 4: Parser un package.json valide
    #[test]
    fn test_parse_package_json_valide() {
        use std::fs;
        let temp_dir = TempDir::new().expect("répertoire temp");
        let package_json = temp_dir.path().join("package.json");

        let content = r#"{
            "name": "myapp",
            "version": "1.0.0",
            "dependencies": {
                "express": "4.18.2",
                "lodash": "4.17.21"
            },
            "devDependencies": {
                "mocha": "9.1.3"
            }
        }"#;

        fs::write(&package_json, content).expect("écrire package.json");

        let manager = SecurityManager {
            db: VulnerabilityDB::new(),
        };
        let result = manager.analyze_file(&package_json);

        assert!(result.is_ok(), "Doit parser package.json valide");
    }

    // TEST 5: Parser un package.json avec version invalide (ne doit pas panic)
    #[test]
    fn test_parse_package_json_invalid_version() {
        use std::fs;
        let temp_dir = TempDir::new().expect("répertoire temp");
        let package_json = temp_dir.path().join("package.json");

        let content = r#"{
            "name": "broken",
            "version": "0.1.0",
            "dependencies": {
                "weird": "not.a.version"
            }
        }"#;

        fs::write(&package_json, content).expect("écrire package.json");

        let manager = SecurityManager {
            db: VulnerabilityDB::new(),
        };
        let result = manager.analyze_file(&package_json);

        assert!(
            result.is_ok(),
            "Le parser doit gérer les versions invalides sans panic"
        );
        let issues = result.expect("Une version NPM invalide doit être ignorée sans erreur");
        assert_eq!(
            issues.len(),
            0,
            "Aucune vulnérabilité attendue pour version invalide"
        );
    }

    // TEST 6: Contraintes Python non épinglées
    // Objectif: Vérifier que seules les versions exactes sont analysées
    #[test]
    fn test_parse_requirements_only_exact_versions() {
        // Créer un fichier Python contenant une version exacte et une contrainte ouverte.
        let temp_dir = TempDir::new().expect("répertoire temp");
        let requirements = temp_dir.path().join("requirements.txt");
        let content = "requests==1.0.0\nrequests>=1.0.0,<2.0.0\n";
        fs::write(&requirements, content).expect("écrire");

        // Charger un advisory et analyser le fichier requirements.txt.
        let mut db = VulnerabilityDB::new();
        db.advisories.insert(
            "requests".to_string(),
            vec![Advisory {
                id: "TEST-REQ-001".to_string(),
                package: "requests".to_string(),
                severity: Severity::High,
                title: "Test".to_string(),
                description: "Test".to_string(),
                versions: Versions {
                    introduced: Vec::new(),
                    fixed: Vec::new(),
                    patched: vec!["2.0.0".to_string()],
                    unaffected: None,
                },
            }],
        );
        let manager = SecurityManager { db };

        let vulnerabilities = manager
            .analyze_file(&requirements)
            .expect("Doit parser requirements.txt");

        // Seule la dépendance avec une version exacte doit être détectée.
        assert_eq!(
            vulnerabilities.len(),
            1,
            "Seule la contrainte exacte doit être analysée"
        );
    }

    // TEST 7: Contraintes Python ouvertes conservées comme indéterminées
    // Objectif: Vérifier qu'une contrainte non exacte ne devient pas une détection certaine
    #[test]
    fn test_parse_requirements_keeps_open_constraints_indeterminate() {
        // Préparer uniquement des contraintes Python ouvertes ou exclues.
        let temp_dir = TempDir::new().expect("répertoire temp");
        let requirements = temp_dir.path().join("requirements.txt");
        fs::write(
            &requirements,
            "requests>=1.0.0,<2.0.0\nrequests~=1.0.0\nrequests!=1.5.0\n",
        )
        .expect("écrire");

        // Charger une plage vulnérable pour vérifier qu'elle ne force pas une détection.
        let mut db = VulnerabilityDB::new();
        db.advisories.insert(
            "requests".to_string(),
            vec![Advisory {
                id: "TEST-REQ-RANGE-001".to_string(),
                package: "requests".to_string(),
                severity: Severity::High,
                title: "Test".to_string(),
                description: "Test".to_string(),
                versions: Versions {
                    introduced: vec!["1.0.0".to_string()],
                    fixed: vec!["2.0.0".to_string()],
                    patched: Vec::new(),
                    unaffected: None,
                },
            }],
        );

        let manager = SecurityManager { db };
        let vulnerabilities = manager
            .analyze_file(&requirements)
            .expect("Doit parser les contraintes Python");

        // Une contrainte ouverte doit rester indéterminée.
        assert!(
            vulnerabilities.is_empty(),
            "Une contrainte ouverte ne doit pas devenir une détection certaine"
        );
    }

    // TEST 8: Suffixe extra dans une dépendance Python
    // Objectif: Vérifier que le parsing d'un nom avec extra ne provoque pas de panic
    #[test]
    fn test_parse_requirements_with_extra_does_not_panic() {
        // Analyser une dépendance Python avec un extra entre crochets.
        let temp_dir = TempDir::new().expect("répertoire temp");
        let requirements = temp_dir.path().join("requirements.txt");
        fs::write(&requirements, "requests[security]==1.0.0\n").expect("écrire");

        // Le parser doit terminer proprement, même sans vulnérabilité connue.
        let manager = SecurityManager {
            db: VulnerabilityDB::new(),
        };
        assert!(manager.analyze_file(&requirements).is_ok());
    }

    // TEST 9: Profondeur excessive d'un package-lock.json
    // Objectif: Vérifier qu'une imbrication NPM excessive est refusée sans panic
    #[test]
    fn test_parse_package_lock_rejects_excessive_nesting() {
        // Construire progressivement un JSON dont la profondeur dépasse la limite autorisée.
        let temp_dir = TempDir::new().expect("répertoire temp");
        let package_lock = temp_dir.path().join("package-lock.json");

        let depth = 129;
        let mut content = String::from("{\"dependencies\":");
        for index in 0..depth {
            content.push_str(&format!(
                "{{\"package-{index}\":{{\"version\":\"1.0.0\",\"dependencies\":"
            ));
        }
        content.push_str("{}");
        for _ in 0..depth {
            content.push_str("}}");
        }
        content.push('}');

        fs::write(&package_lock, content).expect("écrire package-lock.json");

        let manager = SecurityManager {
            db: VulnerabilityDB::new(),
        };
        let result = manager.analyze_file(&package_lock);

        assert!(
            result.is_err(),
            "Une imbrication NPM excessive doit être refusée"
        );
    }
}
