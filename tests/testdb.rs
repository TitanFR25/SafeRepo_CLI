// DESCRIPTION: Tests complets pour la structure VulnerabilityDB et ses méthodes
#[cfg(test)]
mod tests_vulnerability_db {
    use SafeRepo_CLI::database::db::{Advisory, Severity, Versions, VulnerabilityDB};
    use semver::Version;

    // TEST 1: Création d'une nouvelle base de données vide
    // Objectif: Vérifier qu'une DB nouvellement créée est bien vide
    #[test]
    fn test_create_empty_db() {
        // On créer une nouvelle base de données
        let db = VulnerabilityDB::new();

        // On vérifie que la HashMap des advisories est vide
        assert_eq!(
            db.advisories.len(),
            0,
            "Une nouvelle DB doit etre vide, mais elle contient {} entrées",
            db.advisories.len()
        );
    }

    // TEST 2: Charger un fichier TOML valide de vulnérabilité
    // Objectif: Vérifier que load_from_dir() lit correctement un fichier TOML
    #[test]
    fn test_load_valid_toml() {
        // On créer une base de données vide
        let mut db = VulnerabilityDB::new();

        // Créer un fichier TOML de test dans un répartoire temporaire
        let temp_dir =
            tempfile::TempDir::new().expect("Impossible de créer un répartoire temporaire");
        let vuln_file = temp_dir.path().join("test_vuln.toml");

        // Ecrire un fichier TOML valide
        let toml_content = r#"
            [advisory]
            id = "RUSTSEC-2023-0001"
            package = "log4shell"
            severity = "critical"
            title = "Vulnérabilité RCE dans log4shell"
            description = "Permet l'execution de code à distance via la chaine JNDI"
            
            [versions]
            patched = ["0.4.17", "0.5.0"]
            unaffected = ["0.3.0"]"#;

        std::fs::write(&vuln_file, toml_content).expect("Impossible d'écrire le fichier test");

        // Charger la base depuis le répartoire temporaire
        let result = db.load_from_dir(temp_dir.path());

        // 1. Le chargement doit réussir
        assert!(
            result.is_ok(),
            "Le chargement du fichier TOML à échoué : {:?}",
            result.err()
        );

        // 2. La DB doit contenir exactement 1 advisory pour "log4shell"
        assert_eq!(
            db.advisories.len(),
            1,
            "La DB devrait contenir 1 advisory, mais elle en contient {}",
            db.advisories.len()
        );

        // 3. Le package "log4shell" doit exister
        assert!(
            db.advisories.contains_key("log4shell"),
            "Le package 'log4shell' n'a pas chargé"
        );

        let advisories = &db.advisories["log4shell"];
        assert_eq!(
            advisories.len(),
            1,
            "Il devrait y avoir 1 advisory pour log4shell"
        );
        assert_eq!(
            advisories[0].severity,
            Severity::Critical,
            "La sévérité devrait etre Critical"
        );
    }

    // TEST 3: Charger un répertoire avec plusieurs fichiers TOML
    // Objectif: Vérifier que load_from_dir() traite correctement plusieurs fichiers
    #[test]
    fn test_load_multiple_file_from_dir() {
        let mut db = VulnerabilityDB::new();
        let temp_dir =
            tempfile::TempDir::new().expect("Impossible de créer un répartoire temporaire");

        // Créer  fichier TOML valides
        let files_to_create = vec![
            (
                "vuln1.toml",
                r#"
                [advisory]
                id = "RUSTSEC-2023-0001"
                package = "serde"
                severity = "high"
                title = "Désérialisation non sécurisée"
                description = "Les données TOML malveillantes peuvent causer un déni de service"
                
                [versions]
                patched = ["1.0.200"]
                unaffected = ["1.0.0"]"#,
            ),
            (
                "vuln2.toml",
                r#"
                [advisory]
                id = "RUSTSEC-2023-0002"
                package = "reqwest"
                severity = "medium"
                title = "Vulnérabilité de SSRF dans reqwest"
                description = "Permet les attaques SSRF via des requêtes HTTP malveillantes"
                
                [versions]
                patched = ["0.11.10"]
                unaffected = ["0.10.0"]"#,
            ),
            (
                "vuln3.toml",
                r#"
                [advisory]
                id = "RUSTSEC-2023-0003"
                package = "openssl"
                severity = "low"
                title = "Fuite de mémoire"
                description = "Peut causer une fuite de mémoire dans certaines conditions de concurrence"
                
                [versions]
                patched = ["1.20.0"]
                unaffected = ["1.0.0"]"#,
            ),
        ];

        for (filename, content) in files_to_create {
            let file_path = temp_dir.path().join(filename);
            std::fs::write(&file_path, content).expect("Impossible d'écrire le fichier test");
        }

        // Créer 1 fichier corrompu (le scanner doit l'ignorer)
        let corrupted_file = temp_dir.path().join("corrupted.toml");
        std::fs::write(
            &corrupted_file,
            "INVALID TOML ]
            [[[}}}",
        )
        .expect("Impossible d'écrire le fichier");

        // Charger la base
        let result = db.load_from_dir(temp_dir.path());

        // 1. Le chargement ne doit pas planter malgré le fichier corrompu
        assert!(
            result.is_ok(),
            "Le chargement à échoué avec le fichier corrompu"
        );

        // 2. Exactement 3 package doivent etre chargés
        assert_eq!(
            db.advisories.len(),
            3,
            "La DB devrait contenir 3 packages, mais elle en contient {}",
            db.advisories.len()
        );

        // 3. Vérifier que les 3 packages attendus sont présents
        assert!(
            db.advisories.contains_key("serde"),
            "Package 'serde' manquant"
        );
        assert!(
            db.advisories.contains_key("reqwest"),
            "Package 'reqwest' manquant"
        );
        assert!(
            db.advisories.contains_key("openssl"),
            "Package 'openssl' manquant"
        );
    }

    // TEST 4: Détection de vulnérabilités - Cas positif (version vulnérable)
    // Objectif: Vérifier que check_vulnerability() détecte une version vulnérable
    #[test]
    fn test_check_vulnerability_positive() {
        let mut db = VulnerabilityDB::new();

        // Créer une vulnérabilité fictive
        let advisory = Advisory {
            id: "TEST-001".to_string(),
            package: "serde".to_string(),
            severity: Severity::High,
            title: "Test".to_string(),
            description: "Test".to_string(),
            versions: Versions {
                patched: vec!["0.4.0".to_string(), "0.5.0".to_string()],
                unaffected: None,
            },
        };

        db.advisories.insert("serde".to_string(), vec![advisory]);

        // Vérifier une version vulnérable
        let version = Version::parse("0.3.0").expect("Impossible de parser la version");
        let vulnerability = db.check_vulnerability("serde", &version);

        // Une vulnérabilité doit etre trouvée
        assert_eq!(
            vulnerability.len(),
            1,
            "Une vulnérabilité devrait être détectée pour serde 0.3.0"
        );
        assert_eq!(
            vulnerability[0].id, "TEST-001",
            "L'ID de la vulnérabilité est incorrect"
        );
    }

    // TEST 5: Pas de détection pour une version patchée
    // Objectif: Vérifier que check_vulnerability() accepte les versions patchées
    #[test]
    fn test_check_vulnerability_ignore_patch_ver() {
        let mut db = VulnerabilityDB::new();

        // Même vulnérabilité que test précédent
        let advisory = Advisory {
            id: "TEST-001".to_string(),
            package: "serde".to_string(),
            severity: Severity::High,
            title: "Test".to_string(),
            description: "Test".to_string(),
            versions: Versions {
                patched: vec!["0.4.0".to_string(), "0.5.0".to_string()],
                unaffected: None,
            },
        };

        db.advisories.insert("serde".to_string(), vec![advisory]);

        // Vérifier une version patchée
        let version = Version::parse("0.5.0").expect("Impossible de parser la version");
        let vulnerability = db.check_vulnerability("serde", &version);

        // Aucune vulnérabilité ne doit être trouvée
        assert_eq!(
            vulnerability.len(),
            0,
            "Aucune vulnérabilité ne devrait être détectée pour serde 0.5.0 (version patchée)"
        );
    }

    // TEST 6: Package inconnu retourne une liste vide
    // Objectif: Vérifier le comportement si le package n'existe pas dans la DB
    #[test]
    fn test_check_vulnerability_unknown_package() {
        let db = VulnerabilityDB::new();

        // Chercher une vulnérabilité pour un package inconnu
        let version = Version::parse("1.0.0").expect("Impossible de parser la version");
        let vulnerability = db.check_vulnerability("unknown_package", &version);

        // La liste doit être vide
        assert_eq!(
            vulnerability.len(),
            0,
            "La recherche d'un package inconnu doit retourner une liste vide"
        );
    }

    // TEST 7: Plusieurs vulnérabilités pour un seul package
    // Objectif: Vérifier que check_vulnerability() retourne toutes les vulnérabilités
    #[test]
    fn test_check_vulnerability_multiple_advisories() {
        let mut db = VulnerabilityDB::new();

        // Créer 2 vulnérabilités pour le même package
        let advisory1 = Advisory {
            id: "CVE-2024-001".to_string(),
            package: "tokio".to_string(),
            severity: Severity::High,
            title: "Race condition".to_string(),
            description: "...".to_string(),
            versions: Versions {
                patched: vec!["1.35.0".to_string()],
                unaffected: None,
            },
        };

        let advisory2 = Advisory {
            id: "CVE-2024-002".to_string(),
            package: "tokio".to_string(),
            severity: Severity::Medium,
            title: "Déni de service".to_string(),
            description: "...".to_string(),
            versions: Versions {
                patched: vec!["1.36.0".to_string()],
                unaffected: None,
            },
        };

        db.advisories
            .insert("tokio".to_string(), vec![advisory1, advisory2]);

        // Vérifier une version qui n'est patchée pour aucune des deux CVE
        let version = Version::parse("1.30.0").expect("Impossible de parser la version");
        let vulnerability = db.check_vulnerability("tokio", &version);

        // Exactement 2 vulnérabilités doivent être trouvées
        assert_eq!(
            vulnerability.len(),
            2,
            "Deux vulnérabilités devraient être détectées pour tokio 1.30.0"
        );
        assert_eq!(vulnerability[0].id, "CVE-2024-001");
        assert_eq!(vulnerability[1].id, "CVE-2024-002");
    }

    // TEST 8 : Validation stricte TOML - Fichier valide
    #[test]
    fn test_toml_validation_valid_file() {
        let mut db = VulnerabilityDB::new();
        let temp_dir = tempfile::TempDir::new().expect("Impossible de créer un répertoire");
        let vuln_file = temp_dir.path().join("valid.toml");

        let valid_toml = r#"
            [advisory]
            id = "TEST-001"
            package = "serde"
            severity = "high"
            title = "Test Vulnerability"
            description = "This is a test"

            [versions]
            patched = ["1.0.0"]"#;

        std::fs::write(&vuln_file, valid_toml).expect("Impossible d'écrire");

        let result = db.load_from_dir(temp_dir.path());
        assert!(result.is_ok(), "Un fichier TOML valide doit être accepté");
        assert_eq!(db.advisories.len(), 1, "La DB doit contenir 1 package");
    }

    // TEST 9 : Validation stricte TOML - Fichier malformé (syntaxe invalide)
    #[test]
    fn test_toml_validation_malformed() {
        let mut db = VulnerabilityDB::new();
        let temp_dir = tempfile::TempDir::new().expect("Impossible de créer un répertoire");
        let vuln_file = temp_dir.path().join("malformed.toml");

        let malformed_toml = r#"
            [advisory]
            id = "TEST-001"
            package = "serde"
            severity = "high
            title = "Missing quote on severity"

            [versions]
            patched = ["1.0.0"]"#;

        std::fs::write(&vuln_file, malformed_toml).expect("Impossible d'écrire");

        let result = db.load_from_dir(temp_dir.path());
        // Si c'est le SEUL fichier et qu'il est invalide, doit retourner Err
        assert!(
            result.is_err(),
            "Le scan doit retourner une erreur pour un fichier malformé seul"
        );
        assert_eq!(
            db.advisories.len(),
            0,
            "Les fichiers invalides ne doivent pas être chargés"
        );
    }

    // TEST 10 : Validation stricte TOML - Fichier vide
    #[test]
    fn test_toml_validation_empty_file() {
        let mut db = VulnerabilityDB::new();
        let temp_dir = tempfile::TempDir::new().expect("Impossible de créer un répertoire");
        let vuln_file = temp_dir.path().join("empty.toml");

        std::fs::write(&vuln_file, "").expect("Impossible d'écrire");

        let result = db.load_from_dir(temp_dir.path());
        // Si c'est le SEUL fichier et qu'il est vide, doit retourner Err
        assert!(
            result.is_err(),
            "Le scan doit retourner une erreur pour un fichier vide seul"
        );
        assert_eq!(
            db.advisories.len(),
            0,
            "Les fichiers vides ne doivent pas être chargés"
        );
    }

    // TEST 11 : Validation stricte TOML - Champs manquants
    #[test]
    fn test_toml_validation_missing_fields() {
        let mut db = VulnerabilityDB::new();
        let temp_dir = tempfile::TempDir::new().expect("Impossible de créer un répertoire");
        let vuln_file = temp_dir.path().join("incomplete.toml");

        let incomplete_toml = r#"
            [advisory]
            id = "TEST-001"
            # ❌ package est manquant
            severity = "high"
            title = "Missing package field"

            [versions]
            patched = ["1.0.0"]"#;

        std::fs::write(&vuln_file, incomplete_toml).expect("Impossible d'écrire");

        let result = db.load_from_dir(temp_dir.path());
        // Si c'est le SEUL fichier et qu'il est incomplet, doit retourner Err
        assert!(
            result.is_err(),
            "Le scan doit retourner une erreur pour un fichier incomplet seul"
        );
        assert_eq!(
            db.advisories.len(),
            0,
            "Les fichiers avec champs manquants ne doivent pas être chargés"
        );
    }

    // TEST 12 : Vérification SHA-256 - Fichier intact
    #[test]
    fn test_sha256_hash_valid_file() {
        let temp_dir = tempfile::TempDir::new().expect("Impossible de créer un répertoire");
        let db_file = temp_dir.path().join("vuln.toml");

        let content = r#"
            [advisory]
            id = "TEST-001"
            package = "serde"
            severity = "high"
            title = "Test"
            description = "Test"

            [versions]
            patched = ["1.0.0"]"#;

        std::fs::write(&db_file, content).expect("Impossible d'écrire");

        let mut db = VulnerabilityDB::new();
        let result = db.load_from_dir(temp_dir.path());

        assert!(result.is_ok(), "Le chargement doit réussir");

        // Vérifier que l'audit a été créé
        assert!(
            db.integrity_log.is_some(),
            "Le manifeste d'intégrité doit être créé"
        );

        // Vérifier que le hash a été enregistré
        if let Some(audit) = &db.integrity_log {
            assert_eq!(audit.total_files, 1, "1 fichier doit être enregistré");
            assert_eq!(audit.failed_files, 0, "Aucune erreur");
            assert!(
                !audit.advisories.is_empty(),
                "Les hashs doivent être stockés"
            );

            // Vérifier que c'est un hash SHA-256 valide (64 caractères hex)
            let hash = &audit.advisories[0].sha256_hash;
            assert_eq!(hash.len(), 64, "SHA-256 doit faire 64 caractères");
            assert!(
                hash.chars().all(|c| c.is_ascii_hexdigit()),
                "Hash doit être hexadécimal"
            );
        }
    }

    // TEST 13 : Détection de modification de fichier
    #[test]
    fn test_sha256_detect_file_modification() {
        let temp_dir = tempfile::TempDir::new().expect("Impossible de créer un répertoire");
        let db_file = temp_dir.path().join("vuln.toml");

        let original_content = r#"
            [advisory]
            id = "TEST-001"
            package = "serde"
            severity = "high"
            title = "Test"
            description = "Test"

            [versions]
            patched = ["1.0.0"]"#;

        std::fs::write(&db_file, original_content).expect("Impossible d'écrire");

        let mut db = VulnerabilityDB::new();
        db.load_from_dir(temp_dir.path())
            .expect("Chargement initial");

        let original_hash = db.integrity_log.as_ref().unwrap().advisories[0]
            .sha256_hash
            .clone();

        // SIMULATION : Modifier le fichier (attaque ou corruption)
        let modified_content = r#"
            [advisory]
            id = "TEST-001"
            package = "serde"
            severity = "low"  # ⚠️ Modifié de "high" à "low" !!!
            title = "Test"
            description = "Test"

            [versions]
            patched = ["2.0.0"]  # ⚠️ Version patchée changée"#;

        std::fs::write(&db_file, modified_content).expect("Impossible d'écrire");

        // Calculer le nouveau hash
        let new_hash =
            VulnerabilityDB::calculate_file_hash(&db_file).expect("Impossible de calculer le hash");

        // Les hashs doivent être différents
        assert_ne!(
            original_hash, new_hash,
            "Les hashs doivent être différents après modification"
        );

        // La vérification d'intégrité doit échouer
        let verification = VulnerabilityDB::verify_file_integrity(&db_file, &original_hash)
            .expect("Erreur vérification");
        assert!(
            !verification,
            "La vérification d'intégrité doit échouer pour un fichier modifié"
        );
    }

    // TEST 14 : Vérification de la taille du fichier
    #[test]
    fn test_database_integrity_file_size() {
        let temp_dir = tempfile::TempDir::new().expect("Impossible de créer un répertoire");
        let db_file = temp_dir.path().join("vuln.toml");

        let content = r#"
            [advisory]
            id = "TEST-001"
            package = "serde"
            severity = "high"
            title = "Test"
            description = "Test"

            [versions]
            patched = ["1.0.0"]"#;

        std::fs::write(&db_file, content).expect("Impossible d'écrire");

        let mut db = VulnerabilityDB::new();
        db.load_from_dir(temp_dir.path())
            .expect("Chargement initial");

        let file_integrity = &db.integrity_log.as_ref().unwrap().advisories[0];

        // Vérifier que la taille enregistrée correspond
        let metadata = std::fs::metadata(&db_file).expect("Métadonnées");
        assert_eq!(
            file_integrity.file_size,
            metadata.len(),
            "La taille enregistrée doit correspondre"
        );
    }

    // TEST 15 : Audit complet avec plusieurs fichiers
    #[test]
    fn test_database_integrity_multiple_files() {
        let temp_dir = tempfile::TempDir::new().expect("Impossible de créer un répertoire");

        // Créer 3 fichiers de vulnérabilité
        for i in 0..3 {
            let file = temp_dir.path().join(format!("vuln{}.toml", i));
            let content = format!(
                r#"
                [advisory]
                id = "TEST-{:03}"
                package = "pkg{}"
                severity = "high"
                title = "Test {}"
                description = "Test"

                [versions]
                patched = ["1.0.0"]"#,
                i, i, i
            );
            std::fs::write(&file, content).expect("Impossible d'écrire");
        }

        let mut db = VulnerabilityDB::new();
        db.load_from_dir(temp_dir.path()).expect("Chargement");

        let audit = db.integrity_log.as_ref().expect("Audit manquant");

        // Vérifier les statistiques
        assert_eq!(audit.total_files, 3, "3 fichiers doivent être chargés");
        assert_eq!(audit.failed_files, 0, "0 erreur");
        assert_eq!(
            audit.advisories.len(),
            3,
            "3 hashs doivent être enregistrés"
        );

        // Chaque hash doit être valide
        for file_integrity in &audit.advisories {
            assert_eq!(
                file_integrity.sha256_hash.len(),
                64,
                "Chaque hash doit faire 64 caractères"
            );
        }
    }

    // TEST 16 : Vérification du manifeste d'intégrité
    #[test]
    fn test_integrity_manifest_creation() {
        let temp_dir = tempfile::TempDir::new().expect("Impossible de créer un répertoire");
        let db_file = temp_dir.path().join("vuln.toml");

        let content = r#"
            [advisory]
            id = "TEST-001"
            package = "serde"
            severity = "high"
            title = "Test"
            description = "Test"

            [versions]
            patched = ["1.0.0"]"#;

        std::fs::write(&db_file, content).expect("Impossible d'écrire");

        let mut db = VulnerabilityDB::new();
        db.load_from_dir(temp_dir.path()).expect("Chargement");

        // Le manifeste doit avoir été créé
        let manifest_path = temp_dir.path().join(".integrity_manifest");
        assert!(
            manifest_path.exists(),
            "Le manifeste d'intégrité doit être créé"
        );

        // Vérifier le contenu du manifeste
        let manifest_content =
            std::fs::read_to_string(&manifest_path).expect("Impossible de lire le manifeste");

        assert!(
            manifest_content.contains("SHA256"),
            "Le manifeste doit contenir les hashs SHA256"
        );
        assert!(
            manifest_content.contains("Size"),
            "Le manifeste doit contenir les tailles"
        );
    }
}
