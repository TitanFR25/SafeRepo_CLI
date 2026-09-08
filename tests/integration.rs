// DESCRIPTION: Tests d'intégration complets du système (end-to-end)
#[cfg(test)]
mod tests_integration {
    use SafeRepo_CLI::database::db::VulnerabilityDB;
    use SafeRepo_CLI::scaning::scan::{ScanOptions, scan_repo};
    use SafeRepo_CLI::secure::security::SecurityManager;
    use ed25519_dalek::{Signer, SigningKey};
    use std::thread;
    use std::time::Duration;
    use std::{fs, path::Path};
    use tempfile::TempDir;

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn write_signed_manifest(db_path: &Path, signing_key: &SigningKey, files: &[&Path]) {
        let mut manifest = String::from("# Database Integrity Manifest\n\n");
        for file_path in files {
            let hash = VulnerabilityDB::calculate_file_hash(file_path)
                .expect("Impossible de calculer le hash du fixture");
            let size = fs::metadata(file_path)
                .expect("Impossible de lire les métadonnées du fixture")
                .len();
            manifest.push_str(&format!(
                "{}\n  SHA256: {}\n  Size: {} bytes\n\n",
                file_path.display(),
                hash,
                size
            ));
        }

        fs::write(db_path.join(".integrity_manifest"), &manifest)
            .expect("Impossible d'écrire le manifeste signé");
        fs::write(
            db_path.join(".integrity_manifest.sig"),
            signing_key.sign(manifest.as_bytes()).to_bytes(),
        )
        .expect("Impossible d'écrire la signature du manifeste");
    }

    // TEST 1: Scan complet d'un projet fictif (Node.js + Rust)
    // Objectif: Simuler un vrai scan d'un projet multi-langage
    #[test]
    fn test_full_scan_multiplatform_project() {
        // Créer une structure de projet réaliste
        let temp_dir = TempDir::new().expect("Impossible de créer un répertoire temporaire");

        // 1. Créer src/
        let src_dir = temp_dir.path().join("src");
        fs::create_dir(&src_dir).expect("Impossible de créer src/");

        // 2. Créer Cargo.lock
        let cargo_lock = src_dir.join("Cargo.lock");
        let cargo_content = r#"
            [[package]]
            name = "log"
            version = "0.4.18"

            [[package]]
            name = "serde"
            version = "1.0.200"

            [[package]]
            name = "tokio"
            version = "1.40.0""#;

        fs::write(&cargo_lock, cargo_content).expect("Impossible de créer Cargo.lock");

        // 3. Créer package-lock.json
        let package_lock = temp_dir.path().join("package-lock.json");
        let package_content = r#"
            {
                "name": "my-app",
                "packages": {
                    "": {
                        "name": "my-app",
                        "dependencies": {
                            "express": "^4.18.2",
                            "lodash": "^4.17.21"
                        }
                    }
                }
            }
        "#;
        fs::write(&package_lock, package_content).expect("Impossible de créer package-lock.json");

        // 4. Créer des fichiers non-manifestes (doivent être ignorés)
        fs::write(temp_dir.path().join("README.md"), "# My Project")
            .expect("Impossible de créer README");

        fs::write(temp_dir.path().join("main.js"), "console.log('hello')")
            .expect("Impossible de créer main.js");

        let manager = SecurityManager {
            db: VulnerabilityDB::new(),
        };

        // Scanner le projet complet
        let result = scan_repo(temp_dir.path(), &manager, &ScanOptions::default());

        // Le scan doit réussir
        assert!(result.is_ok(), "Le scan complet doit réussir");
    }

    // TEST 2: Détection correcte d'une vulnérabilité connue
    // Objectif: Vérifier le workflow complet: detect -> report
    #[test]
    fn test_detect_and_report_vulnerability() {
        // Créer une DB avec une vulnérabilité
        let temp_db_dir = TempDir::new().expect("Impossible de créer un répertoire temporaire");
        let vuln_file = temp_db_dir.path().join("serde_vuln.toml");

        let toml_content = r#"
            [advisory]
            id = "RUSTSEC-2024-0001"
            package = "serde"
            severity = "high"
            title = "Vulnérabilité de sérialisation"
            description = "Les données sérializées malveillantes peuvent causer un crash"

            [versions]
            patched = ["1.0.200"]"#;

        fs::write(&vuln_file, toml_content).expect("Impossible d'écrire la vulnérabilité");
        let signing_key = test_signing_key();
        write_signed_manifest(temp_db_dir.path(), &signing_key, &[&vuln_file]);

        // Créer le projet avec Cargo.lock vulnérable
        let project_dir = TempDir::new().expect("Impossible de créer un répertoire temporaire");

        let cargo_lock = project_dir.path().join("Cargo.lock");

        let cargo_content = r#"
        [[package]]
        name = "serde"
        version = "1.0.100"  # Version vulnérable (< 1.0.200)"#;

        fs::write(&cargo_lock, cargo_content).expect("Impossible de créer Cargo.lock");

        // Créer le manager avec la DB signée
        let mut db = VulnerabilityDB::new();
        db.load_from_dir_with_verifying_key(temp_db_dir.path(), &signing_key.verifying_key())
            .expect("La base temporaire signée doit être chargée");
        let manager = SecurityManager { db };

        // Scanner et analyser
        let issues = manager
            .analyze_file(&cargo_lock)
            .expect("Le Cargo.lock vulnérable doit être analysé")
            .len();

        // Une vulnérabilité doit être détectée
        assert_eq!(
            issues, 1,
            "La vulnérabilité de serde 1.0.100 doit être détectée"
        );
    }

    // TEST 3: Pas de faux positifs (version patchée ignorée)
    // Objectif: Vérifier qu'une version corrigée n'est pas signalée
    #[test]
    fn test_no_false_positives_patched_versions() {
        // Même vulnérabilité que avant
        let temp_db_dir = TempDir::new().expect("Impossible de créer un répertoire temporaire");
        let vuln_file = temp_db_dir.path().join("serde_vuln.toml");

        let toml_content = r#"
            [advisory]
            id = "RUSTSEC-2024-0001"
            package = "serde"
            severity = "high"
            title = "Vulnérabilité"
            description = "Test"

            [versions]
            patched = ["1.0.200"]"#;

        fs::write(&vuln_file, toml_content).expect("Impossible d'écrire la vulnérabilité");
        let signing_key = test_signing_key();
        write_signed_manifest(temp_db_dir.path(), &signing_key, &[&vuln_file]);

        // Créer le projet avec Cargo.lock sain
        let project_dir = TempDir::new().expect("Impossible de créer un répertoire temporaire");
        let cargo_lock = project_dir.path().join("Cargo.lock");

        let cargo_content = r#"
            [[package]]
            name = "serde"
            version = "1.0.200"  # Version patchée (= patched)"#;

        fs::write(&cargo_lock, cargo_content).expect("Impossible de créer Cargo.lock");

        let mut db = VulnerabilityDB::new();
        db.load_from_dir_with_verifying_key(temp_db_dir.path(), &signing_key.verifying_key())
            .expect("La base temporaire signée doit être chargée");
        let manager = SecurityManager { db };

        // Analyser
        let issues = manager
            .analyze_file(&cargo_lock)
            .expect("Le Cargo.lock patché doit être analysé")
            .len();

        // AUCUNE vulnérabilité ne doit être trouvée
        assert_eq!(
            issues, 0,
            "Aucune vulnérabilité ne doit être détectée pour serde 1.0.200 (version patchée)"
        );
    }

    // TEST 4: Comportement avec DB manquante ou vide
    // Objectif: Vérifier qu'une DB manquante bloque le scan
    #[test]
    fn test_scan_with_missing_database() {
        let result = SecurityManager::new("/tmp/nonexistent_db_12345");

        assert!(result.is_err(), "Une DB manquante doit être refusée");

        let empty_db = TempDir::new().expect("Impossible de créer une DB temporaire vide");
        let result = SecurityManager::new(empty_db.path().to_str().expect("Chemin invalide"));

        assert!(result.is_err(), "Une DB vide doit être refusée");
    }

    // TEST 5: Vérification d'intégrité de la base de données
    // Objectif: Tester verify_database_integrity() en conditions réelles
    // - Créer une DB avec fichiers de vulnérabilités
    // - Charger la DB et générer un manifeste d'intégrité
    // - Vérifier l'intégrité (doit réussir initialement)
    // - Modifier un fichier de vulnérabilité
    // - Vérifier l'intégrité (doit détecter la modification)
    #[test]
    fn test_database_integrity_verification_integration() {
        // 1. Créer une DB temporaire avec des fichiers de vulnérabilités valides
        let temp_db_dir = TempDir::new().expect("Impossible de créer répertoire DB temporaire");

        // Créer fichier de vulnérabilité 1: serde
        let serde_vuln = temp_db_dir.path().join("serde_vuln.toml");
        let serde_content = r#"
            [advisory]
            id = "RUSTSEC-2024-0001"
            package = "serde"
            severity = "high"
            title = "Serde Serialization Vulnerability"
            description = "Malformed data can cause DOS"

            [versions]
            patched = ["1.0.200"]"#;

        fs::write(&serde_vuln, serde_content).expect("Impossible de créer fichier serde_vuln.toml");

        // Créer fichier de vulnérabilité 2: tokio
        let tokio_vuln = temp_db_dir.path().join("tokio_vuln.toml");
        let tokio_content = r#"
            [advisory]
            id = "RUSTSEC-2024-0002"
            package = "tokio"
            severity = "critical"
            title = "Tokio Runtime Panic"
            description = "Panic in runtime scheduling"

            [versions]
            patched = ["1.40.0"]"#;

        fs::write(&tokio_vuln, tokio_content).expect("Impossible de créer fichier tokio_vuln.toml");

        let signing_key = test_signing_key();
        write_signed_manifest(
            temp_db_dir.path(),
            &signing_key,
            &[&serde_vuln, &tokio_vuln],
        );

        // 2. Charger la DB et générer les hashes d'intégrité
        let mut db = VulnerabilityDB::new();
        let load_result =
            db.load_from_dir_with_verifying_key(temp_db_dir.path(), &signing_key.verifying_key());
        assert!(
            load_result.is_ok(),
            "Le chargement de la DB doit réussir: {:?}",
            load_result
        );

        // Vérifier que des fichiers ont été chargés
        assert!(
            !db.advisories.is_empty(),
            "La DB doit contenir au moins une vulnérabilité"
        );

        // Vérifier que le log d'audit a été créé
        assert!(
            db.integrity_log.is_some(),
            "Un log d'audit d'intégrité doit être généré"
        );

        // 3. Vérifier l'intégrité initiale (doit réussir)
        let integrity_check = db.verify_database_integrity_with_verifying_key(
            temp_db_dir.path(),
            &signing_key.verifying_key(),
        );
        assert!(
            integrity_check.is_ok(),
            "La vérification d'intégrité initiale doit réussir"
        );
        assert!(
            integrity_check.unwrap(),
            "L'intégrité doit être confirmée pour une DB non modifiée"
        );

        // 4. Modifier un fichier de vulnérabilité pour simuler une corruption
        let modified_content = r#"
            [advisory]
            id = "RUSTSEC-2024-0001"
            package = "serde"
            severity = "high"
            title = "Serde Serialization Vulnerability - MODIFIED"
            description = "Malformed data can cause DOS - UNAUTHORIZED MODIFICATION"

            [versions]
            patched = ["1.0.200"]"#;

        // Attendre un peu pour s'assurer que la modification est détectable
        thread::sleep(Duration::from_millis(100));

        fs::write(&serde_vuln, modified_content)
            .expect("Impossible de modifier fichier serde_vuln.toml");

        // 5. Charger la DB modifiée et vérifier que l'intégrité détecte le changement
        let mut db_modified = VulnerabilityDB::new();
        let load_result_mod = db_modified
            .load_from_dir_with_verifying_key(temp_db_dir.path(), &signing_key.verifying_key());
        assert!(
            load_result_mod.is_err(),
            "Le chargement doit refuser une DB qui diffère du manifeste"
        );

        // Comparer les hashes avec le log d'audit précédent
        if let Some(original_audit) = &db.integrity_log
            && let Some(modified_audit) = &db_modified.integrity_log
        {
            let hashes_changed = original_audit
                .advisories
                .iter()
                .zip(modified_audit.advisories.iter())
                .any(|(orig, modified)| orig.sha256_hash != modified.sha256_hash);

            assert!(
                hashes_changed,
                "Au moins un hash de fichier doit avoir changé après modification"
            );
        }

        println!("✅ Test d'intégrité DB réussi: modification détectée correctement");
    }

    // TEST 6: Vérification d'intégrité sans manifeste
    // Objectif: Vérifier le comportement quand le manifeste n'existe pas
    #[test]
    fn test_database_integrity_missing_manifest() {
        // Créer une DB temporaire sans manifeste
        let temp_db_dir = TempDir::new().expect("Impossible de créer répertoire DB temporaire");

        // Créer un fichier de vulnérabilité valide
        let vuln_file = temp_db_dir.path().join("test_vuln.toml");
        let content = r#"
            [advisory]
            id = "TEST-001"
            package = "test"
            severity = "high"
            title = "Test"
            description = "Test"

            [versions]
            patched = ["1.0.0"]"#;

        fs::write(&vuln_file, content).expect("Impossible de créer fichier de test");

        // Créer une DB mais NE PAS charger (pour ne pas créer le manifeste)
        let empty_db = VulnerabilityDB::new();

        // Essayer de vérifier l'intégrité sans manifeste et sans chargement
        let integrity_result = empty_db.verify_database_integrity(temp_db_dir.path());

        // Doit retourner une erreur car pas de manifeste
        assert!(
            integrity_result.is_err(),
            "Vérification doit échouer sans manifeste d'intégrité"
        );

        let error_msg = integrity_result.unwrap_err();
        assert!(
            error_msg.contains("manifest"),
            "Le message d'erreur doit mentionner le manifeste manquant: {}",
            error_msg
        );

        println!("✅ Test manifeste manquant réussi: erreur correctement rapportée");
    }

    // TEST 7: Signature de manifeste absente ou altérée
    // Objectif: Vérifier qu'une DB refuse un manifeste sans signature valide
    #[test]
    fn test_database_rejects_missing_or_tampered_manifest_signature() {
        // Créer une DB signée contenant un fichier de vulnérabilité valide.
        let temp_db_dir = TempDir::new().expect("Impossible de créer répertoire DB temporaire");
        let vulnerability_file = temp_db_dir.path().join("test_vuln.toml");
        fs::write(
            &vulnerability_file,
            "[advisory]\nid = \"TEST-001\"\npackage = \"test\"\nseverity = \"high\"\ntitle = \"Test\"\ndescription = \"Test\"\n\n[versions]\npatched = [\"1.0.0\"]",
        )
        .expect("Impossible d'écrire la vulnérabilité de test");
        let signing_key = test_signing_key();
        write_signed_manifest(temp_db_dir.path(), &signing_key, &[&vulnerability_file]);

        // Supprimer la signature et vérifier que le chargement est refusé.
        fs::remove_file(temp_db_dir.path().join(".integrity_manifest.sig"))
            .expect("Impossible de supprimer la signature");
        let mut missing_signature_db = VulnerabilityDB::new();
        assert!(
            missing_signature_db
                .load_from_dir_with_verifying_key(temp_db_dir.path(), &signing_key.verifying_key())
                .is_err(),
            "Une signature absente doit être refusée"
        );

        // Recréer le manifeste, altérer sa signature, puis vérifier son rejet.
        write_signed_manifest(temp_db_dir.path(), &signing_key, &[&vulnerability_file]);
        let signature_path = temp_db_dir.path().join(".integrity_manifest.sig");
        let mut signature = fs::read(&signature_path).expect("Impossible de lire la signature");
        signature[0] ^= 1;
        fs::write(&signature_path, signature).expect("Impossible d'altérer la signature");

        let mut tampered_signature_db = VulnerabilityDB::new();
        assert!(
            tampered_signature_db
                .load_from_dir_with_verifying_key(temp_db_dir.path(), &signing_key.verifying_key())
                .is_err(),
            "Une signature altérée doit être refusée"
        );
    }
}
