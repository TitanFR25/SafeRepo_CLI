// DESCRIPTION: Tests complets pour le module OSV - Détection d'écosystème
#[cfg(test)]
mod tests_osv_client {
    use SafeRepo_CLI::database::db::Severity;
    use SafeRepo_CLI::osv::client::OsvClient;

    // TEST 1: Détection écosystème Cargo
    // Objectif: Vérifier la détection correcte des fichiers Cargo.lock et Cargo.toml
    #[test]
    fn test_detect_ecosystem_cargo_files() {
        // Les deux manifestes Rust doivent être associés à crates.io.
        assert_eq!(OsvClient::detect_ecosystem("Cargo.lock"), "crates.io");
        assert_eq!(OsvClient::detect_ecosystem("Cargo.toml"), "crates.io");
    }

    // TEST 2: Détection écosystème npm
    // Objectif: Vérifier la détection correcte des fichiers package-lock.json et package.json
    #[test]
    fn test_detect_ecosystem_npm_files() {
        // Les manifestes NPM doivent être associés à l'écosystème npm.
        assert_eq!(OsvClient::detect_ecosystem("package-lock.json"), "npm");
        assert_eq!(OsvClient::detect_ecosystem("package.json"), "npm");
    }

    // TEST 3: Détection écosystème Python
    // Objectif: Vérifier la détection correcte des fichiers requirements.txt et setup.py
    #[test]
    fn test_detect_ecosystem_python_files() {
        // Les formats Python supportés doivent être associés à PyPI.
        assert_eq!(OsvClient::detect_ecosystem("requirements.txt"), "PyPI");
        assert_eq!(OsvClient::detect_ecosystem("setup.py"), "PyPI");
    }

    // TEST 4: Détection écosystème Go
    // Objectif: Vérifier la détection correcte des fichiers go.mod et go.sum
    #[test]
    fn test_detect_ecosystem_go_files() {
        // Les manifestes Go doivent être associés à Go.
        assert_eq!(OsvClient::detect_ecosystem("go.mod"), "Go");
        assert_eq!(OsvClient::detect_ecosystem("go.sum"), "Go");
    }

    // TEST 5: Détection écosystème Ruby
    // Objectif: Vérifier la détection correcte des fichiers Gemfile et Gemfile.lock
    #[test]
    fn test_detect_ecosystem_ruby_files() {
        // Les manifestes Ruby doivent être associés à RubyGems.
        assert_eq!(OsvClient::detect_ecosystem("Gemfile"), "RubyGems");
        assert_eq!(OsvClient::detect_ecosystem("Gemfile.lock"), "RubyGems");
    }

    // TEST 6: Détection écosystème PHP
    // Objectif: Vérifier la détection correcte des fichiers composer.json et composer.lock
    #[test]
    fn test_detect_ecosystem_php_files() {
        // Les manifestes PHP doivent être associés à Packagist.
        assert_eq!(OsvClient::detect_ecosystem("composer.json"), "Packagist");
        assert_eq!(OsvClient::detect_ecosystem("composer.lock"), "Packagist");
    }

    // TEST 7: Détection écosystème Java
    // Objectif: Vérifier la détection correcte du fichier pom.xml
    #[test]
    fn test_detect_ecosystem_java_files() {
        // Le manifeste Maven doit être associé à l'écosystème Maven.
        assert_eq!(OsvClient::detect_ecosystem("pom.xml"), "Maven");
    }

    // TEST 8: Insensibilité à la casse
    // Objectif: Vérifier que la détection fonctionne indépendamment de la casse
    #[test]
    fn test_detect_ecosystem_case_insensitive() {
        // Vérifier que la casse du nom de fichier ne change pas l'écosystème détecté.
        assert_eq!(OsvClient::detect_ecosystem("CARGO.LOCK"), "crates.io");
        assert_eq!(OsvClient::detect_ecosystem("Package-Lock.JSON"), "npm");
        assert_eq!(OsvClient::detect_ecosystem("REQUIREMENTS.TXT"), "PyPI");
    }

    // TEST 9: Fallback par défaut pour écosystèmes inconnus
    // Objectif: Vérifier que les fichiers inconnus retournent par défaut "crates.io"
    #[test]
    fn test_detect_ecosystem_unknown_defaults_to_crates_io() {
        // Un nom inconnu doit utiliser l'écosystème par défaut.
        assert_eq!(OsvClient::detect_ecosystem("unknown.txt"), "crates.io");
        assert_eq!(OsvClient::detect_ecosystem("random_file"), "crates.io");
    }

    // TEST 10: Détection avec chemins complets
    // Objectif: Vérifier que la détection fonctionne avec des chemins absolus et relatifs
    #[test]
    fn test_detect_ecosystem_with_paths() {
        // Vérifier la détection lorsque le manifeste est fourni avec un chemin complet.
        assert_eq!(
            OsvClient::detect_ecosystem("/path/to/Cargo.lock"),
            "crates.io"
        );
        assert_eq!(
            OsvClient::detect_ecosystem("C:\\project\\package-lock.json"),
            "npm"
        );
    }

    // TEST 11: Parsing d'une réponse OSV réelle
    // Objectif: Vérifier la conversion d'une réponse JSON OSV en advisory
    #[test]
    fn test_parse_osv_payload() {
        // Préparer une réponse OSV minimale contenant une vulnérabilité Rust.
        let payload = r#"{
            "vulns": [
                {
                    "id": "GHSA-test-1",
                    "summary": "Example vulnerability",
                    "details": "Example details",
                    "severity": "HIGH",
                    "affected": [
                        {
                            "package": {"ecosystem": "crates.io", "name": "serde"},
                            "ranges": [
                                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.188"}]}
                            ],
                            "versions": ["0.9.0", "1.0.0"]
                        }
                    ]
                }
            ]
        }"#;

        // Parser la réponse puis vérifier les champs convertis en advisory.
        let advisories = OsvClient::parse_response(payload).expect("valid OSV payload");

        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].id, "GHSA-test-1");
        assert_eq!(advisories[0].title, "Example vulnerability");
        assert_eq!(advisories[0].severity, Severity::High);
        assert_eq!(advisories[0].versions.patched, vec!["1.0.188"]);
    }
}
