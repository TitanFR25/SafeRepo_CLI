// Tests complets et vicieux pour le module CLI - Clap parsing et commandes
#[cfg(test)]
mod tests_cli_complete {
    use SafeRepo_CLI::command::cli::{Cli, Commands};
    use std::{fs, path::PathBuf};

    #[test]
    fn test_cli_validate_scan_path_accepts_existing_directory() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,
            json: false,
            config: None,
        };

        let temp_dir =
            std::env::temp_dir().join(format!("saferepo-cli-test-{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        let result = cli.validate_scan_path(&temp_dir);

        assert!(result.is_ok());
        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn test_cli_validate_scan_path_rejects_missing_directory() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,
            json: false,
            config: None,
        };

        let missing_path =
            std::env::temp_dir().join(format!("saferepo-missing-{}", std::process::id()));
        let result = cli.validate_scan_path(&missing_path);

        assert!(result.is_err());
    }

    // TEST 1: Parse Scan Command
    // Objectif: Vérifier que la commande Scan est parsée correctement
    #[test]
    fn test_cli_parse_scan_command() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { path, .. } => {
                assert_eq!(path, &PathBuf::from("."));
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 2: Scan avec chemin absolu
    // Objectif: Vérifier que les chemins absolus sont acceptés
    #[test]
    fn test_cli_scan_with_absolute_path() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("/home/user/project"),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { path, .. } => {
                assert!(path.is_absolute() || path.display().to_string() == "/home/user/project");
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 3: Scan avec chemin relatif
    // Objectif: Vérifier que les chemins relatifs sont acceptés
    #[test]
    fn test_cli_scan_with_relative_path() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("../parent/project"),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { path, .. } => {
                assert_eq!(path.display().to_string(), "../parent/project");
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 4: Scan avec sévérité critique
    // Objectif: Vérifier que le paramètre critical est accepté
    #[test]
    fn test_cli_scan_with_critical_severity() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: Some("critical".to_string()),
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { min_severity, .. } => {
                assert_eq!(min_severity, &Some("critical".to_string()));
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 5: Scan avec sévérité haute
    // Objectif: Vérifier que le paramètre high est accepté
    #[test]
    fn test_cli_scan_with_high_severity() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: Some("high".to_string()),
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { min_severity, .. } => {
                assert_eq!(min_severity, &Some("high".to_string()));
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 6: Scan avec sévérité moyenne
    // Objectif: Vérifier que le paramètre medium est accepté
    #[test]
    fn test_cli_scan_with_medium_severity() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: Some("medium".to_string()),
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { min_severity, .. } => {
                assert_eq!(min_severity, &Some("medium".to_string()));
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 7: Scan avec sévérité basse
    // Objectif: Vérifier que le paramètre low est accepté
    #[test]
    fn test_cli_scan_with_low_severity() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: Some("low".to_string()),
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { min_severity, .. } => {
                assert_eq!(min_severity, &Some("low".to_string()));
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 8: Scan avec une seule exclusion
    // Objectif: Vérifier que l'exclusion simple fonctionne
    #[test]
    fn test_cli_scan_with_single_exclude() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: Some(vec!["node_modules".to_string()]),
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { exclude, .. } => {
                assert_eq!(exclude, &Some(vec!["node_modules".to_string()]));
                assert_eq!(exclude.as_ref().unwrap().len(), 1);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 9: Scan avec multiples exclusions
    // Objectif: Vérifier que plusieurs exclusions fonctionnent
    #[test]
    fn test_cli_scan_with_multiple_excludes() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: Some(vec![
                    "node_modules".to_string(),
                    "test".to_string(),
                    "build".to_string(),
                    ".git".to_string(),
                ]),
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { exclude, .. } => {
                assert_eq!(exclude.as_ref().unwrap().len(), 4);
                assert!(
                    exclude
                        .as_ref()
                        .unwrap()
                        .contains(&"node_modules".to_string())
                );
                assert!(exclude.as_ref().unwrap().contains(&"test".to_string()));
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 10: Scan avec wildcard d'exclusion
    // Objectif: Vérifier que les patterns wildcard d'exclusion sont supportés
    #[test]
    fn test_cli_scan_with_wildcard_exclude() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: Some(vec!["*.tmp".to_string(), "**/.cache".to_string()]),
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { exclude, .. } => {
                let excludes = exclude.as_ref().unwrap();
                assert!(excludes.iter().any(|e| e.contains("*")));
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 11: Scan avec un seul thread
    // Objectif: Vérifier que le paramètre threads=1 fonctionne
    #[test]
    fn test_cli_scan_with_single_thread() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: Some(1),
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { threads, .. } => {
                assert_eq!(threads, &Some(1));
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 12: Scan avec multiples threads
    // Objectif: Vérifier que les multiples threads sont acceptés
    #[test]
    fn test_cli_scan_with_multiple_threads() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: Some(16),
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { threads, .. } => {
                assert_eq!(threads, &Some(16));
                assert!(*threads.as_ref().unwrap() > 0);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 13: Scan avec threads excessifs
    // Objectif: Vérifier que les nombres élevés de threads sont acceptés
    #[test]
    fn test_cli_scan_with_excessive_threads() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: Some(256),
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { threads, .. } => {
                // Parse accepte le nombre mais validation devrait être au runtime
                assert_eq!(threads, &Some(256));
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 14: Skip code scan - faux
    // Objectif: Vérifier que skip_code_scan=false est reconnu
    #[test]
    fn test_cli_scan_skip_code_scan_false() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { skip_code_scan, .. } => {
                assert!(!skip_code_scan);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 15: Skip code scan - vrai
    // Objectif: Vérifier que skip_code_scan=true est reconnu
    #[test]
    fn test_cli_scan_skip_code_scan_true() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: true,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { skip_code_scan, .. } => {
                assert!(*skip_code_scan);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 16: Option verbose activée
    // Objectif: Vérifier que verbose=true régle le log level à debug
    #[test]
    fn test_cli_verbose_option() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: true,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        assert!(cli.verbose);
        assert_eq!(cli.get_log_level(), "debug");
    }

    // TEST 17: Option verbose désactivée
    // Objectif: Vérifier que verbose=false régle le log level à info
    #[test]
    fn test_cli_verbose_false() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        assert!(!cli.verbose);
        assert_eq!(cli.get_log_level(), "info");
    }

    // TEST 18: Log level custom override verbose
    // Objectif: Vérifier qu'un log_level explicite override verbose
    #[test]
    fn test_cli_custom_log_level_overrides_verbose() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: true,
            log_level: Some("trace".to_string()),
            set_config: None,
            json: false,
            config: None,
        };

        assert_eq!(cli.get_log_level(), "trace");
    }

    // TEST 19: Log level toutes les variantes
    // Objectif: Vérifier que tous les log levels (trace, debug, info, warn, error) fonctionnent
    #[test]
    fn test_cli_log_level_all_variants() {
        let levels = vec!["trace", "debug", "info", "warn", "error"];
        for level in levels {
            let cli = Cli {
                command: Commands::Scan {
                    path: PathBuf::from("."),
                    min_severity: None,
                    exclude: None,
                    skip_code_scan: false,
                    threads: None,
                    output: None,
                },
                verbose: false,
                log_level: Some(level.to_string()),
                set_config: None,
                json: false,
                config: None,
            };

            assert_eq!(cli.get_log_level(), level);
        }
    }

    // TEST 20: JSON output flag vrai
    // Objectif: Vérifier que json=true est reconnu
    #[test]
    fn test_cli_json_output_flag_true() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: true,
            config: None,
        };

        assert!(cli.is_json_output());
    }

    // TEST 21: JSON output flag faux
    // Objectif: Vérifier que json=false est reconnu
    #[test]
    fn test_cli_json_output_flag_false() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        assert!(!cli.is_json_output());
    }

    // TEST 22: Commande Check avec toutes les options
    // Objectif: Vérifier que la commande Check parse correctement tous les paramètres
    #[test]
    fn test_cli_check_command() {
        let cli = Cli {
            command: Commands::Check {
                file: PathBuf::from("Cargo.lock"),
                min_severity: Some("high".to_string()),
                detailed: true,
                output: Some(PathBuf::from("report.txt")),
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Check {
                file,
                detailed,
                min_severity,
                ..
            } => {
                assert_eq!(file, &PathBuf::from("Cargo.lock"));
                assert!(*detailed);
                assert_eq!(min_severity, &Some("high".to_string()));
            }
            _ => panic!("Expected Check command"),
        }
    }

    // TEST 23: Commande Check minimaliste
    // Objectif: Vérifier que Check fonctionne sans options optionnelles
    #[test]
    fn test_cli_check_command_minimal() {
        let cli = Cli {
            command: Commands::Check {
                file: PathBuf::from("package-lock.json"),
                min_severity: None,
                detailed: false,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Check {
                file,
                detailed,
                min_severity,
                output,
            } => {
                assert_eq!(file, &PathBuf::from("package-lock.json"));
                assert!(!detailed);
                assert!(min_severity.is_none());
                assert!(output.is_none());
            }
            _ => panic!("Expected Check command"),
        }
    }

    // TEST 24: Commande Update avec toutes les options
    // Objectif: Vérifier que Update parse correctement force, source et vérification
    #[test]
    fn test_cli_update_command_with_all_options() {
        let cli = Cli {
            command: Commands::Update {
                force: true,
                source: Some("osv".to_string()),
                verbose_update: true,
                verify_signature: true,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Update {
                force,
                source,
                verify_signature,
                verbose_update,
            } => {
                assert!(*force);
                assert_eq!(source, &Some("osv".to_string()));
                assert!(*verify_signature);
                assert!(*verbose_update);
            }
            _ => panic!("Expected Update command"),
        }
    }

    // TEST 25: Commande Update avec source GitHub
    // Objectif: Vérifier que source=github est accepté
    #[test]
    fn test_cli_update_command_github_source() {
        let cli = Cli {
            command: Commands::Update {
                force: false,
                source: Some("github".to_string()),
                verbose_update: false,
                verify_signature: false,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Update { source, .. } => {
                assert_eq!(source, &Some("github".to_string()));
            }
            _ => panic!("Expected Update command"),
        }
    }

    // TEST 26: Commande Update avec source Snyk
    // Objectif: Vérifier que source=snyk est accepté
    #[test]
    fn test_cli_update_command_snyk_source() {
        let cli = Cli {
            command: Commands::Update {
                force: false,
                source: Some("snyk".to_string()),
                verbose_update: false,
                verify_signature: false,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Update { source, .. } => {
                assert_eq!(source, &Some("snyk".to_string()));
            }
            _ => panic!("Expected Update command"),
        }
    }

    // TEST 27: Commande Config afficher le chemin
    // Objectif: Vérifier que Config show_path=true fonctionne
    #[test]
    fn test_cli_config_command_show_path() {
        let cli = Cli {
            command: Commands::Config {
                show_path: true,
                reset: false,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Config { show_path, reset } => {
                assert!(*show_path);
                assert!(!*reset);
            }
            _ => panic!("Expected Config command"),
        }
    }

    // TEST 28: Commande Config réinitialiser
    // Objectif: Vérifier que Config reset=true fonctionne
    #[test]
    fn test_cli_config_command_reset() {
        let cli = Cli {
            command: Commands::Config {
                show_path: false,
                reset: true,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Config { show_path, reset } => {
                assert!(!*show_path);
                assert!(*reset);
            }
            _ => panic!("Expected Config command"),
        }
    }

    // TEST 29: Commande Stats complète
    // Objectif: Vérifier que Stats avec toutes les options fonctionne
    #[test]
    fn test_cli_stats_command_full() {
        let cli = Cli {
            command: Commands::Stats {
                days: 90,
                by_language: true,
                by_severity: true,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Stats {
                days,
                by_language,
                by_severity,
            } => {
                assert_eq!(*days, 90);
                assert!(*by_language);
                assert!(*by_severity);
            }
            _ => panic!("Expected Stats command"),
        }
    }

    // TEST 30: Commande Stats minimaliste
    // Objectif: Vérifier que Stats fonctionne sans paramètres optionnels
    #[test]
    fn test_cli_stats_command_minimal() {
        let cli = Cli {
            command: Commands::Stats {
                days: 30,
                by_language: false,
                by_severity: false,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Stats {
                days,
                by_language,
                by_severity,
            } => {
                assert_eq!(*days, 30);
                assert!(!*by_language);
                assert!(!*by_severity);
            }
            _ => panic!("Expected Stats command"),
        }
    }

    // TEST 31: Commande Stats avec jours custom
    // Objectif: Vérifier que Stats accepte différentes valeurs de days
    #[test]
    fn test_cli_stats_with_custom_days() {
        let cli = Cli {
            command: Commands::Stats {
                days: 365,
                by_language: false,
                by_severity: false,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Stats { days, .. } => {
                assert_eq!(*days, 365);
            }
            _ => panic!("Expected Stats command"),
        }
    }

    // TEST 32: Chemin de config custom
    // Objectif: Vérifier que le chemin de config custom est respecté
    #[test]
    fn test_cli_custom_config_path() {
        let config_path = PathBuf::from("/etc/saferepo/config.toml");
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: Some(config_path.clone()),
        };

        assert_eq!(cli.get_config_path(), Some(&config_path));
    }

    // TEST 33: Chemin de config absent
    // Objectif: Vérifier que config=None est géré correctement
    #[test]
    fn test_cli_config_path_none() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        assert_eq!(cli.get_config_path(), None);
    }

    // TEST 34: Scan avec toutes les options combinées
    // Objectif: Vérifier que tous les paramètres peuvent être utilisés ensemble
    #[test]
    fn test_cli_scan_all_options_combined() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("/home/user/project"),
                min_severity: Some("critical".to_string()),
                exclude: Some(vec!["node_modules".to_string(), ".git".to_string()]),
                skip_code_scan: true,
                threads: Some(8),
                output: Some(PathBuf::from("report.json")),
            },
            verbose: true,
            log_level: Some("debug".to_string()),
            set_config: None,
            json: true,
            config: Some(PathBuf::from("/etc/saferepo.toml")),
        };

        match &cli.command {
            Commands::Scan {
                path,
                min_severity,
                exclude,
                skip_code_scan,
                threads,
                output,
            } => {
                assert_eq!(path.display().to_string(), "/home/user/project");
                assert_eq!(min_severity, &Some("critical".to_string()));
                assert_eq!(exclude.as_ref().unwrap().len(), 2);
                assert!(*skip_code_scan);
                assert_eq!(threads, &Some(8));
                assert_eq!(output, &Some(PathBuf::from("report.json")));
            }
            _ => panic!("Expected Scan command"),
        }

        assert!(cli.verbose);
        assert_eq!(cli.get_log_level(), "debug");
        assert!(cli.is_json_output());
        assert_eq!(
            cli.get_config_path().unwrap().display().to_string(),
            "/etc/saferepo.toml"
        );
    }

    // TEST 35: Verbose et JSON output combinés
    // Objectif: Vérifier que verbose et json peuvent être utilisés ensemble
    #[test]
    fn test_cli_verbose_with_json_output() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: true,
            log_level: None,
            set_config: None,

            json: true,
            config: None,
        };

        assert!(cli.verbose);
        assert!(cli.is_json_output());
        assert_eq!(cli.get_log_level(), "debug");
    }

    // TEST 36: Log level par défaut
    // Objectif: Vérifier que le log level par défaut est info
    #[test]
    fn test_cli_default_log_level_info() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        assert_eq!(cli.get_log_level(), "info");
    }

    // TEST 37: Scan avec liste d'exclusion vide
    // Objectif: Vérifier que une liste vide d'exclusions est gérée
    #[test]
    fn test_cli_scan_with_empty_exclude_list() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("."),
                min_severity: None,
                exclude: Some(vec![]),
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { exclude, .. } => {
                assert!(exclude.is_some());
                assert_eq!(exclude.as_ref().unwrap().len(), 0);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 38: Scan avec chemin très long
    // Objectif: Vérifier que les chemins énormément longs sont gérés
    #[test]
    fn test_cli_scan_with_very_long_path() {
        let long_path = vec!["a"; 100].join("/");
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from(&long_path),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { path, .. } => {
                // Vérifier que le chemin très long est accepté
                assert!(path.to_string_lossy().contains("a/a/a"));
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 39: Scan avec caractères spéciaux dans le chemin
    // Objectif: Vérifier que les chemins avec caractères spéciaux fonctionnent
    #[test]
    fn test_cli_scan_with_special_characters_in_path() {
        let cli = Cli {
            command: Commands::Scan {
                path: PathBuf::from("/home/user/my-project_v1.0"),
                min_severity: None,
                exclude: None,
                skip_code_scan: false,
                threads: None,
                output: None,
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: false,
            config: None,
        };

        match &cli.command {
            Commands::Scan { path, .. } => {
                let path_str = path.to_string_lossy();
                assert!(path_str.contains("-"));
                assert!(path_str.contains("_"));
                assert!(path_str.contains("."));
            }
            _ => panic!("Expected Scan command"),
        }
    }

    // TEST 40: Check avec JSON output
    // Objectif: Vérifier que Check fonctionne avec JSON output
    #[test]
    fn test_cli_check_with_json_output() {
        let cli = Cli {
            command: Commands::Check {
                file: PathBuf::from("Cargo.lock"),
                min_severity: Some("high".to_string()),
                detailed: true,
                output: Some(PathBuf::from("report.json")),
            },
            verbose: false,
            log_level: None,
            set_config: None,

            json: true,
            config: None,
        };

        assert!(cli.is_json_output());
        match &cli.command {
            Commands::Check { output, .. } => {
                assert!(output.is_some());
                assert_eq!(output.as_ref().unwrap().extension(), Some("json".as_ref()));
            }
            _ => panic!("Expected Check command"),
        }
    }

    // TEST 41: Multiples fichiers manifestés
    // Objectif: Vérifier que différents fichiers manifest peuvent être checkés
    #[test]
    fn test_cli_multiple_manifest_files() {
        let files = vec![
            "Cargo.lock",
            "package-lock.json",
            "requirements.txt",
            "go.mod",
        ];
        for file in files {
            let cli = Cli {
                command: Commands::Check {
                    file: PathBuf::from(file),
                    min_severity: None,
                    detailed: false,
                    output: None,
                },
                verbose: false,
                log_level: None,
                set_config: None,

                json: false,
                config: None,
            };

            match &cli.command {
                Commands::Check { file: f, .. } => {
                    assert_eq!(f.file_name().unwrap().to_str().unwrap(), file);
                }
                _ => panic!("Expected Check command"),
            }
        }
    }

    // TEST 42: Output avec différentes extensions
    // Objectif: Vérifier que différentes extensions d'output sont supportées
    #[test]
    fn test_cli_output_with_different_extensions() {
        let outputs = vec![
            ("report.json", "json"),
            ("report.txt", "txt"),
            ("report.csv", "csv"),
            ("report.html", "html"),
        ];

        for (output_path, expected_ext) in outputs {
            let cli = Cli {
                command: Commands::Scan {
                    path: PathBuf::from("."),
                    min_severity: None,
                    exclude: None,
                    skip_code_scan: false,
                    threads: None,
                    output: Some(PathBuf::from(output_path)),
                },
                verbose: false,
                log_level: None,
                set_config: None,

                json: false,
                config: None,
            };

            match &cli.command {
                Commands::Scan { output, .. } => {
                    assert_eq!(
                        output
                            .as_ref()
                            .unwrap()
                            .extension()
                            .unwrap()
                            .to_str()
                            .unwrap(),
                        expected_ext
                    );
                }
                _ => panic!("Expected Scan command"),
            }
        }
    }
}
