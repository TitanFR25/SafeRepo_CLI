use clap::{Parser, Subcommand};
use log::{debug, info};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::command::config::SafeRepoConfig;
use crate::database::db::{Advisory, Severity};
use crate::scaning::scan::{self, ScanOptions};
use crate::secure::security::SecurityManager;
use indicatif::{ProgressBar, ProgressStyle};

/// SafeRepo - Scanner de vulnérabilités multi-langage
///
/// Outil CLI puissant pour scanner les vulnérabilités de dépendances
/// Compatible avec tous les langages majeurs.
#[derive(Parser, Debug)]
#[command(
    name = "SafeRepo",
    version = "0.6.5",
    about = "Scanner de vulnérabilités pour dépendances multi-langage",
    long_about = "SafeRepo est un outil CLI pour scanner les vulnérabilités de vos dépendances dans les projets Rust, Node.js, Python, Go, etc.\n\nUsage: saferepo <COMMAND> [OPTIONS]\n\nExamples:\n  saferepo scan .                 # Scanner le répertoire courant\n  saferepo scan /path/to/project  # Scanner un projet spécifique\n  saferepo check Cargo.lock       # Vérifier un seul manifest\n  saferepo update                 # Mettre à jour la base de données\n  saferepo --version              # Afficher la version",
    author = "SafeRepo Team"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    // Activer le mode verbeux (debug logs)
    #[arg(global = true, short, long)]
    pub verbose: bool,

    // Niveau de log (trace, debug, info, warn, error)
    #[arg(global = true, long, value_name = "LEVEL")]
    pub log_level: Option<String>,

    // Chemin personnalisé vers le fichier de configuration
    #[arg(global = true, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Paramètre d'ajustement de la configuration (peut être utilisé plusieurs fois)
    #[arg(global = true, long, value_name = "KEY=VALUE")]
    pub set_config: Option<Vec<String>>,

    // Format de sortie JSON (pour intégration CI/CD)
    #[arg(global = true, long)]
    pub json: bool,
}

#[derive(Debug, Clone)]
struct RemoteManifestEntry {
    path: String,
    hash: String,
    size: u64,
}
#[derive(Subcommand, Debug)]
pub enum Commands {
    // Scanner un projet pour détecter les vulnérabilités
    //
    // Analyse récursivement le répertoire spécifié et détecte
    // toutes les vulnérabilités connues dans les dépendances.
    #[command(about = "Scanner un projet pour vulnérabilités")]
    Scan {
        // Chemin du projet à scanner (default: répertoire courant)
        #[arg(value_name = "PATH", default_value = ".")]
        path: PathBuf,

        // Sévérité minimale (critical, high, medium, low)
        #[arg(short, long, value_name = "SEVERITY")]
        min_severity: Option<String>,

        // Ignorer certains patterns (chemins à ignorer)
        #[arg(short, long, value_name = "PATTERNS")]
        exclude: Option<Vec<String>>,

        // Ne scanner que les dépendances (ignorer le code source)
        #[arg(long)]
        skip_code_scan: bool,
        // Nombre maximum de threads (default: nombre de CPU)
        #[arg(long, value_name = "N")]
        threads: Option<usize>,

        // Sauvegarder le rapport dans un fichier
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },

    // Vérifier un seul fichier manifeste
    //
    // Analyse un fichier manifeste spécifique (Cargo.lock, package.json, etc.)
    // et retourne les vulnérabilités trouvées pour ce fichier.
    #[command(about = "Vérifier un fichier manifeste")]
    Check {
        // Fichier manifeste à vérifier
        #[arg(value_name = "FILE")]
        file: PathBuf,

        // Sévérité minimale (critical, high, medium, low)
        #[arg(short, long, value_name = "SEVERITY")]
        min_severity: Option<String>,

        // Afficher les détails complets de chaque vulnérabilité
        #[arg(short, long)]
        detailed: bool,

        // Sauvegarder le rapport dans un fichier
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },

    // Mettre à jour la base de données des vulnérabilités
    //
    // Télécharge et vérifie la dernière version de la base de données
    // depuis les sources officielles (OSV.dev, GitHub Advisory Database).
    #[command(about = "Mettre à jour la base de données")]
    Update {
        // Forcer la mise à jour même si à jour
        #[arg(short, long)]
        force: bool,

        // Source de mise à jour (osv, github, snyk)
        #[arg(short, long, value_name = "SOURCE")]
        source: Option<String>,

        // Afficher les progrès détaillés
        #[arg(long)]
        verbose_update: bool,

        // Vérifier la signature GPG du fichier téléchargé
        #[arg(long)]
        verify_signature: bool,
    },

    // Afficher la configuration active
    //
    // Affiche la configuration utilisée par SafeRepo, incluant
    // les patterns ignorés, les seuils de sévérité, etc.
    #[command(about = "Afficher la configuration")]
    Config {
        // Afficher le chemin du fichier de configuration
        #[arg(long)]
        show_path: bool,

        // Réinitialiser la configuration par défaut
        #[arg(long)]
        reset: bool,
    },

    // Afficher les statistiques de sécurité
    //
    // Affiche un résumé des vulnerabilités trouvées, statistiques,
    // et tendances temporelles.
    #[command(about = "Afficher les statistiques")]
    Stats {
        // Limiter à N jours de données (default: 30)
        #[arg(short, long, value_name = "DAYS", default_value = "30")]
        days: u32,

        // Afficher les vulnérabilités par langage
        #[arg(long)]
        by_language: bool,

        // Afficher les vulnérabilités par sévérité
        #[arg(long)]
        by_severity: bool,
    },
}

impl Cli {
    // Parse les arguments de la ligne de commande
    pub fn parse_args() -> Self {
        Parser::parse()
    }

    // Obtient le niveau de log configuré
    pub fn get_log_level(&self) -> String {
        match &self.log_level {
            Some(level) => level.clone(),
            None => {
                if self.verbose {
                    "debug".to_string()
                } else {
                    "info".to_string()
                }
            }
        }
    }

    // Vérifie si JSON output est activé
    pub fn is_json_output(&self) -> bool {
        self.json
    }

    // Obtient le chemin de configuration custom
    pub fn get_config_path(&self) -> Option<&PathBuf> {
        self.config.as_ref()
    }

    pub fn validate_scan_path(
        &self,
        path: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resolved = path.canonicalize()?;

        if !resolved.exists() {
            return Err(format!("Le chemin '{}' n'existe pas", path.display()).into());
        }

        if !resolved.is_dir() {
            return Err(format!("Le chemin '{}' n'est pas un répertoire", path.display()).into());
        }

        Ok(())
    }

    pub fn validate_check_path(
        &self,
        path: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resolved = path.canonicalize()?;

        if !resolved.exists() {
            return Err(format!("Le fichier '{}' n'existe pas", path.display()).into());
        }

        if !resolved.is_file() {
            return Err(
                format!("Le chemin '{}' n'est pas un fichier valide", path.display()).into(),
            );
        }

        Ok(())
    }

    // Execute la commande appropriée
    pub fn execute(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Configurer le logging
        self.setup_logging();

        // Charger la configuration
        let config = SafeRepoConfig::load_or_default(self.config.as_deref())?;
        config.validate()?;

        debug!("SafeRepo v0.6.5 démarré");
        debug!("Configuration chargée depuis: {:?}", self.config);
        debug!("Sévérité minimale: {}", config.min_severity);

        if self.json {
            info!("Format JSON activé");
        }

        match &self.command {
            Commands::Scan {
                path,
                min_severity,
                exclude,
                skip_code_scan: _,
                threads,
                output,
            } => {
                self.validate_scan_path(path)?;
                let mut exclude_paths = config.exclude_paths.clone();
                if let Some(patterns) = exclude {
                    exclude_paths.extend(patterns.iter().cloned());
                }
                let scan_options = ScanOptions {
                    max_depth: config.max_depth,
                    max_file_size: config.max_file_size,
                    manifest_files: config.manifest_files.iter().cloned().collect(),
                    ignored_dirs: config.ignore_patterns.iter().cloned().collect(),
                    exclude_paths,
                    database_path: fs::canonicalize(&config.db_path).ok(),
                    threads: threads.or(config.threads),
                };
                self.handle_scan(
                    path,
                    min_severity.as_deref(),
                    output.as_ref(),
                    &config.db_path,
                    &scan_options,
                )?;
            }

            Commands::Check {
                file,
                min_severity,
                detailed,
                output,
            } => {
                self.validate_check_path(file)?;
                self.handle_check(
                    file,
                    min_severity.as_deref(),
                    *detailed,
                    output.as_ref(),
                    &config.db_path,
                )?;
            }

            Commands::Update {
                force,
                source,
                verbose_update,
                verify_signature: _,
            } => {
                self.handle_update(
                    *force,
                    source.as_deref(),
                    *verbose_update,
                    &config.db_path,
                    config.update_url.as_deref(),
                )?;
            }

            Commands::Config { show_path, reset } => {
                self.handle_config(*show_path, *reset)?;
            }

            Commands::Stats {
                days,
                by_language,
                by_severity,
            } => {
                self.handle_stats(*days, *by_language, *by_severity)?;
            }
        }

        Ok(())
    }

    // Configure le système de logging
    fn setup_logging(&self) {
        use log::LevelFilter;

        let log_str = self.log_level.as_deref().unwrap_or("info");
        let level = match log_str {
            "trace" => LevelFilter::Trace,
            "debug" => LevelFilter::Debug,
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            "error" => LevelFilter::Error,
            _ => LevelFilter::Info,
        };

        env_logger::Builder::from_default_env()
            .filter_level(level)
            .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
            .try_init()
            .unwrap_or_else(|_| {
                eprintln!("⚠️  Logging déjà initialisé");
            });

        debug!("Logging configuré avec le niveau: {}", log_str);
    }

    // Gére la commande scan
    fn handle_scan(
        &self,
        path: &PathBuf,
        min_severity: Option<&str>,
        output: Option<&PathBuf>,
        db_path: &str,
        scan_options: &ScanOptions,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Démarrage du scan du répertoire: {:?}", path);
        debug!(
            "Sévérité minimale: {:?}, Sortie: {:?}",
            min_severity, output
        );

        let database_progress = ProgressBar::new_spinner();
        database_progress.set_style(
            ProgressStyle::with_template("{msg} {spinner}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        database_progress.set_message("Chargement de la base de données");
        database_progress.enable_steady_tick(std::time::Duration::from_millis(100));

        let security_manager = match SecurityManager::new(db_path) {
            Ok(manager) => manager,
            Err(error) => {
                database_progress.finish_and_clear();
                return Err(error.into());
            }
        };
        database_progress.finish_and_clear();
        let detected_vulnerabilities = scan::scan_repo(path, &security_manager, scan_options)?;

        debug!(
            "Scan terminé: {} vulnérabilités détectées",
            detected_vulnerabilities.len()
        );

        // Filtrer par sévérité si spécifié
        let filtered: Vec<_> = if let Some(sev) = min_severity {
            detected_vulnerabilities
                .into_iter()
                .filter(|v| self.matches_severity_filter(v, sev))
                .collect()
        } else {
            detected_vulnerabilities
        };

        // OUTPUT JSON
        if self.json {
            let json_output = json!({
                "status": "success",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "path": path.to_string_lossy(),
                "total_vulnerabilities": filtered.len(),
                "vulnerabilities": filtered.iter().map(|v| {
                    json!({
                        "id": &v.id,
                        "package": &v.package,
                        "severity": format!("{:?}", v.severity),
                        "title": &v.title,
                        "description": &v.description,
                        "patched_versions": &v.versions.patched,
                    })
                }).collect::<Vec<_>>(),
            });

            println!("{}", serde_json::to_string_pretty(&json_output)?);

            if let Some(out_path) = output {
                debug!("Sauvegarde rapport JSON: {:?}", out_path);
                std::fs::write(out_path, serde_json::to_string_pretty(&json_output)?)?;
                info!("Rapport sauvegardé: {:?}", out_path);
            }
        } else {
            // OUTPUT TEXTE NORMAL
            println!("\n📊 Rapport de Scan");
            println!("==================");
            println!("Chemin: {}", path.display());
            println!("Vulnérabilités détectées: {}\n", filtered.len());

            for vuln in &filtered {
                println!("🚨 {} - {}", vuln.package, vuln.title);
                println!("   ID: {}", vuln.id);
                println!("   Sévérité: {:?}", vuln.severity);
                println!("   Versions corrigées: {:?}", vuln.versions.patched);
                println!("   Description: {}\n", vuln.description);
            }

            if let Some(out_path) = output {
                debug!("Sauvegarde rapport texte: {:?}", out_path);
                let report = format!(
                    "RAPPORT DE SCAN\n================\nChemin: {}\n\n{}\n",
                    path.display(),
                    filtered
                        .iter()
                        .map(|v| format!(
                            "🚨 {} - {}\n   ID: {}\n   Sévérité: {:?}\n   Versions corrigées: {:?}",
                            v.package, v.title, v.id, v.severity, v.versions.patched
                        ))
                        .collect::<Vec<_>>()
                        .join("\n\n")
                );

                std::fs::write(out_path, report)?;
                info!("Rapport texte sauvegardé: {:?}", out_path);
            }
        }

        Ok(())
    }

    fn matches_severity_filter(&self, vuln: &Advisory, severity: &str) -> bool {
        match (severity.to_lowercase().as_str(), &vuln.severity) {
            ("critical", Severity::Critical) => true,
            ("critical", Severity::High) => false,
            ("high", Severity::High | Severity::Critical) => true,
            ("medium", Severity::Medium | Severity::High | Severity::Critical) => true,
            ("low", _) => true,
            _ => false,
        }
    }

    // Gére la commande check
    fn handle_check(
        &self,
        file: &PathBuf,
        min_severity: Option<&str>,
        detailed: bool,
        output: Option<&PathBuf>,
        db_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("Vérification du fichier: {:?}", file);
        debug!("Détaillé: {}, Sévérité min: {:?}", detailed, min_severity);

        let security_manager = SecurityManager::new(db_path)?;
        let vulns = security_manager.analyze_file(file)?;

        info!("Analyse terminée: {} vulnérabilités trouvées", vulns.len());

        let filtered: Vec<_> = if let Some(sev) = min_severity {
            vulns
                .into_iter()
                .filter(|v| self.matches_severity_filter(v, sev))
                .collect()
        } else {
            vulns
        };

        // OUTPUT JSON
        if self.json {
            let json_output = json!({
                "status": "success",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "file": file.to_string_lossy(),
                "total_vulnerabilities": filtered.len(),
                "vulnerabilities": filtered.iter().map(|v| {
                    let mut item = json!({
                        "id": &v.id,
                        "package": &v.package,
                        "severity": format!("{:?}", v.severity),
                        "title": &v.title,
                        "patched_versions": &v.versions.patched,
                    });
                    if detailed {
                        item.as_object_mut().unwrap().insert(
                            "description".to_string(),
                            json!(&v.description),
                        );
                    }
                    item
                }).collect::<Vec<_>>(),
            });

            println!("{}", serde_json::to_string_pretty(&json_output)?);

            if let Some(out_path) = output {
                debug!("Sauvegarde rapport JSON check: {:?}", out_path);
                std::fs::write(out_path, serde_json::to_string_pretty(&json_output)?)?;
                info!("Rapport check sauvegardé: {:?}", out_path);
            }
        } else {
            // OUTPUT TEXTE NORMAL
            println!("\n📋 Vérification du Fichier");
            println!("==========================");
            println!("Fichier: {}", file.display());
            println!("Vulnérabilités trouvées: {}\n", filtered.len());

            for vuln in &filtered {
                println!("🚨 {} - {}", vuln.package, vuln.title);
                println!("   Sévérité: {:?}", vuln.severity);
                println!("   Versions corrigées: {:?}", vuln.versions.patched);
                if detailed {
                    println!("   Description: {}", vuln.description);
                }
                println!();
            }

            if let Some(out_path) = output {
                std::fs::write(
                    out_path,
                    format!(
                        "Fichier: {}\n\n{}",
                        file.display(),
                        filtered
                            .iter()
                            .map(|v| format!(
                                "🚨 {} - {}\n   Sévérité: {:?}\n   Versions corrigées: {:?}",
                                v.package, v.title, v.severity, v.versions.patched
                            ))
                            .collect::<Vec<_>>()
                            .join("\n\n")
                    ),
                )?;
                info!("Rapport texte check sauvegardé: {:?}", out_path);
            }
        }

        Ok(())
    }

    // Gére la commande update
    fn handle_update(
        &self,
        force: bool,
        source: Option<&str>,
        verbose: bool,
        db_path: &str,
        update_url: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n🔄 Mise à jour de la base de données...");

        if force {
            println!("⚠️  Mise à jour forcée activée");
        }

        if verbose {
            println!("📊 Mode verbeux activé");
        }

        let source_name = source.unwrap_or("osv");
        println!("📥 Source utilisé : {}", source_name);

        // Sélectionner la source d'update
        match source_name {
            "osv" => {
                println!("🔗 Téléchargement depuis OSV.dev...");
                self.download_from_osv(force, verbose, db_path, update_url)?;
            }
            "github" => {
                println!("🔗 Téléchargement depuis GitHub Advisory Database...");
                self.download_from_github(force, verbose, db_path, update_url)?;
            }
            "snyk" => {
                println!("🔗 Téléchargement depuis Snyk Database...");
                println!("⚠️  Snyk nécessite une authentification (API key)");
                println!("✅ Fonctionnalité prévue pour v0.7.0");
            }
            _ => {
                eprintln!("❌ Source inconnue : {}", source_name);
                println!("Sources disponibles : osv, github, snyk");
                return Err(format!("Source inconnue: {}", source_name).into());
            }
        }

        println!("\n✅ Base de données mise à jour avec succès !");
        println!(
            "📅 Version : v0.6.5 (updated at {})",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        );

        Ok(())
    }

    // Télécharge les vulnérabilités depuis OSV.dev
    fn download_from_osv(
        &self,
        force: bool,
        verbose: bool,
        db_path: &str,
        update_url: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(Self::download_from_osv_async(
            force, verbose, db_path, update_url,
        ))
    }

    pub async fn download_from_osv_async(
        force: bool,
        verbose: bool,
        db_path: &str,
        update_url: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Self::download_signed_bundle_async("OSV", force, verbose, db_path, update_url).await
    }

    async fn download_signed_bundle_async(
        _source: &str,
        _force: bool,
        verbose: bool,
        db_path: &str,
        update_url: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        const MANIFEST_NAME: &str = ".integrity_manifest";
        const SIGNATURE_NAME: &str = ".integrity_manifest.sig";
        const MAX_BUNDLE_FILE_SIZE: u64 = 2 * 1024 * 1024;

        let base_url = update_url.ok_or(
            "Aucune URL de bundle OSV signée configurée; définissez update_url dans la configuration",
        )?;
        let base_url = base_url.trim_end_matches('/');
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(15))
            .build()?;

        let manifest = Self::download_bundle_file(&client, base_url, MANIFEST_NAME).await?;
        let signature = Self::download_bundle_file(&client, base_url, SIGNATURE_NAME).await?;
        let manifest_text = std::str::from_utf8(&manifest)?;
        let remote_entries = Self::parse_remote_manifest_entries(manifest_text)?;
        if remote_entries.is_empty() {
            return Err("Le manifeste distant ne référence aucun fichier TOML".into());
        }

        let local_entries = if Path::new(db_path).exists() {
            Self::read_local_manifest_entries(Path::new(db_path)).unwrap_or_default()
        } else {
            HashMap::new()
        };

        let destination = Path::new(db_path);
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(
            ".{}.update-{}",
            destination
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("vulnera_db"),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir(&temporary)?;

        let result = (async {
            fs::write(temporary.join(MANIFEST_NAME), &manifest)?;
            fs::write(temporary.join(SIGNATURE_NAME), &signature)?;

            for entry in &remote_entries {
                let target = temporary.join(&entry.path);
                let unchanged = local_entries
                    .get(&entry.path)
                    .is_some_and(|local| local.hash == entry.hash && local.size == entry.size)
                    && destination.join(&entry.path).is_file();

                if unchanged {
                    if let Err(error) = fs::hard_link(destination.join(&entry.path), &target) {
                        if verbose {
                            eprintln!(
                                "Lien dur indisponible pour {}, copie de secours: {}",
                                entry.path, error
                            );
                        }
                        fs::copy(destination.join(&entry.path), &target)?;
                    }
                } else {
                    let content =
                        Self::download_bundle_file(&client, base_url, &entry.path).await?;
                    if content.len() as u64 > MAX_BUNDLE_FILE_SIZE {
                        return Err(
                            format!("advisory file exceeds {MAX_BUNDLE_FILE_SIZE} bytes").into(),
                        );
                    }
                    let hash =
                        crate::database::db::VulnerabilityDB::hash_bytes_for_update(&content);
                    if !entry.hash.is_empty()
                        && (hash != entry.hash || content.len() as u64 != entry.size)
                    {
                        return Err(format!("contenu incohérent pour {}", entry.path).into());
                    }
                    fs::write(&target, content)?;
                }
            }

            let mut candidate = crate::database::db::VulnerabilityDB::new();
            candidate.load_from_dir(&temporary)?;
            if verbose {
                eprintln!("Bundle OSV signé validé dans {}", temporary.display());
            }
            Self::replace_database_atomically(&temporary, destination)?;
            Ok(())
        })
        .await;

        if result.is_err() {
            let _ = fs::remove_dir_all(&temporary);
        }
        result
    }

    async fn download_bundle_file(
        client: &reqwest::Client,
        base_url: &str,
        name: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
        let response = client.get(format!("{base_url}/{name}")).send().await?;
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES)
        {
            return Err(format!("bundle response exceeds {MAX_RESPONSE_BYTES} bytes").into());
        }
        let payload = response.bytes().await?;
        if payload.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(format!("bundle response exceeds {MAX_RESPONSE_BYTES} bytes").into());
        }
        if !status.is_success() {
            return Err(format!("bundle request failed with HTTP {status}").into());
        }
        Ok(payload.to_vec())
    }

    pub fn parse_remote_manifest_paths(
        manifest: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut paths = Vec::new();
        for line in manifest.lines().map(str::trim) {
            if line.is_empty()
                || line.starts_with('#')
                || line.starts_with("SHA256: ")
                || line.starts_with("Size: ")
            {
                continue;
            }
            let path = Path::new(line);
            if path.is_absolute()
                || path.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::ParentDir | std::path::Component::RootDir
                    )
                })
                || path.extension().and_then(|extension| extension.to_str()) != Some("toml")
                || path.file_name().and_then(|name| name.to_str()) != Some(line)
            {
                return Err(format!("chemin de bundle invalide: {line}").into());
            }
            if paths.iter().any(|existing| existing == line) {
                return Err(format!("fichier dupliqué dans le manifeste: {line}").into());
            }
            paths.push(line.to_string());
        }
        Ok(paths)
    }

    fn parse_remote_manifest_entries(
        manifest: &str,
    ) -> Result<Vec<RemoteManifestEntry>, Box<dyn std::error::Error>> {
        let mut entries = Vec::new();
        let mut path: Option<String> = None;
        let mut hash: Option<String> = None;

        for line in manifest.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(value) = line.strip_prefix("SHA256: ") {
                if path.is_none() || hash.is_some() {
                    return Err("entrée SHA256 invalide dans le manifeste".into());
                }
                hash = Some(value.to_string());
                continue;
            }
            if let Some(value) = line.strip_prefix("Size: ") {
                let size = value
                    .strip_suffix(" bytes")
                    .ok_or("taille invalide dans le manifeste")?
                    .parse::<u64>()?;
                let file_path = path.take().ok_or("taille sans chemin dans le manifeste")?;
                let file_hash = hash.take().ok_or("taille sans hash dans le manifeste")?;
                Self::validate_remote_toml_path(&file_path)?;
                entries.push(RemoteManifestEntry {
                    path: file_path,
                    hash: file_hash,
                    size,
                });
                continue;
            }
            if let Some(previous_path) = path.replace(line.to_string()) {
                if hash.is_some() {
                    return Err("chemin suivant avant la fin de l'entrée précédente".into());
                }
                Self::validate_remote_toml_path(&previous_path)?;
                entries.push(RemoteManifestEntry {
                    path: previous_path,
                    hash: String::new(),
                    size: 0,
                });
            }
        }

        if let Some(last_path) = path {
            if hash.is_some() {
                return Err("hash sans taille dans le manifeste distant".into());
            }
            Self::validate_remote_toml_path(&last_path)?;
            entries.push(RemoteManifestEntry {
                path: last_path,
                hash: String::new(),
                size: 0,
            });
        } else if hash.is_some() {
            return Err("entrée incomplète dans le manifeste distant".into());
        }
        if entries
            .iter()
            .map(|entry| &entry.path)
            .collect::<std::collections::HashSet<_>>()
            .len()
            != entries.len()
        {
            return Err("fichier dupliqué dans le manifeste distant".into());
        }
        Ok(entries)
    }

    fn read_local_manifest_entries(
        db_path: &Path,
    ) -> Result<HashMap<String, RemoteManifestEntry>, Box<dyn std::error::Error>> {
        let manifest = fs::read_to_string(db_path.join(".integrity_manifest"))?;
        Ok(Self::parse_remote_manifest_entries(&manifest)?
            .into_iter()
            .map(|entry| (entry.path.clone(), entry))
            .collect())
    }

    fn validate_remote_toml_path(path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let path_ref = Path::new(path);
        if path_ref.is_absolute()
            || path_ref.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::RootDir
                )
            })
            || path_ref
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("toml")
            || path_ref.file_name().and_then(|name| name.to_str()) != Some(path)
        {
            return Err(format!("chemin de bundle invalide: {path}").into());
        }
        Ok(())
    }

    pub fn replace_database_atomically(
        temporary: &Path,
        destination: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let backup = destination.with_extension(format!(
            "backup-{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        let had_destination = destination.exists();
        if had_destination {
            fs::rename(destination, &backup)?;
        }

        if let Err(error) = fs::rename(temporary, destination) {
            if had_destination {
                let _ = fs::rename(&backup, destination);
            }
            return Err(Box::new(std::io::Error::other(format!(
                "atomic database replacement failed: {error}"
            ))));
        }

        if had_destination {
            fs::remove_dir_all(backup)?;
        }
        Ok(())
    }

    // Télécharge les vulnérabilités depuis GitHub Advisory Database
    fn download_from_github(
        &self,
        force: bool,
        verbose: bool,
        db_path: &str,
        update_url: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let update_url = update_url.ok_or(
            "Aucune URL de bundle GitHub signée configurée; définissez update_url dans la configuration",
        )?;
        Self::validate_github_bundle_url(update_url)?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(Self::download_signed_bundle_async(
            "GitHub",
            force,
            verbose,
            db_path,
            Some(update_url),
        ))
    }

    pub fn validate_github_bundle_url(update_url: &str) -> Result<(), Box<dyn std::error::Error>> {
        let url = reqwest::Url::parse(update_url)
            .map_err(|error| format!("URL GitHub invalide: {error}"))?;
        let host = url.host_str().unwrap_or_default();
        if !(host == "github.com"
            || host.ends_with(".github.com")
            || host == "githubusercontent.com"
            || host.ends_with(".githubusercontent.com")
            || host == "github.io"
            || host.ends_with(".github.io"))
        {
            return Err(
                "l'URL GitHub doit pointer vers github.com, githubusercontent.com ou github.io"
                    .into(),
            );
        }
        Ok(())
    }

    // Gére la commande config
    fn handle_config(
        &self,
        show_path: bool,
        reset: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("Gestion de la configuration");

        if show_path {
            let config = SafeRepoConfig::load_or_default(self.config.as_deref())?;

            if self.json {
                let json_config = json!({
                    "min_severity": &config.min_severity,
                    "max_depth": config.max_depth,
                    "max_file_size": config.max_file_size,
                    "output_format": &config.output_format,
                    "verify_signatures": config.verify_signatures,
                    "db_path": &config.db_path,
                    "update_url": &config.update_url,
                    "ignore_patterns": &config.ignore_patterns,
                    "manifest_files": &config.manifest_files,
                    "exclude_paths": &config.exclude_paths,
                });
                println!("{}", serde_json::to_string_pretty(&json_config)?);
                return Ok(());
            }

            println!("\n📋 Chemins de Configuration");
            println!("==========================\n");

            // Afficher les chemins standard
            let standard_paths = [
                PathBuf::from(".saferepo.toml"),
                PathBuf::from(".config/saferepo.toml"),
                SafeRepoConfig::get_config_dir()?.join("saferepo.toml"),
            ];

            println!("Emplacements de recherche:");
            for (i, path) in standard_paths.iter().enumerate() {
                let status = if path.exists() {
                    "✓ EXISTS"
                } else {
                    "✗ not found"
                };
                println!("  {}. {} [{}]", i + 1, path.display(), status);
            }

            println!("\n📊 Configuration Actuelle");
            println!("========================\n");
            println!("Sévérité minimale: {}", config.min_severity);
            println!("Max depth: {}", config.max_depth);
            println!(
                "Max file size: {} bytes ({} MB)",
                config.max_file_size,
                config.max_file_size / (1024 * 1024)
            );
            println!("Format de sortie: {}", config.output_format);
            println!("Vérifier signatures: {}", config.verify_signatures);
            println!("Base de données: {}", config.db_path);
            println!("URL bundle update: {:?}", config.update_url);

            println!("\n📁 Patterns Ignorés:");
            for pattern in &config.ignore_patterns {
                println!("   - {}", pattern);
            }

            println!("\n📄 Fichiers Manifeste:");
            for manifest in &config.manifest_files {
                println!("   - {}", manifest);
            }

            if !config.exclude_paths.is_empty() {
                println!("\n🚫 Chemins Exclus:");
                for path in &config.exclude_paths {
                    println!("   - {}", path);
                }
            }

            return Ok(());
        }

        if reset {
            debug!("Réinitialisation de la configuration");
            let config = SafeRepoConfig::default();

            // Sauvegarder dans le répertoire config standard
            let config_path = SafeRepoConfig::get_config_dir()?.join("saferepo.toml");
            config.save(&config_path)?;

            println!("✅ Configuration réinitialisée");
            println!("   Sauvegardée dans: {}", config_path.display());
            info!("Configuration réinitialisée avec succès");
            return Ok(());
        }

        // Si aucune option, afficher le chemin du fichier par défaut
        println!("✅ Fichier de configuration par défaut générré:");
        let path = SafeRepoConfig::generate_default()?;
        println!("   {}", path.display());
        println!("\n📝 Vous pouvez éditer ce fichier pour personnaliser SafeRepo");

        Ok(())
    }

    /// Gère la commande stats - Affiche les statistiques de sécurité
    fn handle_stats(
        &self,
        days: u32,
        by_language: bool,
        by_severity: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("Récupération des statistiques (derniers {} jours)", days);
        debug!(
            "Par langage: {}, Par sévérité: {}",
            by_language, by_severity
        );

        let mut db = crate::database::db::VulnerabilityDB::new();
        db.load_from_dir("vulnera_db")?;

        // Compter les stats par sévérité
        let mut stats_by_severity: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        for advisories in db.advisories.values() {
            for adv in advisories {
                let sev_str = format!("{:?}", adv.severity).to_lowercase();
                *stats_by_severity.entry(sev_str).or_insert(0) += 1;
            }
        }

        let total_entries: u32 = stats_by_severity.values().sum();
        info!("Statistiques: {} entrées totales", total_entries);

        if self.json {
            let mut json_stats = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "period_days": days,
                "total_entries": total_entries,
                "by_severity": {
                    "critical": stats_by_severity.get("critical").copied().unwrap_or(0),
                    "high": stats_by_severity.get("high").copied().unwrap_or(0),
                    "medium": stats_by_severity.get("medium").copied().unwrap_or(0),
                    "low": stats_by_severity.get("low").copied().unwrap_or(0),
                }
            });

            if by_language {
                // Compter par langage basé sur les patterns de package
                let mut lang_count: std::collections::HashMap<String, u32> =
                    std::collections::HashMap::new();
                for pkg_name in db.advisories.keys() {
                    let lang = if pkg_name.contains("@") {
                        "Node.js"
                    } else if pkg_name.to_lowercase().contains("py") {
                        "Python"
                    } else if pkg_name.to_lowercase().contains("go") {
                        "Go"
                    } else {
                        "Other"
                    };
                    *lang_count.entry(lang.to_string()).or_insert(0) += 1;
                }
                json_stats
                    .as_object_mut()
                    .unwrap()
                    .insert("by_language".to_string(), json!(lang_count));
            }

            println!("{}", serde_json::to_string_pretty(&json_stats)?);
        } else {
            println!("\n📊 Statistiques SafeRepo");
            println!("======================");
            println!("Période: {} jours", days);
            println!("Total d'entrées: {}\n", total_entries);

            println!("Par Sévérité:");
            println!(
                "  🔴 CRITICAL: {}",
                stats_by_severity.get("critical").copied().unwrap_or(0)
            );
            println!(
                "  🟠 HIGH:     {}",
                stats_by_severity.get("high").copied().unwrap_or(0)
            );
            println!(
                "  🟡 MEDIUM:   {}",
                stats_by_severity.get("medium").copied().unwrap_or(0)
            );
            println!(
                "  🟢 LOW:      {}",
                stats_by_severity.get("low").copied().unwrap_or(0)
            );

            if by_language {
                println!("\nPar Langage:");
                for pkg_name in db.advisories.keys() {
                    let lang = if pkg_name.contains("@") {
                        "Node.js"
                    } else if pkg_name.to_lowercase().contains("py") {
                        "Python"
                    } else if pkg_name.to_lowercase().contains("go") {
                        "Go"
                    } else {
                        "Other"
                    };
                    println!("  {} packages", lang);
                }
            }
        }

        Ok(())
    }
}
