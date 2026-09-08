use crate::database::db::{Advisory, VulnerabilityDB};
use crate::errorhandle::errors::{SafeRepoError, SafeRepoResult};
use crate::utils::manifest_utils::{
    file_name_matches, normalize_python_version, normalize_semver, read_manifest_file,
};
use serde::Deserialize;
use std::path::Path;

// Struture temporaire pour parser le fichier Cargo.lock
// Le format Cargo.lock utilise des blocs [[package]]
#[derive(Deserialize)]
struct CargoLock {
    #[serde(rename = "package")]
    packages: Vec<PackageEntry>,
}

#[derive(Deserialize)]
struct PackageEntry {
    name: String,
    version: String,
}

#[derive(Deserialize)]
struct PackageLockEntry {
    version: String,
    #[serde(default)]
    dependencies: Option<std::collections::HashMap<String, PackageLockDep>>,
}

#[derive(Deserialize)]
struct PackageLockJson {
    #[serde(default)]
    packages: std::collections::HashMap<String, PackageLockEntry>,
    #[serde(default)]
    dependencies: std::collections::HashMap<String, PackageLockDep>,
}

#[derive(Deserialize)]
struct PackageLockDep {
    version: Option<String>,
    #[allow(dead_code)]
    resolved: Option<String>,
    #[serde(default)]
    dependencies: Option<std::collections::HashMap<String, PackageLockDep>>,
}

// Structure pour stocker une dépendance Python parsée
struct PythonRequirement {
    name: String,
    constraints: Option<String>,
}

// Structure pour stocker une dépendance Go parsée
#[derive(Debug, Clone)]
struct GoModule {
    name: String,
    version: String,
}

impl GoModule {
    // Parser une ligne de dépendance du fichier go.mod
    fn parse(line: &str) -> Option<Self> {
        let trimmed = line.trim();
        // Ignorer les lignes vides et les commentaires
        if trimmed.is_empty() || trimmed.starts_with("//") {
            return None;
        }

        // Ignorer les blocs require/replace
        if trimmed == "require (" || trimmed == "replace (" {
            return None;
        }

        // Extraire la directive require/replace
        let (is_require, rest) = if let Some(idx) = trimmed.find("require ") {
            (true, &trimmed[idx + 8..].trim())
        } else {
            let idx = trimmed.find("replace ")?;
            (false, &trimmed[idx + 8..].trim())
        };

        if !is_require && trimmed.contains("//") {
            // Ignorer les remplacements avec commentaires inline
            return None;
        }

        // Parser le format: "module_name v1.2.3" ou "module_name v1.2.3 => replacement v4.5.6"
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let name = parts[0].to_string();
        let version_str = parts[1];

        // Nettoyer la version (elle commence toujours par 'v')
        if !version_str.starts_with("v") {
            return None;
        }

        let version = version_str
            .strip_prefix("v")
            .unwrap_or(version_str)
            .to_string();

        Some(GoModule { name, version })
    }
}

impl PythonRequirement {
    // Parser une seule ligne de requirements.txt
    // Support des formats:
    // - package==1.0.0
    // - package>=1.0.0
    // - package~=1.0.0
    // - package (sans version)
    // - package[extra]==1.0.0
    // - git+https://github.com/user/repo.git#egg=package
    fn parse(line: &str) -> Option<Self> {
        let trimmed = line.trim();

        // Ignorer les lignes vides et les commentaires
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }

        // Ignorer les marqueurs d'environement (ex: ; python_version > '3.6')
        let line = if let Some(pos) = trimmed.find(';') {
            &trimmed[..pos]
        } else {
            trimmed
        };

        // Ignorer les références git/url pour le moment
        if line.starts_with("git+") || line.starts_with("http") {
            return None;
        }

        // Extraire le nom du package et la version
        // Les noms de packages peuvent avoir des extras: package[extra]==version
        let base_package = if let Some(pos) = line.find('[') {
            line[..pos].trim()
        } else {
            line
        };

        // Conserver toute la liste de contraintes pour ne pas perdre les bornes combinées.
        let operators = ["==", "~=", "!=", "<=", ">=", "<", ">"];
        for op in &operators {
            if let Some(pos) = line.find(op) {
                let name = line[..pos]
                    .split('[')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_lowercase();

                return Some(PythonRequirement {
                    name,
                    constraints: Some(line[pos..].trim().to_string()),
                });
            }
        }

        // Pas de version spécifiée
        Some(PythonRequirement {
            name: base_package.trim().to_lowercase().to_string(),
            constraints: None,
        })
    }
}

trait ManifestParser {
    fn parse(&self, content: &str, db: &VulnerabilityDB) -> SafeRepoResult<Vec<Advisory>>;
    fn supported_file_name(&self) -> &'static str;
}

fn parse_version_candidate(version_str: &str) -> Option<semver::Version> {
    let cleaned = version_str.trim();
    let candidate = if semver::Version::parse(cleaned).is_ok() {
        cleaned.to_string()
    } else {
        normalize_semver(cleaned).unwrap_or_else(|| cleaned.to_string())
    };

    semver::Version::parse(&candidate).ok()
}

fn parse_python_version(version_str: &str) -> Option<semver::Version> {
    semver::Version::parse(version_str).ok().or_else(|| {
        normalize_python_version(version_str)
            .and_then(|normalized| semver::Version::parse(&normalized).ok())
    })
}

struct CargoTomlParser;
impl ManifestParser for CargoTomlParser {
    fn parse(&self, content: &str, db: &VulnerabilityDB) -> SafeRepoResult<Vec<Advisory>> {
        let value =
            toml::from_str::<toml::Value>(content).map_err(|e| SafeRepoError::TomlError {
                context: format!("parsing {}", self.supported_file_name()),
                source: e,
            })?;

        let mut vulnerabilities = Vec::new();
        if let Some(deps) = value.get("dependencies")
            && let Some(table) = deps.as_table()
        {
            for (name, val) in table.iter() {
                let version_opt = if val.is_str() {
                    val.as_str().map(|s| s.to_string())
                } else if val.is_table() {
                    val.get("version")
                        .and_then(|v| v.as_str().map(|s| s.to_string()))
                } else {
                    None
                };

                if let Some(ver) = version_opt
                    && let Some(version) = parse_version_candidate(&ver)
                {
                    let found = db.check_vulnerability(name, &version);
                    vulnerabilities.extend(found.iter().map(|&adv| adv.clone()));
                }
            }
        }

        if let Some(dev_deps) = value.get("dev-dependencies")
            && let Some(table) = dev_deps.as_table()
        {
            for (name, val) in table.iter() {
                let version_opt = if val.is_str() {
                    val.as_str().map(|s| s.to_string())
                } else if val.is_table() {
                    val.get("version")
                        .and_then(|v| v.as_str().map(|s| s.to_string()))
                } else {
                    None
                };

                if let Some(ver) = version_opt
                    && let Some(version) = parse_version_candidate(&ver)
                {
                    let found = db.check_vulnerability(name, &version);
                    vulnerabilities.extend(found.iter().map(|&adv| adv.clone()));
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn supported_file_name(&self) -> &'static str {
        "Cargo.toml"
    }
}

struct PackageLockParser;
const MAX_NPM_DEPTH: usize = 128;
const MAX_NPM_NODES: usize = 100_000;

impl ManifestParser for PackageLockParser {
    fn parse(&self, content: &str, db: &VulnerabilityDB) -> SafeRepoResult<Vec<Advisory>> {
        let lock_data: PackageLockJson =
            serde_json::from_str(content).map_err(|e| SafeRepoError::ValidationError {
                file_path: self.supported_file_name().to_string(),
                reason: format!("Invalid JSON in {}: {}", self.supported_file_name(), e),
            })?;

        let mut vulnerabilities = Vec::new();
        for (pkg_name, pkg_entry) in &lock_data.packages {
            if pkg_name.is_empty() || pkg_name == "." {
                continue;
            }

            let clean_name = if let Some(pos) = pkg_name.rfind('/') {
                &pkg_name[pos + 1..]
            } else {
                pkg_name
            };

            if let Ok(version) = semver::Version::parse(&pkg_entry.version) {
                let found = db.check_vulnerability(clean_name, &version);
                vulnerabilities.extend(found.iter().map(|&adv| adv.clone()));
            }

            if let Some(nested_deps) = &pkg_entry.dependencies {
                vulnerabilities.extend(Self::process_npm_dependencies(
                    clean_name,
                    nested_deps,
                    db,
                )?);
            }
        }

        vulnerabilities.extend(Self::process_npm_dependencies(
            "root",
            &lock_data.dependencies,
            db,
        )?);
        Ok(vulnerabilities)
    }

    fn supported_file_name(&self) -> &'static str {
        "package-lock.json"
    }
}

impl PackageLockParser {
    fn process_npm_dependencies(
        _parent: &str,
        deps: &std::collections::HashMap<String, PackageLockDep>,
        db: &VulnerabilityDB,
    ) -> SafeRepoResult<Vec<Advisory>> {
        let mut vulnerabilities = Vec::new();
        let mut stack = vec![(deps, 0)];
        let mut processed_nodes: usize = 0;

        while let Some((current_deps, depth)) = stack.pop() {
            if depth > MAX_NPM_DEPTH {
                return Err(SafeRepoError::ValidationError {
                    file_path: "package-lock.json".to_string(),
                    reason: format!("NPM dependency nesting exceeds {} levels", MAX_NPM_DEPTH),
                });
            }

            processed_nodes = processed_nodes.saturating_add(current_deps.len());
            if processed_nodes > MAX_NPM_NODES {
                return Err(SafeRepoError::ValidationError {
                    file_path: "package-lock.json".to_string(),
                    reason: format!("NPM dependency count exceeds {} nodes", MAX_NPM_NODES),
                });
            }

            for (dep_name, dep) in current_deps {
                if let Some(version_str) = &dep.version
                    && let Ok(version) = semver::Version::parse(version_str)
                {
                    let found = db.check_vulnerability(dep_name, &version);
                    vulnerabilities.extend(found.iter().map(|&adv| adv.clone()));
                }

                if let Some(nested) = &dep.dependencies {
                    stack.push((nested, depth + 1));
                }
            }
        }
        Ok(vulnerabilities)
    }
}

struct CargoLockParser;
impl ManifestParser for CargoLockParser {
    fn parse(&self, content: &str, db: &VulnerabilityDB) -> SafeRepoResult<Vec<Advisory>> {
        let lock_data: CargoLock =
            toml::from_str(content).map_err(|e| SafeRepoError::TomlError {
                context: format!("parsing {}", self.supported_file_name()),
                source: e,
            })?;

        let mut vulnerabilities = Vec::new();
        for package in &lock_data.packages {
            if let Ok(version) = semver::Version::parse(&package.version) {
                let found = db.check_vulnerability(&package.name, &version);
                vulnerabilities.extend(found.iter().map(|&adv| adv.clone()));
            }
        }

        Ok(vulnerabilities)
    }

    fn supported_file_name(&self) -> &'static str {
        "Cargo.lock"
    }
}

struct PackageJsonParser;
impl ManifestParser for PackageJsonParser {
    fn parse(&self, content: &str, db: &VulnerabilityDB) -> SafeRepoResult<Vec<Advisory>> {
        let value: serde_json::Value =
            serde_json::from_str(content).map_err(|e| SafeRepoError::ValidationError {
                file_path: self.supported_file_name().to_string(),
                reason: format!("Invalid JSON in {}: {}", self.supported_file_name(), e),
            })?;

        let mut vulnerabilities = Vec::new();
        let mut process_deps =
            |map: &serde_json::Map<String, serde_json::Value>| -> SafeRepoResult<()> {
                for (name, val) in map.iter() {
                    let version_opt = if val.is_string() {
                        val.as_str().map(|s| s.to_string())
                    } else if val.is_object() {
                        val.get("version")
                            .and_then(|v| v.as_str().map(|s| s.to_string()))
                    } else {
                        None
                    };

                    if let Some(ver) = version_opt
                        && let Some(version) = parse_version_candidate(&ver)
                    {
                        let found = db.check_vulnerability(name, &version);
                        vulnerabilities.extend(found.iter().map(|&adv| adv.clone()));
                    }
                }
                Ok(())
            };

        if let Some(deps) = value.get("dependencies")
            && let Some(obj) = deps.as_object()
        {
            process_deps(obj)?;
        }

        if let Some(dev) = value.get("devDependencies")
            && let Some(obj) = dev.as_object()
        {
            process_deps(obj)?;
        }

        Ok(vulnerabilities)
    }

    fn supported_file_name(&self) -> &'static str {
        "package.json"
    }
}

struct RequirementsParser;
impl ManifestParser for RequirementsParser {
    fn parse(&self, content: &str, db: &VulnerabilityDB) -> SafeRepoResult<Vec<Advisory>> {
        let mut vulnerabilities = Vec::new();
        for line in content.lines() {
            if let Some(req) = PythonRequirement::parse(line)
                && let Some(constraints) = req.constraints
            {
                if let Some(version) = exact_python_constraint(&constraints) {
                    let found = db.check_vulnerability(&req.name, &version);
                    vulnerabilities.extend(found.iter().map(|&adv| adv.clone()));
                } else if python_constraint_is_supported(&constraints) {
                    eprintln!(
                        "À VÉRIFIER: la contrainte Python de {} ({}) ne permet pas de déterminer une version installée; aucune vulnérabilité certaine n'est déclarée",
                        req.name, constraints
                    );
                }
            }
        }
        Ok(vulnerabilities)
    }

    fn supported_file_name(&self) -> &'static str {
        "requirements.txt"
    }
}

fn exact_python_constraint(constraints: &str) -> Option<semver::Version> {
    let value = constraints.strip_prefix("==")?.trim();
    if value.contains('*') || value.contains(',') {
        return None;
    }
    parse_python_version(value)
}

fn python_constraint_is_supported(constraints: &str) -> bool {
    constraints.split(',').all(|constraint| {
        let trimmed = constraint.trim();
        ["~=", "!=", ">=", "<=", "==", ">", "<"]
            .iter()
            .any(|operator| {
                trimmed.strip_prefix(operator).is_some_and(|value| {
                    !value.trim().is_empty()
                        && (value.contains('*') || parse_python_version(value.trim()).is_some())
                })
            })
    })
}

struct GoModParser;
impl ManifestParser for GoModParser {
    fn parse(&self, content: &str, db: &VulnerabilityDB) -> SafeRepoResult<Vec<Advisory>> {
        let mut vulnerabilities = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("module ") || trimmed.starts_with("go ") {
                continue;
            }
            if let Some(module) = GoModule::parse(line)
                && let Ok(version) = semver::Version::parse(&module.version)
            {
                let found = db.check_vulnerability(&module.name, &version);
                vulnerabilities.extend(found.iter().map(|&adv| adv.clone()));
            }
        }
        Ok(vulnerabilities)
    }

    fn supported_file_name(&self) -> &'static str {
        "go.mod"
    }
}

// Gère la logique de sécurité et l'orchestration des analyses
pub struct SecurityManager {
    pub db: VulnerabilityDB,
}

impl SecurityManager {
    // Initialise le manager et charge la base de données locale
    pub fn new(db_path: &str) -> SafeRepoResult<Self> {
        let mut db = VulnerabilityDB::new();
        db.load_from_dir(db_path)?;
        Ok(Self { db })
    }

    /// Initialise le manager avec OSV.dev comme source (vraie BD en production)
    pub fn with_osv() -> Self {
        let db = VulnerabilityDB::new();
        // OSV sera interrogé à la demande pour chaque package analysé
        // (plutôt que de charger tout en mémoire)
        eprintln!("✅ [security] Mode OSV.dev activé - requêtes dynamiques");
        Self { db }
    }

    /// Initialise le manager hybride : OSV + cache local
    pub fn with_osv_and_local_cache(db_path: &str) -> Self {
        let mut db = VulnerabilityDB::new();
        // Charger le cache local s'il existe
        if let Err(e) = db.load_from_dir(db_path) {
            log::warn!("Cache local non disponible: {}", e);
        } else {
            eprintln!("✅ Cache local chargé depuis {}", db_path);
        }
        eprintln!("✅ Mode hibride: OSV.dev + cache local");
        Self { db }
    }

    fn parse_with_parser<P: ManifestParser>(
        &self,
        file_path: &Path,
        parser: &P,
    ) -> SafeRepoResult<Vec<Advisory>> {
        let content = read_manifest_file(file_path, parser.supported_file_name())?;
        parser.parse(&content, &self.db)
    }

    // Point d'entrée principal pour analyser un fichier détecté
    pub fn analyze_file(&self, file_path: &Path) -> SafeRepoResult<Vec<Advisory>> {
        // Vérifier l'extension
        let extension = file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .ok_or_else(|| SafeRepoError::ValidationError {
                file_path: file_path.display().to_string(),
                reason: "File has no extension".to_string(),
            })?;

        // Router vers le parser approprié avec Result
        match extension {
            "lock" => {
                if file_name_matches(file_path, "Cargo.lock") {
                    self.process_cargo_lock(file_path)
                } else if file_name_matches(file_path, "package-lock.json") {
                    self.process_package_lock(file_path)
                } else {
                    Err(SafeRepoError::ValidationError {
                        file_path: file_path.display().to_string(),
                        reason: format!("Unknown lock file: {}", file_path.display()),
                    })
                }
            }
            "json" => {
                if file_name_matches(file_path, "package-lock.json") {
                    self.process_package_lock(file_path)
                } else if file_name_matches(file_path, "package.json") {
                    self.process_package_json(file_path)
                } else {
                    Err(SafeRepoError::ValidationError {
                        file_path: file_path.display().to_string(),
                        reason: format!("Fichier JSON inconnu: {}", file_path.display()),
                    })
                }
            }
            "txt" => {
                if file_name_matches(file_path, "requirements.txt") {
                    self.process_requirements_txt(file_path)
                } else {
                    Err(SafeRepoError::ValidationError {
                        file_path: file_path.display().to_string(),
                        reason: format!("Fichier TXT inconnu: {}", file_path.display()),
                    })
                }
            }
            "mod" => {
                if file_name_matches(file_path, "go.mod") {
                    self.process_go_mod(file_path)
                } else {
                    Err(SafeRepoError::ValidationError {
                        file_path: file_path.display().to_string(),
                        reason: format!("Fichier MOD inconnu: {}", file_path.display()),
                    })
                }
            }
            "toml" => {
                if file_name_matches(file_path, "Cargo.toml") {
                    self.process_cargo_toml(file_path)
                } else {
                    Err(SafeRepoError::ValidationError {
                        file_path: file_path.display().to_string(),
                        reason: format!("Fichier TOML inconnu: {}", file_path.display()),
                    })
                }
            }
            _ => Err(SafeRepoError::ValidationError {
                file_path: file_path.display().to_string(),
                reason: format!("Type de fichier non supporté: {}", extension),
            }),
        }
    }

    /// Parser Cargo.toml - extraire les dépendances et vérifier les versions
    fn process_cargo_toml(&self, file_path: &Path) -> SafeRepoResult<Vec<Advisory>> {
        self.parse_with_parser(file_path, &CargoTomlParser)
    }

    // Parser package-lock.json - Parser les dépendances Node.js/NPM
    // Traite les formats NPM v2 (plat) et v3+ (imbriqué)
    fn process_package_lock(&self, file_path: &Path) -> SafeRepoResult<Vec<Advisory>> {
        self.parse_with_parser(file_path, &PackageLockParser)
    }

    // Valide un fichier Cargo.lock et retourne une erreur si malformé
    #[allow(dead_code)]
    fn validate_cargo_lock(file_path: &Path, content: &str) -> Result<CargoLock, String> {
        // Vérifier que le fichier n'est pas vide
        if content.trim().is_empty() {
            return Err(format!("❌ Cargo.lock vide dans {}", file_path.display()));
        }

        // Parser et valider
        match toml::from_str::<CargoLock>(content) {
            Ok(lock) => {
                // Vérifier qu'il y'a au moins des packages
                if lock.packages.is_empty() {
                    return Err(format!(
                        "⚠️ ATTENTION : {} - Aucun package détecté dans Cargo.lock",
                        file_path.display()
                    ));
                }
                Ok(lock)
            }
            Err(e) => Err(format!(
                "❌ CARGO.LOCK INVALIDE dans {} : {}",
                file_path.display(),
                e
            )),
        }
    }

    /// Parser Cargo.lock - retourner Result
    fn process_cargo_lock(&self, file_path: &Path) -> SafeRepoResult<Vec<Advisory>> {
        self.parse_with_parser(file_path, &CargoLockParser)
    }

    /// Parser package.json - retourner Result
    fn process_package_json(&self, file_path: &Path) -> SafeRepoResult<Vec<Advisory>> {
        self.parse_with_parser(file_path, &PackageJsonParser)
    }

    /// Parser requirements.txt - Parser les dépendances Python/PIP
    /// Support de multiples formats et contraintes
    fn process_requirements_txt(&self, file_path: &Path) -> SafeRepoResult<Vec<Advisory>> {
        self.parse_with_parser(file_path, &RequirementsParser)
    }

    /// Parser go.mod - Parser les dépendances Go modules
    /// Traite les directives require et replace
    fn process_go_mod(&self, file_path: &Path) -> SafeRepoResult<Vec<Advisory>> {
        self.parse_with_parser(file_path, &GoModParser)
    }

    // Affiche une alerte formatée pour le développeur
    #[allow(dead_code)]
    fn report_vulnerability(&self, name: &str, ver: &str, adv: &Advisory) {
        println!(
            "\n[!] VULNÉRABILITÉ DÉTECTÉE\n\
            Package  : {} (v{})\n\
            ID       : {}\n\
            Sévérité : {:?}\n\
            Titre    : {}\n\
            Détails  : {}",
            name, ver, adv.id, adv.severity, adv.title, adv.description
        );
    }
}
