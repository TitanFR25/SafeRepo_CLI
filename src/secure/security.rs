use crate::database::db::{Advisory, VulnerabilityDB};
use crate::errorhandle::errors::{SafeRepoError, SafeRepoResult};
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
    resolved: Option<String>,
    #[serde(default)]
    dependencies: Option<std::collections::HashMap<String, PackageLockDep>>,
}

// Structure pour stocker une dépendance Python parsée
struct PythonRequirement {
    name: String,
    version: Option<String>,
    operator: Option<String>,
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
        } else if let Some(idx) = trimmed.find("replace ") {
            (false, &trimmed[idx + 8..].trim())
        } else {
            return None;
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

        let version = version_str.strip_prefix("v").unwrap_or(version_str).to_string();

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

        // Vérifier les opérateur de version
        let operators = ["==", "~=", "!=", "<=", ">=", "<", ">"];
        for op in &operators {
            if let Some(pos) = line.find(op) {
                let name = base_package.trim().to_lowercase();
                let version = line[pos + op.len()..].trim().to_string();

                // Parser la version sémantique - peut avoir plusieurs contraintes
                // Pour la simplicité, prendre la première contrainte
                let version_part = version.split(',').next().unwrap_or(&version).trim();

                return Some(PythonRequirement {
                    name,
                    version: Some(version_part.to_string()),
                    operator: Some(op.to_string()),
                });
            }
        }

        // Pas de version spécifiée
        Some(PythonRequirement {
            name: base_package.trim().to_lowercase().to_string(),
            version: None,
            operator: None,
        })
    }
}

// Gère la logique de sécurité et l'orchestration des analyses
pub struct SecurityManager {
    pub db: VulnerabilityDB,
}

impl SecurityManager {
    // Initialise le manager et charge la base de données
    pub fn new(db_path: &str) -> Self {
        let mut db = VulnerabilityDB::new();
        if let Err(e) = db.load_from_dir(db_path) {
            eprintln!("⚠️ [security] Erreur de chargement de la DB : {}", e);
        }
        Self { db }
    }

    // Point d'entrée principal pour analyser un fichier détecté
    pub fn analyze_file(&mut self, file_path: &Path) -> SafeRepoResult<Vec<Advisory>> {
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
                if file_path.file_name().unwrap_or_default() == "Cargo.lock" {
                    self.process_cargo_lock(file_path)
                } else if file_path.file_name().unwrap_or_default() == "package-lock.json" {
                    self.process_package_lock(file_path)
                } else {
                    Err(SafeRepoError::ValidationError {
                        file_path: file_path.display().to_string(),
                        reason: format!("Unknown lock file: {}", file_path.display()),
                    })
                }
            }
            "json" => {
                if file_path.file_name().unwrap_or_default() == "package-lock.json" {
                    self.process_package_lock(file_path)
                } else if file_path.file_name().unwrap_or_default() == "package.json" {
                    self.process_package_json(file_path)
                } else {
                    Err(SafeRepoError::ValidationError {
                        file_path: file_path.display().to_string(),
                        reason: format!("Fichier JSON inconnu: {}", file_path.display()),
                    })
                }
            }
            "txt" => {
                if file_path.file_name().unwrap_or_default() == "requirements.txt" {
                     self.process_requirements_txt(file_path)
                } else {
                    Err(SafeRepoError::ValidationError {
                        file_path: file_path.display().to_string(),
                        reason: format!("Fichier TXT inconnu: {}", file_path.display()),
                    })
                }
            },
            "mod" => {
                if file_path.file_name().unwrap_or_default() == "go.mod" {
                    self.process_go_mod(file_path)
                } else {
                    Err(SafeRepoError::ValidationError {
                        file_path: file_path.display().to_string(),
                        reason: format!("Fichier MOD inconnu: {}", file_path.display()),
                    })
                }
            }
            _ => Err(SafeRepoError::ValidationError {
                file_path: file_path.display().to_string(),
                reason: format!("Type de fichier non supporté: {}", extension),
            })
        }
    }

    // Parser package-lock.json - Parser les dépendances Node.js/NPM
    // Traite les formats NPM v2 (plat) et v3+ (imbriqué)
    fn process_package_lock(&mut self, file_path: &Path) -> SafeRepoResult<Vec<Advisory>> {
        // 1. lire le fichier
        let content = std::fs::read_to_string(file_path).map_err(|e| SafeRepoError::IoError {
            context: format!("reading package-lock.json: {}", file_path.display()),
            source: e,
        })?;

        // 2. Valider que le fichier n'est pas vide
        if content.trim().is_empty() {
            return Err(SafeRepoError::ValidationError {
                file_path: file_path.display().to_string(),
                reason: "package-lock.json is empty".to_string(),
            });
        }

        // 3. Parse JSON
        let lock_data: PackageLockJson =
            serde_json::from_str(&content).map_err(|e| SafeRepoError::ValidationError {
                file_path: file_path.display().to_string(),
                reason: format!("Invalid JSON in package-lock.json: {}", e),
            })?;

        let mut vulnerabilities = Vec::new();

        // 4. Traiter les paquets au niveau racine (format NPM v3+)
        for (pkg_name, pkg_entry) in &lock_data.packages {
            // Ignorer le paquet racine (clé = "")
            if pkg_name.is_empty() || pkg_name == "." {
                continue;
            }

            // Extraire le nom du package du chemin (format: "node_modules/nom-package")
            let clean_name = if let Some(pos) = pkg_name.rfind('/') {
                &pkg_name[pos + 1..]
            } else {
                pkg_name
            };

            // Valider la version
            match semver::Version::parse(&pkg_entry.version) {
                Ok(version) => {
                    let found = self.db.check_vulnerability(clean_name, &version);
                    vulnerabilities.extend(found.iter().map(|&adv| adv.clone()));
                }
                Err(e) => {
                    eprintln!(
                        "⚠️ Version invalide pour {}: {} ({})",
                        clean_name, pkg_entry.version, e
                    );
                }
            }

            // 5. Traiter les dépendances imbriquées si présentes
            if let Some(nested_deps) = &pkg_entry.dependencies {
                vulnerabilities.extend(self.process_npm_dependencies(clean_name, &nested_deps)?);
            }
        }

        // 6. Traiter les dépendances plates (format NPM v2)
        vulnerabilities.extend(self.process_npm_dependencies("root", &lock_data.dependencies)?);

        Ok(vulnerabilities)
    }

    // Fonction helper pour traiter les dépendances NPM imbriquées
    fn process_npm_dependencies(
        &mut self,
        parent: &str,
        deps: &std::collections::HashMap<String, PackageLockDep>,
    ) -> SafeRepoResult<Vec<Advisory>> {
        let mut vulnerabilities = Vec::new();

        for (dep_name, dep) in deps.iter() {
            if let Some(version_str) = &dep.version {
                match semver::Version::parse(version_str) {
                    Ok(version) => {
                        let found = self.db.check_vulnerability(dep_name, &version);
                        vulnerabilities.extend(found.iter().map(|&adv| adv.clone()));
                    }
                    Err(e) => {
                        eprintln!(
                            "⚠️ [{}] Version invalide pour {}: {} ({})",
                            parent, dep_name, version_str, e
                        );
                    }
                }
            }

            // Traiter récursivement les dépendances imbriquées
            if let Some(nested) = &dep.dependencies {
                vulnerabilities.extend(self.process_npm_dependencies(dep_name, nested)?);
            }
        }

        Ok(vulnerabilities)
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
    fn process_cargo_lock(&mut self, file_path: &Path) -> SafeRepoResult<Vec<Advisory>> {
        let content = std::fs::read_to_string(file_path).map_err(|e| SafeRepoError::IoError {
            context: format!("reading Cargo.lock: {}", file_path.display()),
            source: e,
        })?;

        let lock_data: CargoLock =
            toml::from_str(&content).map_err(|e| SafeRepoError::TomlError {
                context: format!("parsing Cargo.lock: {}", file_path.display()),
                source: e,
            })?;

        let mut vulnerabilities = Vec::new();

        // Itérer sans panic - continuer même si une dépendance est invalide
        for package in &lock_data.packages {
            match semver::Version::parse(&package.version) {
                Ok(version) => {
                    let found = self.db.check_vulnerability(&package.name, &version);
                    vulnerabilities.extend(found.iter().map(|&adv| adv.clone()));
                }
                Err(e) => {
                    // Logger et continuer
                    eprintln!(
                        "⚠️ Invalid version for {}: {} ({})",
                        package.name, package.version, e
                    );
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Parser package.json - retourner Result
    fn process_package_json(&mut self, _file_path: &Path) -> SafeRepoResult<Vec<Advisory>> {
        // TODO: Implémentation du parsing package.json
        Ok(Vec::new())
    }

    /// Parser requirements.txt - Parser les dépendances Python/PIP
    /// Support de multiples formats et contraintes
    fn process_requirements_txt(&mut self, file_path: &Path) -> SafeRepoResult<Vec<Advisory>> {
        // 1. Lire le fichier
        let content = std::fs::read_to_string(file_path).map_err(|e| {
            SafeRepoError::IoError {
                context: format!("lecture de requirements.txt: {}", file_path.display()),
                source: e,
            }
        })?;

        // 2. Valider que le fichier n'est pas vide
        if content.trim().is_empty() {
            return Err(SafeRepoError::ValidationError {
                file_path: file_path.display().to_string(),
                reason: "requirements.txt est vide".to_string(),
            });
        }

        let mut vulnerabilities = Vec::new();
        let mut line_count = 0;

        // 3. Traiter chaque ligne
        for (line_num, line) in content.lines().enumerate() {
            line_count += 1;

            // Parser la dépendance
            match PythonRequirement::parse(line) {
                Some(req) => {
                    // Si une version est spécifiée, vérifier les vulnérabilités
                    if let Some(version_str) = &req.version {
                        // Python utilise des schémas de version différents du semver
                        // Essayer de convertir au format semver
                        match semver::Version::parse(version_str) {
                            Ok(version) => {
                                let found = self.db.check_vulnerability(&req.name, &version);
                                vulnerabilities.extend(found.iter().map(|&adv| adv.clone()));
                            }
                            Err(_) => {
                                // Essayer de normaliser la version Python vers semver
                                // Format: 1.2.3 ou 1.2.3.post1 ou 1.2.3rc1
                                if let Some(normalized) = self.normalize_python_version(version_str) {
                                    match semver::Version::parse(&normalized) {
                                        Ok(version) => {
                                            let found = self.db.check_vulnerability(&req.name, &version);
                                            vulnerabilities.extend(found.iter().map(|&adv| adv.clone()));
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "⚠️ [requirements.txt:{}] Impossible de parser la version '{}' pour {}: {}",
                                                line_num + 1, version_str, req.name, e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        // Pas de version spécifiée - log comme info
                        eprintln!(
                            "ℹ️ [requirements.txt:{}] Pas de version spécifiée pour {} - vérification de version ignorée",
                            line_num + 1, req.name
                        );
                    }
                }
                None => {
                    // Ignorer (commentaires, URLs git, etc.)
                }
            }
        }

        eprintln!(
            "✅ {} lignes traitées depuis requirements.txt",
            line_count
        );

        Ok(vulnerabilities)
    }

    /// Normaliser les chaînes de version Python au format de versioning sémantique
    /// Convertit: 1.2.3.post1 → 1.2.3-post1
    /// Convertit: 1.2.3rc1 → 1.2.3-rc1
    /// Convertit: 1.2 → 1.2.0
    fn normalize_python_version(&self, version_str: &str) -> Option<String> {
        // Supprimer les espaces
        let version = version_str.trim();

        // Gérer les suffixes .devN et .postN
        let normalized = version
            .replace(".dev", "-dev")
            .replace(".post", "-post")
            .replace("rc", "-rc")
            .replace("a", "-a")
            .replace("b", "-b");

        // S'assurer que nous avons au moins 3 parties de version (x.y.z)
        let parts: Vec<&str> = normalized.split('.').collect();
        if parts.len() < 3 {
            // Compléter avec des zéros
            let mut padded = parts.join(".");
            while padded.matches('.').count() < 2 {
                padded.push_str(".0");
            }
            Some(padded)
        } else {
            Some(normalized)
        }
    }

    /// Parser go.mod - Parser les dépendances Go modules
    /// Traite les directives require et replace
    fn process_go_mod(&mut self, file_path: &Path) -> SafeRepoResult<Vec<Advisory>> {
        // 1. Lire le fichier
        let content = std::fs::read_to_string(file_path).map_err(|e| {
            SafeRepoError::IoError {
                context: format!("lecture de go.mod: {}", file_path.display()),
                source: e,
            }
        })?;

        // 2. Valider que le fichier n'est pas vide
        if content.trim().is_empty() {
            return Err(SafeRepoError::ValidationError {
                file_path: file_path.display().to_string(),
                reason: "go.mod est vide".to_string(),
            });
        }

        // 3. Vérifier que c'est un vrai fichier go.mod
        if !content.starts_with("module ") {
            return Err(SafeRepoError::ValidationError {
                file_path: file_path.display().to_string(),
                reason: "fichier go.mod invalide: doit commencer par 'module'".to_string(),
            });
        }

        let mut vulnerabilities = Vec::new();
        let mut line_count = 0;

        // 4. Traiter chaque ligne
        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            // Ignorer les blocs module et go version
            if trimmed.starts_with("module ") || trimmed.starts_with("go ") {
                continue;
            }

            // Parser le module
            match GoModule::parse(line) {
                Some(module) => {
                    line_count += 1;

                    // Parser la version Go (format: v1.2.3)
                    match semver::Version::parse(&module.version) {
                        Ok(version) => {
                            let found = self.db.check_vulnerability(&module.name, &version);
                            vulnerabilities.extend(found.iter().map(|&adv| adv.clone()));
                        }
                        Err(e) => {
                            eprintln!(
                                "⚠️ [go.mod:{}] Version invalide pour {}: {} ({})",
                                line_num + 1, module.name, module.version, e
                            );
                        }
                    }
                }
                None => {
                    // Ignorer (commentaires, directives, etc.)
                }
            }
        }

        eprintln!(
            "✅ {} modules Go traités depuis go.mod",
            line_count
        );

        Ok(vulnerabilities)
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
