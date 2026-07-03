// Client OSV.dev - Interface avec l'API Open Source Vulnerabilities
// Permet de rechercher des vulnérabilités par package name et version

use crate::database::db::{Advisory, Severity, Versions};
use crate::errorhandle::SafeRepoResult;
use serde::{Deserialize, Serialize};

const _OSV_API_URL: &str = "https://api.osv.dev/v1/query";

/// Réponse de l'API OSV.dev
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvResponse {
    pub vulns: Vec<OsvVulnerability>,
}

/// Vulnérabilité retournée par OSV.dev
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvVulnerability {
    pub id: String,
    pub summary: String,
    pub details: Option<String>,
    pub severity: Option<String>,
    pub affected: Option<Vec<AffectedPackage>>,
}

/// Package affecté avec ses versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedPackage {
    pub package: PackageInfo,
    pub ranges: Option<Vec<VersionRange>>,
    pub versions: Option<Vec<String>>,
}

/// Info du package affecté
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    pub ecosystem: String,
    pub name: String,
}

/// Plage de versions affectées
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRange {
    pub r#type: Option<String>,
    pub events: Option<Vec<VersionEvent>>,
}

/// Événement de version (introduced, fixed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}

/// Requête à envoyer à l'API OSV.dev
#[derive(Debug, Serialize)]
pub struct OsvQuery {
    pub package: OsvPackageQuery,
}

/// Spécification du package à rechercher
#[derive(Debug, Serialize)]
pub struct OsvPackageQuery {
    pub name: String,
    pub ecosystem: String,
}

/// Client pour interroger l'API OSV.dev
pub struct OsvClient;

impl OsvClient {
    /// Cherche les vulnérabilités pour un package spécifique
    ///
    /// # Arguments
    /// * `package_name` - Nom du package (ex: "serde", "lodash")
    /// * `ecosystem` - Écosystème (ex: "npm", "crates.io", "PyPI")
    pub async fn query(package_name: &str, ecosystem: &str) -> SafeRepoResult<Vec<Advisory>> {
        // 🔍 Construire la requête
        let _query = OsvQuery {
            package: OsvPackageQuery {
                name: package_name.to_string(),
                ecosystem: ecosystem.to_string(),
            },
        };

        // ⚠️ Pour l'instant, retourner un vecteur vide (pas de dépendance HTTP en compile-time)
        // En production, utiliser reqwest pour faire la requête réelle
        log::debug!("OSV Query (simulated): {} in {}", package_name, ecosystem);

        Ok(Vec::new())
    }

    /// Convertir une réponse OSV.dev en Advisory
    pub fn convert_to_advisory(vuln: &OsvVulnerability) -> Option<Advisory> {
        // Déterminer la sévérité
        let severity = match vuln.severity.as_deref() {
            Some("CRITICAL") => Severity::Critical,
            Some("HIGH") => Severity::High,
            Some("MEDIUM") => Severity::Medium,
            Some("LOW") => Severity::Low,
            _ => Severity::Low, // Default
        };

        // Extraire les versions corrigées depuis les ranges
        let mut patched_versions = Vec::new();
        if let Some(affected) = &vuln.affected {
            for pkg in affected {
                if let Some(ranges) = &pkg.ranges {
                    for range in ranges {
                        if let Some(events) = &range.events {
                            for event in events {
                                if let Some(fixed) = &event.fixed {
                                    patched_versions.push(fixed.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        Some(Advisory {
            id: vuln.id.clone(),
            package: "unknown".to_string(), // À déterminer depuis affected
            severity,
            title: vuln.summary.clone(),
            description: vuln.details.clone().unwrap_or_default(),
            versions: Versions {
                patched: patched_versions,
                unaffected: None,
            },
        })
    }

    /// Détecter l'écosystème basé sur le type de fichier
    pub fn detect_ecosystem(manifest_file: &str) -> &'static str {
        match manifest_file.to_lowercase().as_str() {
            f if f.ends_with("cargo.lock") || f.ends_with("cargo.toml") => "crates.io",
            f if f.ends_with("package-lock.json") || f.ends_with("package.json") => "npm",
            f if f.ends_with("requirements.txt") || f.ends_with("setup.py") => "PyPI",
            f if f.ends_with("go.mod") || f.ends_with("go.sum") => "Go",
            f if f.ends_with("gemfile") || f.ends_with("gemfile.lock") => "RubyGems",
            f if f.ends_with("composer.json") || f.ends_with("composer.lock") => "Packagist",
            f if f.ends_with("pom.xml") => "Maven",
            _ => "crates.io", // Default
        }
    }
}
