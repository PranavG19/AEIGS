use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifRule {
    pub id: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifConfiguration,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifConfiguration {
    pub level: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    pub properties: SarifResultProperties,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: Option<SarifPhysicalLocation>,
    #[serde(rename = "logicalLocations")]
    pub logical_locations: Vec<SarifLogicalLocation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifLogicalLocation {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifResultProperties {
    pub severity: f64,
    pub confidence: f64,
    pub composite_score: f64,
}

pub struct SarifFinding {
    pub rule_id: String,
    pub rule_description: String,
    pub level: SarifLevel,
    pub message: String,
    pub uri: Option<String>,
    pub logical_location_name: Option<String>,
    pub logical_location_kind: Option<String>,
    pub severity: f64,
    pub confidence: f64,
    pub composite_score: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SarifLevel {
    Error,
    Warning,
    Note,
    None,
}

impl SarifLevel {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Note => "note",
            Self::None => "none",
        }
    }
}

pub fn emit_sarif(findings: &[SarifFinding], tool_version: &str) -> SarifReport {
    let mut rules = Vec::new();
    let mut seen_rules = std::collections::HashSet::new();

    for finding in findings {
        if seen_rules.insert(finding.rule_id.clone()) {
            rules.push(SarifRule {
                id: finding.rule_id.clone(),
                short_description: SarifMessage {
                    text: finding.rule_description.clone(),
                },
                default_configuration: SarifConfiguration {
                    level: finding.level.as_str().to_string(),
                },
            });
        }
    }

    let results: Vec<SarifResult> = findings
        .iter()
        .map(|f| {
            let mut locations = Vec::new();

            let physical_location = f.uri.as_ref().map(|uri| SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation { uri: uri.clone() },
            });

            let mut logical_locations = Vec::new();
            if let Some(name) = &f.logical_location_name {
                logical_locations.push(SarifLogicalLocation {
                    name: name.clone(),
                    kind: f
                        .logical_location_kind
                        .clone()
                        .unwrap_or_else(|| "function".to_string()),
                });
            }

            if physical_location.is_some() || !logical_locations.is_empty() {
                locations.push(SarifLocation {
                    physical_location,
                    logical_locations,
                });
            }

            SarifResult {
                rule_id: f.rule_id.clone(),
                level: f.level.as_str().to_string(),
                message: SarifMessage {
                    text: f.message.clone(),
                },
                locations,
                properties: SarifResultProperties {
                    severity: f.severity,
                    confidence: f.confidence,
                    composite_score: f.composite_score,
                },
            }
        })
        .collect();

    SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "AEGIS".to_string(),
                    version: tool_version.to_string(),
                    rules,
                },
            },
            results,
        }],
    }
}

pub fn sarif_to_json(report: &SarifReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}
