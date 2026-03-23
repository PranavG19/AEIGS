use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ContentTypeConfusionIssue {
    AcceptsXmlWhenExpectingJson {
        endpoint: String,
    },
    XxeIndicator {
        endpoint: String,
        indicator: String,
    },
    AcceptsMultipleContentTypes {
        endpoint: String,
        accepted: Vec<String>,
    },
    MismatchedResponseType {
        request_ct: String,
        response_ct: String,
    },
}

impl std::fmt::Display for ContentTypeConfusionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AcceptsXmlWhenExpectingJson { endpoint } => {
                write!(f, "accepts_xml_for_json:{endpoint}")
            }
            Self::XxeIndicator {
                endpoint,
                indicator,
            } => {
                write!(f, "xxe_indicator:{endpoint}:{indicator}")
            }
            Self::AcceptsMultipleContentTypes { endpoint, accepted } => {
                write!(f, "multi_ct:{endpoint}:{}", accepted.join(","))
            }
            Self::MismatchedResponseType {
                request_ct,
                response_ct,
            } => {
                write!(f, "ct_mismatch:{request_ct}->{response_ct}")
            }
        }
    }
}

const TEST_CONTENT_TYPES: &[&str] = &[
    "application/xml",
    "text/xml",
    "application/x-www-form-urlencoded",
];

pub fn audit_content_type_confusion(target: &str) -> Vec<ContentTypeConfusionIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let mut issues = Vec::new();

    let json_resp = client
        .post(target)
        .header("Content-Type", "application/json")
        .body("{}")
        .send();
    let json_status = json_resp.as_ref().ok().map(|r| r.status().as_u16());

    for &ct in TEST_CONTENT_TYPES {
        let body = if ct.contains("xml") {
            "<root></root>"
        } else {
            "key=value"
        };

        if let Ok(resp) = client
            .post(target)
            .header("Content-Type", ct)
            .body(body)
            .send()
        {
            let status = resp.status().as_u16();
            if let Some(js) = json_status
                && js < 400
                && status < 400
                && ct.contains("xml")
            {
                issues.push(ContentTypeConfusionIssue::AcceptsXmlWhenExpectingJson {
                    endpoint: target.to_string(),
                });
            }
        }
    }

    issues
}

pub fn analyze_content_type_confusion(
    json_status: u16,
    xml_status: u16,
    xml_body: &str,
    endpoint: &str,
) -> Vec<ContentTypeConfusionIssue> {
    let mut issues = Vec::new();

    if json_status < 400 && xml_status < 400 {
        issues.push(ContentTypeConfusionIssue::AcceptsXmlWhenExpectingJson {
            endpoint: endpoint.to_string(),
        });
    }

    if xml_status < 400 {
        if xml_body.contains("root:") || xml_body.contains("/bin/") {
            issues.push(ContentTypeConfusionIssue::XxeIndicator {
                endpoint: endpoint.to_string(),
                indicator: "file_content_leak".to_string(),
            });
        }
        if xml_body.contains("169.254.169.254") || xml_body.contains("metadata") {
            issues.push(ContentTypeConfusionIssue::XxeIndicator {
                endpoint: endpoint.to_string(),
                indicator: "ssrf_metadata_leak".to_string(),
            });
        }
    }

    issues
}

pub fn analyze_response_type_mismatch(
    request_content_type: &str,
    response_content_type: &str,
) -> Option<ContentTypeConfusionIssue> {
    let req_ct = request_content_type.to_ascii_lowercase();
    let resp_ct = response_content_type.to_ascii_lowercase();

    let req_is_json = req_ct.contains("json");
    let resp_is_json = resp_ct.contains("json");
    let req_is_xml = req_ct.contains("xml");
    let resp_is_xml = resp_ct.contains("xml");

    if (req_is_json && resp_is_xml) || (req_is_xml && resp_is_json) {
        return Some(ContentTypeConfusionIssue::MismatchedResponseType {
            request_ct: request_content_type.to_string(),
            response_ct: response_content_type.to_string(),
        });
    }

    None
}

pub fn content_type_confusion_severity(issue: &ContentTypeConfusionIssue) -> f64 {
    match issue {
        ContentTypeConfusionIssue::XxeIndicator { .. } => 9.0,
        ContentTypeConfusionIssue::AcceptsXmlWhenExpectingJson { .. } => 6.0,
        ContentTypeConfusionIssue::MismatchedResponseType { .. } => 4.0,
        ContentTypeConfusionIssue::AcceptsMultipleContentTypes { .. } => 3.5,
    }
}

pub fn content_type_confusion_to_operations(
    issues: &[ContentTypeConfusionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::XmlExternalEntity,
                content_type_confusion_severity(issue),
                0.7,
            )
        })
        .collect()
}
