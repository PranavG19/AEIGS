use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::recon_client;
use crate::util::timestamp_ms;

#[derive(Debug, Clone)]
pub struct SecurityTxtInfo {
    pub fields: Vec<(String, String)>,
    pub path: String,
}

pub fn fetch_security_txt(target: &str) -> Option<SecurityTxtInfo> {
    let domain = recon_client::validated_domain(target)?;
    let scheme = if target.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    let client = recon_client::default_client()?;

    for path in &[".well-known/security.txt", "security.txt"] {
        let url = format!("{scheme}://{domain}/{path}");
        if let Ok(resp) = client.get(&url).send()
            && resp.status().is_success()
            && let Ok(body) = resp.text()
        {
            let fields = parse_security_txt(&body);
            if !fields.is_empty() {
                return Some(SecurityTxtInfo {
                    fields,
                    path: path.to_string(),
                });
            }
        }
    }
    None
}

pub(crate) fn parse_security_txt(body: &str) -> Vec<(String, String)> {
    body.lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if value.is_empty() {
                return None;
            }
            Some((key, value))
        })
        .collect()
}

pub fn security_txt_to_operations(info: &SecurityTxtInfo, seq: &mut u64) -> Vec<OperationLogEntry> {
    *seq += 1;
    let mut props: Vec<(String, String)> = info
        .fields
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    props.push(("source".to_string(), "security_txt".to_string()));
    props.push(("path".to_string(), info.path.clone()));

    vec![OperationLogEntry {
        sequence_number: *seq,
        module: ModuleIdentifier::PassiveRecon,
        operation: GraphOperation::AddNode {
            node_type: NodeType::Config,
            properties: props,
        },
        timestamp_unix_ms: timestamp_ms(),
    }]
}
