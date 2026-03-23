use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone)]
pub struct DocumentDomainIssue {
    pub snippet: String,
}

pub fn audit_document_domain(target: &str) -> Vec<DocumentDomainIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    find_document_domain(&body)
}

pub(crate) fn find_document_domain(html: &str) -> Vec<DocumentDomainIssue> {
    let lower = html.to_ascii_lowercase();
    let mut issues = Vec::new();
    let mut search_from = 0;

    while let Some(start) = lower[search_from..].find("<script") {
        let abs_start = search_from + start;
        let Some(tag_end) = lower[abs_start..].find('>') else {
            break;
        };
        let tag = &lower[abs_start..abs_start + tag_end + 1];
        if tag.contains("src=") {
            search_from = abs_start + tag_end + 1;
            continue;
        }

        let script_end = lower[abs_start + tag_end + 1..]
            .find("</script>")
            .map(|e| abs_start + tag_end + 1 + e)
            .unwrap_or(lower.len());

        let script_body = &lower[abs_start + tag_end + 1..script_end];
        search_from = script_end;

        if script_body.contains("document.domain") {
            let original_body = &html[abs_start + tag_end + 1..script_end];
            let snippet = extract_snippet(original_body, "document.domain");
            issues.push(DocumentDomainIssue { snippet });
        }
    }

    issues
}

fn extract_snippet(body: &str, pattern: &str) -> String {
    let lower = body.to_ascii_lowercase();
    let Some(pos) = lower.find(pattern) else {
        return String::new();
    };
    let start = body[..pos].rfind('\n').map(|p| p + 1).unwrap_or(0);
    let end = body[pos..]
        .find('\n')
        .map(|p| pos + p)
        .unwrap_or(body.len());
    let line = body[start..end].trim();
    if line.len() > 120 {
        format!("{}...", &line[..117])
    } else {
        line.to_string()
    }
}

pub fn document_domain_to_operations(
    issues: &[DocumentDomainIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        5.0,
        0.8,
    )]
}
