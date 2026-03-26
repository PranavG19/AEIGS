use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;

use crate::state::AppState;

/// GET /api/export/html — full HTML report of findings
pub async fn export_html(State(state): State<AppState>) -> impl IntoResponse {
    let graph = state.graph.read();
    let findings = &graph.findings;

    let mut html = String::from(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8">
<title>AEGIS Scan Report</title>
<style>
body{font-family:system-ui;max-width:900px;margin:40px auto;padding:0 20px;color:#1a1a2e;background:#f8fafc}
h1{color:#1e293b;border-bottom:2px solid #3b82f6;padding-bottom:8px}
.finding{background:#fff;border-radius:8px;padding:16px;margin:12px 0;border-left:4px solid #94a3b8;box-shadow:0 1px 3px rgba(0,0,0,0.1)}
.finding.critical{border-left-color:#ef4444} .finding.high{border-left-color:#f97316}
.finding.medium{border-left-color:#eab308} .finding.low{border-left-color:#22c55e}
.sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:700;text-transform:uppercase}
.sev.critical{background:#fef2f2;color:#dc2626} .sev.high{background:#fff7ed;color:#ea580c}
.sev.medium{background:#fefce8;color:#ca8a04} .sev.low{background:#f0fdf4;color:#16a34a}
pre{background:#f1f5f9;padding:12px;border-radius:6px;overflow-x:auto;font-size:13px}
.meta{color:#64748b;font-size:14px;margin-top:4px}
</style></head><body>
<h1>AEGIS Scan Report</h1>"#,
    );

    let status = state.scan_status.read();
    html.push_str(&format!(
        "<p><strong>Target:</strong> {}</p><p><strong>Findings:</strong> {}</p><p><strong>Risk Score:</strong> {}/100</p><hr>\n",
        status.target, findings.len(), status.risk_score
    ));

    for f in findings.iter().rev() {
        let sev_lower = f.severity.to_lowercase();
        html.push_str(&format!(
            r#"<div class="finding {}">
<h3>{} <span class="sev {}">{}</span></h3>
<div class="meta">{}</div>
<pre>{}</pre>
<p>Confidence: {:.0}%</p>
</div>"#,
            sev_lower, f.vuln_class, sev_lower, f.severity,
            f.endpoint, f.evidence_preview, f.confidence * 100.0,
        ));
    }

    html.push_str("</body></html>");

    (
        [(header::CONTENT_TYPE, "text/html"), (header::CONTENT_DISPOSITION, "attachment; filename=\"aegis-report.html\"")],
        html,
    )
}

/// GET /api/export/sarif — SARIF 2.1.0 JSON export
pub async fn export_sarif(State(state): State<AppState>) -> impl IntoResponse {
    let graph = state.graph.read();
    let findings = &graph.findings;

    let rules: Vec<serde_json::Value> = findings.iter().enumerate().map(|(i, f)| {
        serde_json::json!({
            "id": format!("AEGIS-{:03}", i + 1),
            "name": f.vuln_class,
            "shortDescription": { "text": f.vuln_class },
            "defaultConfiguration": { "level": severity_to_sarif_level(&f.severity) }
        })
    }).collect();

    let results: Vec<serde_json::Value> = findings.iter().enumerate().map(|(i, f)| {
        serde_json::json!({
            "ruleId": format!("AEGIS-{:03}", i + 1),
            "level": severity_to_sarif_level(&f.severity),
            "message": { "text": format!("{} at {}", f.vuln_class, f.endpoint) },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": f.endpoint }
                }
            }],
            "properties": {
                "confidence": f.confidence,
                "evidence": f.evidence_preview,
            }
        })
    }).collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AEGIS",
                    "version": "0.1.0",
                    "informationUri": "https://aegis.dev",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    });

    (
        [(header::CONTENT_TYPE, "application/json"), (header::CONTENT_DISPOSITION, "attachment; filename=\"aegis-report.sarif.json\"")],
        serde_json::to_string_pretty(&sarif).unwrap_or_default(),
    )
}

/// GET /api/export/json — raw findings JSON
pub async fn export_json(State(state): State<AppState>) -> impl IntoResponse {
    let graph = state.graph.read();
    let export = serde_json::json!({
        "findings": graph.findings,
        "nodes": graph.nodes.values().collect::<Vec<_>>(),
        "edges": graph.edges,
    });

    (
        [(header::CONTENT_TYPE, "application/json"), (header::CONTENT_DISPOSITION, "attachment; filename=\"aegis-findings.json\"")],
        serde_json::to_string_pretty(&export).unwrap_or_default(),
    )
}

/// GET /api/export/graph.svg — current graph as SVG
pub async fn export_svg(State(state): State<AppState>) -> impl IntoResponse {
    let graph = state.graph.read();
    let mut svg = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="800" viewBox="0 0 1200 800">
<style>
  text { font-family: monospace; font-size: 11px; fill: #e2e8f0; }
  .bg { fill: #0a0e17; }
  .endpoint { fill: #3b82f6; }
  .vuln-critical { fill: #ef4444; }
  .vuln-high { fill: #f97316; }
  .vuln-medium { fill: #eab308; }
  .vuln-low { fill: #22c55e; }
  .asset { fill: #22c55e; }
  .edge { stroke: #334155; stroke-width: 1.5; }
</style>
<rect class="bg" width="1200" height="800"/>
"#,
    );

    let node_list: Vec<_> = graph.nodes.values().collect();
    let spacing = if node_list.is_empty() { 0.0 } else { 1100.0 / node_list.len() as f64 };

    for (i, node) in node_list.iter().enumerate() {
        let x = 50.0 + (i as f64) * spacing;
        let y = 400.0 + ((i % 3) as f64 - 1.0) * 120.0;
        let class = match node.node_type.as_str() {
            "vulnerability" => {
                let sev = node.severity.as_deref().unwrap_or("medium");
                format!("vuln-{}", sev)
            }
            "asset" => "asset".to_string(),
            _ => "endpoint".to_string(),
        };
        svg.push_str(&format!(
            r#"<circle cx="{}" cy="{}" r="12" class="{}"/><text x="{}" y="{}">{}</text>"#,
            x, y, class, x, y + 25.0, node.label,
        ));
    }

    svg.push_str("</svg>");

    (
        [(header::CONTENT_TYPE, "image/svg+xml"), (header::CONTENT_DISPOSITION, "attachment; filename=\"aegis-graph.svg\"")],
        svg,
    )
}

/// GET /api/export/graph.dot — DOT format for Graphviz
pub async fn export_dot(State(state): State<AppState>) -> impl IntoResponse {
    let graph = state.graph.read();
    let mut dot = String::from("digraph aegis {\n  rankdir=LR;\n  node [style=filled fontname=\"monospace\" fontsize=10];\n\n");

    for node in graph.nodes.values() {
        let (color, shape) = match node.node_type.as_str() {
            "vulnerability" => {
                let c = match node.severity.as_deref().unwrap_or("medium") {
                    "critical" => "#ef4444",
                    "high" => "#f97316",
                    "medium" => "#eab308",
                    _ => "#22c55e",
                };
                (c, "octagon")
            }
            "asset" => ("#22c55e", "diamond"),
            _ => ("#3b82f6", "ellipse"),
        };
        dot.push_str(&format!(
            "  \"{}\" [label=\"{}\" fillcolor=\"{}\" shape={}];\n",
            node.id, node.label, color, shape,
        ));
    }

    dot.push('\n');
    for edge in &graph.edges {
        dot.push_str(&format!(
            "  \"{}\" -> \"{}\" [label=\"{}\"];\n",
            edge.source, edge.target, edge.label,
        ));
    }

    dot.push_str("}\n");

    (
        [(header::CONTENT_TYPE, "text/vnd.graphviz"), (header::CONTENT_DISPOSITION, "attachment; filename=\"aegis-graph.dot\"")],
        dot,
    )
}

/// POST /api/share — encode findings in a shareable URL fragment
pub async fn create_share_link(State(state): State<AppState>) -> impl IntoResponse {
    let graph = state.graph.read();
    let payload = serde_json::json!({
        "findings": graph.findings,
        "node_count": graph.nodes.len(),
        "edge_count": graph.edges.len(),
    });
    let json_str = serde_json::to_string(&payload).unwrap_or_default();
    let encoded = base64_encode(&json_str);
    let port = state.args.port;

    axum::Json(serde_json::json!({
        "url": format!("http://localhost:{}/#share={}", port, encoded),
        "encoded_length": encoded.len(),
    }))
}

fn severity_to_sarif_level(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        "low" => "note",
        _ => "none",
    }
}

fn base64_encode(input: &str) -> String {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut encoder = Base64Encoder::new(&mut buf);
        let _ = encoder.write_all(input.as_bytes());
        let _ = encoder.finish();
    }
    String::from_utf8(buf).unwrap_or_default()
}

/// Minimal base64 encoder to avoid pulling in the base64 crate just for this.
struct Base64Encoder<W: std::io::Write> {
    writer: W,
    buf: [u8; 3],
    buf_len: usize,
}

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

impl<W: std::io::Write> Base64Encoder<W> {
    fn new(writer: W) -> Self {
        Self { writer, buf: [0; 3], buf_len: 0 }
    }

    fn flush_buf(&mut self) -> std::io::Result<()> {
        if self.buf_len == 0 { return Ok(()); }
        let b = &self.buf;
        let mut out = [b'='; 4];
        out[0] = B64_CHARS[(b[0] >> 2) as usize];
        out[1] = B64_CHARS[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize];
        if self.buf_len > 1 {
            out[2] = B64_CHARS[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize];
        }
        if self.buf_len > 2 {
            out[3] = B64_CHARS[(b[2] & 0x3f) as usize];
        }
        self.writer.write_all(&out)?;
        self.buf = [0; 3];
        self.buf_len = 0;
        Ok(())
    }

    fn finish(mut self) -> std::io::Result<W> {
        self.flush_buf()?;
        Ok(self.writer)
    }
}

impl<W: std::io::Write> std::io::Write for Base64Encoder<W> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut written = 0;
        for &byte in data {
            self.buf[self.buf_len] = byte;
            self.buf_len += 1;
            if self.buf_len == 3 {
                self.flush_buf()?;
            }
            written += 1;
        }
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_buf()
    }
}

#[cfg(test)]
#[path = "export_api_test.rs"]
mod export_api_test;
