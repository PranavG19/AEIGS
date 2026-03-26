#[cfg(test)]
mod tests {
    use crate::dashboard::DASHBOARD_HTML;

    #[test]
    fn dashboard_html_is_valid_structure() {
        assert!(DASHBOARD_HTML.contains("<!DOCTYPE html>"));
        assert!(DASHBOARD_HTML.contains("</html>"));
        assert!(DASHBOARD_HTML.contains("<title>AEGIS"));
    }

    #[test]
    fn dashboard_includes_d3_cdn() {
        assert!(DASHBOARD_HTML.contains("d3js.org/d3.v7"));
    }

    #[test]
    fn dashboard_includes_sse_connection() {
        assert!(DASHBOARD_HTML.contains("EventSource"));
        assert!(DASHBOARD_HTML.contains("/api/graph"));
    }

    #[test]
    fn dashboard_includes_keyboard_shortcuts() {
        assert!(DASHBOARD_HTML.contains("Space"));
        assert!(DASHBOARD_HTML.contains("keydown"));
        assert!(DASHBOARD_HTML.contains("KeyR"));
        assert!(DASHBOARD_HTML.contains("KeyF"));
        assert!(DASHBOARD_HTML.contains("KeyE"));
    }

    #[test]
    fn dashboard_includes_force_simulation() {
        assert!(DASHBOARD_HTML.contains("forceSimulation"));
        assert!(DASHBOARD_HTML.contains("forceLink"));
        assert!(DASHBOARD_HTML.contains("forceManyBody"));
    }

    #[test]
    fn dashboard_includes_modal() {
        assert!(DASHBOARD_HTML.contains("modal-overlay"));
        assert!(DASHBOARD_HTML.contains("closeModal"));
    }

    #[test]
    fn dashboard_includes_severity_colors() {
        assert!(DASHBOARD_HTML.contains("--accent-red"));
        assert!(DASHBOARD_HTML.contains("--accent-orange"));
        assert!(DASHBOARD_HTML.contains("--accent-yellow"));
        assert!(DASHBOARD_HTML.contains("--accent-green"));
    }

    #[test]
    fn dashboard_includes_graph_legend() {
        assert!(DASHBOARD_HTML.contains("Endpoint"));
        assert!(DASHBOARD_HTML.contains("Vulnerability"));
        assert!(DASHBOARD_HTML.contains("Asset"));
    }

    #[test]
    fn dashboard_includes_export_svg_function() {
        assert!(DASHBOARD_HTML.contains("exportSVG"));
        assert!(DASHBOARD_HTML.contains("XMLSerializer"));
    }
}
