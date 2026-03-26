#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::js_engine::{
        DomSimulation, HttpMethod, JsEngine, JsEngineConfig, JsEngineError, SimulatedDomElement,
        SourceMap, SourceMapProcessor, StorageSimulation,
    };

    fn default_engine() -> JsEngine {
        JsEngine::new(JsEngineConfig::default())
    }

    #[test]
    fn extract_fetch_url() {
        let engine = default_engine();
        let script = r#"fetch("/api/users")"#;
        let urls = engine.extract_endpoints(script);
        assert!(urls.contains(&"/api/users".to_string()));
    }

    #[test]
    fn extract_fetch_with_options() {
        let engine = default_engine();
        let script = r#"fetch("/api/data", { method: "POST", body: JSON.stringify("payload") })"#;
        let urls = engine.extract_endpoints(script);
        assert!(urls.contains(&"/api/data".to_string()));
    }

    #[test]
    fn extract_xhr_url() {
        let engine = default_engine();
        let script = r#"
            var xhr = new XMLHttpRequest();
            xhr.open("GET", "/api/reports");
            xhr.send();
        "#;
        let urls = engine.extract_endpoints(script);
        assert!(urls.contains(&"/api/reports".to_string()));
    }

    #[test]
    fn extract_axios_url() {
        let engine = default_engine();
        let script = r#"axios.get("/api/v2/items")"#;
        let urls = engine.extract_endpoints(script);
        assert!(urls.contains(&"/api/v2/items".to_string()));
    }

    #[test]
    fn extract_string_literal_url() {
        let engine = default_engine();
        let script = r#"const baseUrl = "https://api.example.com/v1/endpoint";"#;
        let urls = engine.extract_endpoints(script);
        assert!(urls.iter().any(|u| u.contains("api.example.com")));
    }

    #[test]
    fn extract_concatenated_url() {
        let engine = default_engine();
        let script = r#"var url = "/api" + "/users/list";"#;
        let urls = engine.extract_endpoints(script);
        assert!(urls.contains(&"/api/users/list".to_string()));
    }

    #[test]
    fn extract_multiple_urls_deduplicates() {
        let engine = default_engine();
        let script = r#"
            fetch("/api/users");
            fetch("/api/users");
            fetch("/api/data");
        "#;
        let urls = engine.extract_endpoints(script);
        let user_count = urls.iter().filter(|u| *u == "/api/users").count();
        assert_eq!(user_count, 1);
        assert!(urls.contains(&"/api/data".to_string()));
    }

    #[test]
    fn execute_captures_fetch_intercept() {
        let mut engine = default_engine();
        let script = r#"fetch("/api/items", { method: "POST" })"#;
        let result = engine.execute(script).unwrap();
        assert_eq!(result.intercepted_requests.len(), 1);
        assert_eq!(result.intercepted_requests[0].url, "/api/items");
        assert_eq!(result.intercepted_requests[0].method, HttpMethod::Post);
    }

    #[test]
    fn execute_captures_xhr_intercept() {
        let mut engine = default_engine();
        let script = r#"
            var x = new XMLHttpRequest();
            x.open("DELETE", "/api/sessions/123");
            x.send();
        "#;
        let result = engine.execute(script).unwrap();
        assert!(result
            .intercepted_requests
            .iter()
            .any(|r| r.url == "/api/sessions/123"));
        assert!(result
            .intercepted_requests
            .iter()
            .any(|r| r.method == HttpMethod::Delete));
    }

    #[test]
    fn execute_captures_localstorage_set() {
        let mut engine = default_engine();
        let script = r#"localStorage.setItem("token", "abc123")"#;
        let result = engine.execute(script).unwrap();
        assert_eq!(result.storage_entries.get("token").unwrap(), "abc123");
    }

    #[test]
    fn execute_captures_sessionstorage_set() {
        let mut engine = default_engine();
        let script = r#"sessionStorage.setItem("cart_id", "xyz789")"#;
        let result = engine.execute(script).unwrap();
        assert_eq!(result.storage_entries.get("cart_id").unwrap(), "xyz789");
    }

    #[test]
    fn execute_captures_console_log() {
        let mut engine = default_engine();
        let script = r#"console.log("debug: loaded")"#;
        let result = engine.execute(script).unwrap();
        assert!(result.console_output.contains(&"debug: loaded".to_string()));
    }

    #[test]
    fn execute_captures_console_warn() {
        let mut engine = default_engine();
        let script = r#"console.warn("deprecated API")"#;
        let result = engine.execute(script).unwrap();
        assert!(result
            .console_output
            .contains(&"deprecated API".to_string()));
    }

    #[test]
    fn execute_fails_on_empty_script() {
        let mut engine = default_engine();
        let result = engine.execute("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn execute_accumulates_intercepted_requests_across_calls() {
        let mut engine = default_engine();
        engine.execute(r#"fetch("/api/first")"#).unwrap();
        engine.execute(r#"fetch("/api/second")"#).unwrap();
        let all = engine.all_intercepted_requests();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn execute_returns_execution_time() {
        let mut engine = default_engine();
        let result = engine.execute(r#"fetch("/api/test")"#).unwrap();
        assert!(result.execution_time_ms < 1000);
    }

    #[test]
    fn storage_simulation_local_operations() {
        let mut storage = StorageSimulation::new();
        storage.local_set("key1", "value1");
        storage.local_set("key2", "value2");
        assert_eq!(storage.local_get("key1").unwrap(), "value1");
        assert_eq!(storage.local_entries().len(), 2);
        storage.local_remove("key1");
        assert!(storage.local_get("key1").is_none());
        storage.local_clear();
        assert!(storage.local_entries().is_empty());
    }

    #[test]
    fn storage_simulation_session_operations() {
        let mut storage = StorageSimulation::new();
        storage.session_set("sess_key", "sess_val");
        assert_eq!(storage.session_get("sess_key").unwrap(), "sess_val");
        storage.session_remove("sess_key");
        assert!(storage.session_get("sess_key").is_none());
    }

    #[test]
    fn storage_simulation_all_entries_merges() {
        let mut storage = StorageSimulation::new();
        storage.local_set("local_k", "local_v");
        storage.session_set("sess_k", "sess_v");
        let all = storage.all_entries();
        assert_eq!(all.len(), 2);
        assert_eq!(all.get("local_k").unwrap(), "local_v");
        assert_eq!(all.get("sess_k").unwrap(), "sess_v");
    }

    #[test]
    fn dom_simulation_get_element_by_id() {
        let mut dom = DomSimulation::new();
        dom.add_element(
            "main",
            SimulatedDomElement {
                tag: "div".to_string(),
                id: Some("main".to_string()),
                attributes: HashMap::new(),
                inner_text: "Hello".to_string(),
            },
        );
        let el = dom.get_element_by_id("main");
        assert!(el.is_some());
        assert_eq!(el.unwrap().tag, "div");
    }

    #[test]
    fn dom_simulation_get_element_by_id_missing() {
        let dom = DomSimulation::new();
        assert!(dom.get_element_by_id("nonexistent").is_none());
    }

    #[test]
    fn dom_simulation_query_selector_by_id() {
        let mut dom = DomSimulation::new();
        dom.add_element(
            "header",
            SimulatedDomElement {
                tag: "h1".to_string(),
                id: Some("header".to_string()),
                attributes: HashMap::new(),
                inner_text: "Title".to_string(),
            },
        );
        let el = dom.query_selector("#header");
        assert!(el.is_some());
        assert_eq!(el.unwrap().inner_text, "Title");
    }

    #[test]
    fn dom_simulation_query_selector_by_tag() {
        let mut dom = DomSimulation::new();
        dom.add_element(
            "form1",
            SimulatedDomElement {
                tag: "form".to_string(),
                id: Some("form1".to_string()),
                attributes: HashMap::new(),
                inner_text: String::new(),
            },
        );
        let el = dom.query_selector("form");
        assert!(el.is_some());
    }

    #[test]
    fn dom_simulation_create_element() {
        let el = DomSimulation::create_element("canvas");
        assert_eq!(el.tag, "canvas");
        assert!(el.id.is_none());
        assert!(el.attributes.is_empty());
    }

    #[test]
    fn dom_simulation_element_count() {
        let mut dom = DomSimulation::new();
        assert_eq!(dom.element_count(), 0);
        dom.add_element(
            "a",
            SimulatedDomElement {
                tag: "a".to_string(),
                id: Some("a".to_string()),
                attributes: HashMap::new(),
                inner_text: String::new(),
            },
        );
        assert_eq!(dom.element_count(), 1);
    }

    #[test]
    fn source_map_parse_valid_json() {
        let json = r#"{
            "version": 3,
            "file": "app.min.js",
            "sourceRoot": "/src/",
            "sources": ["main.ts", "utils.ts", "api.ts"],
            "names": ["handleClick", "fetchData", "parseResponse"],
            "mappings": "AAAA,SAAS;AACT,SAAS"
        }"#;
        let sm = SourceMapProcessor::parse(json);
        assert!(sm.is_some());
        let sm = sm.unwrap();
        assert_eq!(sm.version, 3);
        assert_eq!(sm.file.as_deref(), Some("app.min.js"));
        assert_eq!(sm.source_root.as_deref(), Some("/src/"));
        assert_eq!(sm.sources.len(), 3);
        assert_eq!(sm.names.len(), 3);
        assert!(!sm.mappings.is_empty());
    }

    #[test]
    fn source_map_parse_minimal_json() {
        let json = r#"{"version": 3, "sources": ["a.js"], "mappings": "AAAA"}"#;
        let sm = SourceMapProcessor::parse(json);
        assert!(sm.is_some());
        let sm = sm.unwrap();
        assert_eq!(sm.version, 3);
        assert!(sm.file.is_none());
        assert!(sm.names.is_empty());
    }

    #[test]
    fn source_map_parse_invalid_json_returns_none() {
        assert!(SourceMapProcessor::parse("not json").is_none());
    }

    #[test]
    fn source_map_parse_missing_version_returns_none() {
        let json = r#"{"sources": ["a.js"], "mappings": "AAAA"}"#;
        assert!(SourceMapProcessor::parse(json).is_none());
    }

    #[test]
    fn source_map_segment_count() {
        let sm = SourceMap {
            version: 3,
            file: None,
            source_root: None,
            sources: vec!["a.js".to_string()],
            names: vec![],
            mappings: "AAAA,CAAC;AACD,CAAC,CAAC".to_string(),
        };
        let count = SourceMapProcessor::segment_count(&sm);
        assert_eq!(count, 5);
    }

    #[test]
    fn source_map_deobfuscate_name() {
        let sm = SourceMap {
            version: 3,
            file: None,
            source_root: None,
            sources: vec![],
            names: vec!["handleSubmit".to_string(), "validateForm".to_string()],
            mappings: String::new(),
        };
        assert_eq!(
            SourceMapProcessor::deobfuscate_name(&sm, 0),
            Some("handleSubmit")
        );
        assert_eq!(
            SourceMapProcessor::deobfuscate_name(&sm, 1),
            Some("validateForm")
        );
        assert!(SourceMapProcessor::deobfuscate_name(&sm, 99).is_none());
    }

    #[test]
    fn js_engine_config_defaults() {
        let config = JsEngineConfig::default();
        assert_eq!(config.max_execution_time_ms, 5000);
        assert_eq!(config.max_memory_bytes, 64 * 1024 * 1024);
        assert!(config.enable_network_intercept);
        assert!(config.enable_storage_simulation);
        assert!(config.enable_console_capture);
    }

    #[test]
    fn js_engine_config_builder() {
        let config = JsEngineConfig::default()
            .with_max_execution_time_ms(10000)
            .with_max_memory_bytes(128 * 1024 * 1024)
            .with_network_intercept(false)
            .with_storage_simulation(false)
            .with_console_capture(false);
        assert_eq!(config.max_execution_time_ms, 10000);
        assert_eq!(config.max_memory_bytes, 128 * 1024 * 1024);
        assert!(!config.enable_network_intercept);
        assert!(!config.enable_storage_simulation);
        assert!(!config.enable_console_capture);
    }

    #[test]
    fn http_method_display() {
        assert_eq!(HttpMethod::Get.to_string(), "GET");
        assert_eq!(HttpMethod::Post.to_string(), "POST");
        assert_eq!(HttpMethod::Put.to_string(), "PUT");
        assert_eq!(HttpMethod::Delete.to_string(), "DELETE");
        assert_eq!(HttpMethod::Patch.to_string(), "PATCH");
        assert_eq!(HttpMethod::Options.to_string(), "OPTIONS");
        assert_eq!(HttpMethod::Head.to_string(), "HEAD");
    }

    #[test]
    fn http_method_equality() {
        assert_eq!(HttpMethod::Get, HttpMethod::Get);
        assert_ne!(HttpMethod::Get, HttpMethod::Post);
    }

    #[test]
    fn js_engine_error_display() {
        assert_eq!(JsEngineError::EmptyScript.to_string(), "empty script");
        assert!(JsEngineError::ExecutionTimeout(5000)
            .to_string()
            .contains("5000"));
        assert!(JsEngineError::MemoryExceeded(1024)
            .to_string()
            .contains("1024"));
        assert!(JsEngineError::ParseError("unexpected token".to_string())
            .to_string()
            .contains("unexpected token"));
    }

    #[test]
    fn js_engine_dom_mut_access() {
        let mut engine = default_engine();
        engine.dom_mut().add_element(
            "test",
            SimulatedDomElement {
                tag: "div".to_string(),
                id: Some("test".to_string()),
                attributes: HashMap::new(),
                inner_text: "content".to_string(),
            },
        );
        assert_eq!(engine.dom_mut().element_count(), 1);
    }

    #[test]
    fn js_engine_storage_mut_access() {
        let mut engine = default_engine();
        engine.storage_mut().local_set("key", "val");
        assert_eq!(engine.storage_mut().local_get("key").unwrap(), "val");
    }

    #[test]
    fn extract_endpoints_with_api_prefix() {
        let engine = default_engine();
        let script = r#"const url = "/api/v3/resources";"#;
        let urls = engine.extract_endpoints(script);
        assert!(urls.iter().any(|u| u.contains("/api/v3/resources")));
    }

    #[test]
    fn intercepted_request_body_captured() {
        let mut engine = default_engine();
        let script = r#"fetch("/api/submit", { method: "POST", body: JSON.stringify("data") })"#;
        let result = engine.execute(script).unwrap();
        let req = &result.intercepted_requests[0];
        assert!(req.body.is_some());
    }
}
