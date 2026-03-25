#[cfg(test)]
mod tests {
    use crate::api_doc_discovery::{ApiDocDiscovery, DocType};

    #[test]
    fn generates_probes_for_all_doc_types() {
        let disco = ApiDocDiscovery::new("http://localhost:3000");
        let probes = disco.generate_probes();

        assert!(probes.len() >= 50);

        let doc_types: Vec<_> = probes.iter().map(|p| &p.doc_type).collect();
        assert!(doc_types.contains(&&DocType::OpenApiJson));
        assert!(doc_types.contains(&&DocType::OpenApiYaml));
        assert!(doc_types.contains(&&DocType::SwaggerUi));
        assert!(doc_types.contains(&&DocType::GraphqlPlayground));
        assert!(doc_types.contains(&&DocType::GraphiQl));
        assert!(doc_types.contains(&&DocType::GraphqlVoyager));
        assert!(doc_types.contains(&&DocType::PostmanCollection));
        assert!(doc_types.contains(&&DocType::Wsdl));
        assert!(doc_types.contains(&&DocType::Wadl));
        assert!(doc_types.contains(&&DocType::GrpcReflection));
        assert!(doc_types.contains(&&DocType::Redoc));
        assert!(doc_types.contains(&&DocType::RapiDoc));
        assert!(doc_types.contains(&&DocType::AsyncApi));
    }

    #[test]
    fn openapi_probes_include_versioned_paths() {
        let disco = ApiDocDiscovery::new("http://localhost:3000");
        let probes = disco.generate_probes();

        let openapi_paths: Vec<&str> = probes
            .iter()
            .filter(|p| p.doc_type == DocType::OpenApiJson)
            .map(|p| p.path.as_str())
            .collect();

        assert!(openapi_paths.contains(&"/v1/openapi.json"));
        assert!(openapi_paths.contains(&"/v2/openapi.json"));
        assert!(openapi_paths.contains(&"/api/v1/openapi.json"));
    }

    #[test]
    fn swagger_ui_probes_include_standard_paths() {
        let disco = ApiDocDiscovery::new("http://localhost:3000");
        let probes = disco.generate_probes();

        let swagger_paths: Vec<&str> = probes
            .iter()
            .filter(|p| p.doc_type == DocType::SwaggerUi)
            .map(|p| p.path.as_str())
            .collect();

        assert!(swagger_paths.contains(&"/swagger-ui.html"));
        assert!(swagger_paths.contains(&"/swagger-ui/index.html"));
        assert!(swagger_paths.contains(&"/docs"));
    }

    #[test]
    fn graphql_probes_include_playground_and_graphiql() {
        let disco = ApiDocDiscovery::new("http://localhost:3000");
        let probes = disco.generate_probes();

        let graphql_playground: Vec<_> = probes
            .iter()
            .filter(|p| p.doc_type == DocType::GraphqlPlayground)
            .collect();
        assert!(graphql_playground.len() >= 3);

        let graphiql: Vec<_> = probes
            .iter()
            .filter(|p| p.doc_type == DocType::GraphiQl)
            .collect();
        assert!(graphiql.len() >= 2);
    }

    #[test]
    fn wsdl_probes_for_legacy_soap() {
        let disco = ApiDocDiscovery::new("http://localhost:3000");
        let probes = disco.generate_probes();

        let wsdl: Vec<_> = probes
            .iter()
            .filter(|p| p.doc_type == DocType::Wsdl)
            .collect();
        assert!(wsdl.len() >= 4);
        assert!(wsdl.iter().any(|p| p.path.contains("?wsdl")));
    }

    #[test]
    fn grpc_reflection_probe_exists() {
        let disco = ApiDocDiscovery::new("http://localhost:3000");
        let probes = disco.generate_probes();

        let grpc: Vec<_> = probes
            .iter()
            .filter(|p| p.doc_type == DocType::GrpcReflection)
            .collect();
        assert_eq!(grpc.len(), 1);
        assert!(grpc[0].path.contains("reflection"));
    }

    #[test]
    fn custom_prefix_adds_extra_probes() {
        let disco = ApiDocDiscovery::new("http://localhost:3000")
            .with_prefix("/internal")
            .with_prefix("/private");
        let probes = disco.generate_probes();

        let custom: Vec<_> = probes
            .iter()
            .filter(|p| p.path.starts_with("/internal") || p.path.starts_with("/private"))
            .collect();
        assert!(custom.len() >= 10);
        assert!(custom.iter().any(|p| p.path == "/internal/openapi.json"));
        assert!(custom.iter().any(|p| p.path == "/private/swagger.json"));
    }

    #[test]
    fn classify_valid_openapi_response() {
        let disco = ApiDocDiscovery::new("http://localhost:3000");
        let probes = disco.generate_probes();
        let probe = probes.iter().find(|p| p.path == "/openapi.json").unwrap();

        let body =
            r#"{"openapi": "3.0.3", "info": {"title": "My API", "version": "1.0"}, "paths": {}}"#;
        let result = disco.classify_response(probe, 200, Some("application/json"), body);

        assert!(result.is_some());
        let doc = result.unwrap();
        assert_eq!(doc.doc_type, DocType::OpenApiJson);
        assert_eq!(doc.swagger_version, Some("OpenAPI 3.0".to_string()));
        assert_eq!(doc.api_title, Some("My API".to_string()));
        assert_eq!(doc.url, "http://localhost:3000/openapi.json");
    }

    #[test]
    fn classify_swagger_20_response() {
        let disco = ApiDocDiscovery::new("http://localhost:3000");
        let probes = disco.generate_probes();
        let probe = probes.iter().find(|p| p.path == "/swagger.json").unwrap();

        let body = r#"{"swagger": "2.0", "info": {"title": "Legacy API"}, "paths": {}}"#;
        let result = disco.classify_response(probe, 200, Some("application/json"), body);

        assert!(result.is_some());
        let doc = result.unwrap();
        assert_eq!(doc.swagger_version, Some("Swagger 2.0".to_string()));
        assert_eq!(doc.api_title, Some("Legacy API".to_string()));
    }

    #[test]
    fn classify_404_returns_none() {
        let disco = ApiDocDiscovery::new("http://localhost:3000");
        let probes = disco.generate_probes();
        let probe = probes.iter().find(|p| p.path == "/openapi.json").unwrap();

        let result = disco.classify_response(probe, 404, None, "Not Found");
        assert!(result.is_none());
    }

    #[test]
    fn classify_200_no_pattern_match_returns_none() {
        let disco = ApiDocDiscovery::new("http://localhost:3000");
        let probes = disco.generate_probes();
        let probe = probes.iter().find(|p| p.path == "/openapi.json").unwrap();

        let result = disco.classify_response(probe, 200, Some("text/html"), "<html>Welcome</html>");
        assert!(result.is_none());
    }

    #[test]
    fn classify_swagger_ui_html_response() {
        let disco = ApiDocDiscovery::new("http://localhost:3000");
        let probes = disco.generate_probes();
        let probe = probes
            .iter()
            .find(|p| p.path == "/swagger-ui.html")
            .unwrap();

        let body = "<html><head><script src='swagger-ui-bundle.js'></script></head><body><div id='swagger-ui'></div></body></html>";
        let result = disco.classify_response(probe, 200, Some("text/html"), body);

        assert!(result.is_some());
        let doc = result.unwrap();
        assert_eq!(doc.doc_type, DocType::SwaggerUi);
    }

    #[test]
    fn base_url_trailing_slash_stripped() {
        let disco = ApiDocDiscovery::new("http://localhost:3000/");
        assert_eq!(disco.base_url(), "http://localhost:3000");
    }

    #[test]
    fn all_probes_have_detection_patterns() {
        let disco = ApiDocDiscovery::new("http://localhost:3000");
        let probes = disco.generate_probes();

        for probe in &probes {
            assert!(
                !probe.detection_patterns.is_empty(),
                "Probe {} has no detection patterns",
                probe.path
            );
        }
    }

    #[test]
    fn postman_collection_probes_exist() {
        let disco = ApiDocDiscovery::new("http://localhost:3000");
        let probes = disco.generate_probes();

        let postman: Vec<_> = probes
            .iter()
            .filter(|p| p.doc_type == DocType::PostmanCollection)
            .collect();
        assert!(postman.len() >= 4);
        assert!(postman.iter().any(|p| p.path.contains("postman")));
    }

    #[test]
    fn openapi_31_version_detection() {
        let disco = ApiDocDiscovery::new("http://localhost:3000");
        let probes = disco.generate_probes();
        let probe = probes.iter().find(|p| p.path == "/openapi.json").unwrap();

        let body = r#"{"openapi":"3.1.0","info":{"title":"New API","version":"1.0"},"paths":{}}"#;
        let result = disco.classify_response(probe, 200, Some("application/json"), body);

        assert!(result.is_some());
        assert_eq!(
            result.unwrap().swagger_version,
            Some("OpenAPI 3.1".to_string())
        );
    }
}
