use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocType {
    OpenApiJson,
    OpenApiYaml,
    SwaggerUi,
    GraphqlPlayground,
    GraphiQl,
    GraphqlVoyager,
    PostmanCollection,
    Wsdl,
    Wadl,
    GrpcReflection,
    Redoc,
    RapiDoc,
    AsyncApi,
    ApiBluePrint,
}

impl std::fmt::Display for DocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::OpenApiJson => "openapi_json",
            Self::OpenApiYaml => "openapi_yaml",
            Self::SwaggerUi => "swagger_ui",
            Self::GraphqlPlayground => "graphql_playground",
            Self::GraphiQl => "graphiql",
            Self::GraphqlVoyager => "graphql_voyager",
            Self::PostmanCollection => "postman_collection",
            Self::Wsdl => "wsdl",
            Self::Wadl => "wadl",
            Self::GrpcReflection => "grpc_reflection",
            Self::Redoc => "redoc",
            Self::RapiDoc => "rapidoc",
            Self::AsyncApi => "asyncapi",
            Self::ApiBluePrint => "api_blueprint",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocProbe {
    pub path: String,
    pub doc_type: DocType,
    pub description: String,
    pub detection_patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredDoc {
    pub url: String,
    pub doc_type: DocType,
    pub status_code: u16,
    pub content_type: Option<String>,
    pub swagger_version: Option<String>,
    pub api_title: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DocDiscoveryReport {
    pub probes_sent: usize,
    pub discovered: Vec<DiscoveredDoc>,
    pub undiscovered_types: Vec<DocType>,
}

pub struct ApiDocDiscovery {
    base_url: String,
    custom_prefixes: Vec<String>,
}

impl ApiDocDiscovery {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            custom_prefixes: Vec::new(),
        }
    }

    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.custom_prefixes.push(prefix.to_string());
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn generate_probes(&self) -> Vec<DocProbe> {
        let mut probes = Vec::new();

        probes.extend(self.openapi_probes());
        probes.extend(self.swagger_ui_probes());
        probes.extend(self.graphql_probes());
        probes.extend(self.postman_probes());
        probes.extend(self.wsdl_wadl_probes());
        probes.extend(self.grpc_probes());
        probes.extend(self.redoc_rapidoc_probes());
        probes.extend(self.asyncapi_probes());

        if !self.custom_prefixes.is_empty() {
            probes.extend(self.custom_prefix_probes());
        }

        probes
    }

    fn openapi_probes(&self) -> Vec<DocProbe> {
        let paths = vec![
            "/openapi.json",
            "/openapi.yaml",
            "/openapi.yml",
            "/api-docs",
            "/api-docs.json",
            "/api/openapi.json",
            "/api/openapi.yaml",
            "/v1/openapi.json",
            "/v2/openapi.json",
            "/v3/openapi.json",
            "/api/v1/openapi.json",
            "/api/v2/openapi.json",
            "/api/v3/openapi.json",
            "/swagger.json",
            "/swagger.yaml",
            "/api/swagger.json",
            "/v1/swagger.json",
            "/v2/swagger.json",
            "/api/v1/swagger.json",
            "/api/v2/swagger.json",
            "/.well-known/openapi.json",
        ];

        paths
            .into_iter()
            .map(|p| {
                let doc_type = if p.ends_with(".yaml") || p.ends_with(".yml") {
                    DocType::OpenApiYaml
                } else {
                    DocType::OpenApiJson
                };
                DocProbe {
                    path: p.to_string(),
                    doc_type,
                    description: format!("OpenAPI/Swagger specification at {p}"),
                    detection_patterns: vec![
                        "\"openapi\"".to_string(),
                        "\"swagger\"".to_string(),
                        "\"paths\"".to_string(),
                    ],
                }
            })
            .collect()
    }

    fn swagger_ui_probes(&self) -> Vec<DocProbe> {
        let paths = vec![
            "/swagger",
            "/swagger-ui",
            "/swagger-ui.html",
            "/swagger-ui/index.html",
            "/api/swagger-ui",
            "/api/swagger-ui.html",
            "/docs",
            "/api/docs",
            "/api-explorer",
            "/developer/docs",
        ];

        paths
            .into_iter()
            .map(|p| DocProbe {
                path: p.to_string(),
                doc_type: DocType::SwaggerUi,
                description: format!("Swagger UI at {p}"),
                detection_patterns: vec![
                    "swagger-ui".to_string(),
                    "SwaggerUIBundle".to_string(),
                    "swagger-ui-bundle".to_string(),
                ],
            })
            .collect()
    }

    fn graphql_probes(&self) -> Vec<DocProbe> {
        let mut probes = Vec::new();

        let playground_paths = vec![
            "/graphql",
            "/graphql/playground",
            "/api/graphql",
            "/v1/graphql",
            "/playground",
        ];

        for p in &playground_paths {
            probes.push(DocProbe {
                path: p.to_string(),
                doc_type: DocType::GraphqlPlayground,
                description: format!("GraphQL Playground at {p}"),
                detection_patterns: vec![
                    "graphql-playground".to_string(),
                    "GraphQLPlayground".to_string(),
                    "playground".to_string(),
                ],
            });
        }

        let graphiql_paths = vec!["/graphiql", "/api/graphiql", "/graphql/graphiql"];

        for p in &graphiql_paths {
            probes.push(DocProbe {
                path: p.to_string(),
                doc_type: DocType::GraphiQl,
                description: format!("GraphiQL at {p}"),
                detection_patterns: vec!["graphiql".to_string(), "GraphiQL".to_string()],
            });
        }

        let voyager_paths = vec!["/voyager", "/graphql/voyager"];
        for p in &voyager_paths {
            probes.push(DocProbe {
                path: p.to_string(),
                doc_type: DocType::GraphqlVoyager,
                description: format!("GraphQL Voyager at {p}"),
                detection_patterns: vec![
                    "graphql-voyager".to_string(),
                    "GraphQLVoyager".to_string(),
                ],
            });
        }

        probes
    }

    fn postman_probes(&self) -> Vec<DocProbe> {
        let paths = vec![
            "/postman",
            "/postman.json",
            "/api/postman",
            "/collection.json",
            "/api/collection.json",
            "/.postman/collection.json",
        ];

        paths
            .into_iter()
            .map(|p| DocProbe {
                path: p.to_string(),
                doc_type: DocType::PostmanCollection,
                description: format!("Postman collection at {p}"),
                detection_patterns: vec![
                    "\"info\"".to_string(),
                    "\"item\"".to_string(),
                    "postman".to_string(),
                ],
            })
            .collect()
    }

    fn wsdl_wadl_probes(&self) -> Vec<DocProbe> {
        let mut probes = Vec::new();

        let wsdl_paths = vec![
            "/service?wsdl",
            "/ws?wsdl",
            "/soap?wsdl",
            "/api?wsdl",
            "/services?wsdl",
            "/webservice?wsdl",
        ];

        for p in &wsdl_paths {
            probes.push(DocProbe {
                path: p.to_string(),
                doc_type: DocType::Wsdl,
                description: format!("WSDL service definition at {p}"),
                detection_patterns: vec![
                    "wsdl:definitions".to_string(),
                    "wsdl:service".to_string(),
                    "xmlns:wsdl".to_string(),
                ],
            });
        }

        let wadl_paths = vec!["/application.wadl", "/api/application.wadl"];

        for p in &wadl_paths {
            probes.push(DocProbe {
                path: p.to_string(),
                doc_type: DocType::Wadl,
                description: format!("WADL service definition at {p}"),
                detection_patterns: vec!["application".to_string(), "wadl".to_string()],
            });
        }

        probes
    }

    fn grpc_probes(&self) -> Vec<DocProbe> {
        vec![DocProbe {
            path: "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo".to_string(),
            doc_type: DocType::GrpcReflection,
            description: "gRPC reflection service endpoint".to_string(),
            detection_patterns: vec!["grpc".to_string(), "reflection".to_string()],
        }]
    }

    fn redoc_rapidoc_probes(&self) -> Vec<DocProbe> {
        let mut probes = Vec::new();

        let redoc_paths = vec!["/redoc", "/api/redoc", "/docs/redoc"];
        for p in &redoc_paths {
            probes.push(DocProbe {
                path: p.to_string(),
                doc_type: DocType::Redoc,
                description: format!("ReDoc API documentation at {p}"),
                detection_patterns: vec!["redoc".to_string(), "Redoc".to_string()],
            });
        }

        let rapidoc_paths = vec!["/rapidoc", "/api/rapidoc"];
        for p in &rapidoc_paths {
            probes.push(DocProbe {
                path: p.to_string(),
                doc_type: DocType::RapiDoc,
                description: format!("RapiDoc API documentation at {p}"),
                detection_patterns: vec!["rapi-doc".to_string(), "RapiDoc".to_string()],
            });
        }

        probes
    }

    fn asyncapi_probes(&self) -> Vec<DocProbe> {
        let paths = vec!["/asyncapi.json", "/asyncapi.yaml", "/api/asyncapi.json"];

        paths
            .into_iter()
            .map(|p| DocProbe {
                path: p.to_string(),
                doc_type: DocType::AsyncApi,
                description: format!("AsyncAPI specification at {p}"),
                detection_patterns: vec!["asyncapi".to_string(), "channels".to_string()],
            })
            .collect()
    }

    fn custom_prefix_probes(&self) -> Vec<DocProbe> {
        let suffixes = vec![
            "/openapi.json",
            "/swagger.json",
            "/docs",
            "/swagger-ui.html",
            "/graphql",
        ];

        let mut probes = Vec::new();
        for prefix in &self.custom_prefixes {
            let prefix = prefix.trim_end_matches('/');
            for suffix in &suffixes {
                probes.push(DocProbe {
                    path: format!("{prefix}{suffix}"),
                    doc_type: DocType::OpenApiJson,
                    description: format!("Custom prefix probe at {prefix}{suffix}"),
                    detection_patterns: vec![
                        "\"openapi\"".to_string(),
                        "\"swagger\"".to_string(),
                        "swagger-ui".to_string(),
                    ],
                });
            }
        }

        probes
    }

    pub fn classify_response(
        &self,
        probe: &DocProbe,
        status_code: u16,
        content_type: Option<&str>,
        body: &str,
    ) -> Option<DiscoveredDoc> {
        if status_code >= 400 {
            return None;
        }

        let matches_pattern = probe
            .detection_patterns
            .iter()
            .any(|pattern| body.contains(pattern));

        if !matches_pattern && status_code != 200 {
            return None;
        }

        if !matches_pattern {
            return None;
        }

        let swagger_version = Self::detect_swagger_version(body);
        let api_title = Self::extract_api_title(body);

        Some(DiscoveredDoc {
            url: format!("{}{}", self.base_url, probe.path),
            doc_type: probe.doc_type.clone(),
            status_code,
            content_type: content_type.map(String::from),
            swagger_version,
            api_title,
        })
    }

    fn detect_swagger_version(body: &str) -> Option<String> {
        if body.contains("\"openapi\":\"3.1") || body.contains("\"openapi\": \"3.1") {
            Some("OpenAPI 3.1".to_string())
        } else if body.contains("\"openapi\":\"3.0") || body.contains("\"openapi\": \"3.0") {
            Some("OpenAPI 3.0".to_string())
        } else if body.contains("\"swagger\":\"2.0") || body.contains("\"swagger\": \"2.0") {
            Some("Swagger 2.0".to_string())
        } else {
            None
        }
    }

    fn extract_api_title(body: &str) -> Option<String> {
        let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
        parsed
            .get("info")
            .and_then(|info| info.get("title"))
            .and_then(|t| t.as_str())
            .map(String::from)
    }
}
