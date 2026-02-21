use std::collections::HashMap;

use aegis_enumeration::auth_flow::{
    AuthFlowVulnerability, detect_insecure_cookie, detect_session_fixation, detect_weak_session_id,
    render_template,
};
use aegis_enumeration::auth_matrix::{
    AnomalyType, AuthorizationMatrix, Credential, EndpointAccess, PrivilegeLevel,
};
use aegis_enumeration::graphql_discovery::{
    DiscoveryMethod, discover_common_fields, discover_from_error_responses, merge_discovery_results,
};
use aegis_enumeration::introspection::{
    ParameterLocation, parse_graphql_introspection, parse_graphql_sdl, parse_openapi_json,
};
use aegis_enumeration::route_parser::{Framework, HttpMethod, parse_routes_from_source};
use aegis_test_support::fixture_server::TestServer;
use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;

// ---------------------------------------------------------------------------
// Fixture data
// ---------------------------------------------------------------------------

fn fixture_openapi_spec() -> &'static str {
    r#"{
        "openapi": "3.0.0",
        "info": { "title": "Pet Store", "version": "1.0.0" },
        "security": [{ "bearerAuth": [] }],
        "paths": {
            "/pets": {
                "get": {
                    "summary": "List all pets",
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "required": false,
                            "schema": { "type": "integer" }
                        }
                    ],
                    "responses": {
                        "200": { "description": "A list of pets" }
                    }
                },
                "post": {
                    "summary": "Create a pet",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": { "type": "string" },
                                        "tag": { "type": "string" },
                                        "age": { "type": "integer" }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": { "description": "Created" },
                        "400": { "description": "Bad request" }
                    }
                }
            },
            "/pets/{petId}": {
                "get": {
                    "summary": "Get a pet by ID",
                    "parameters": [
                        {
                            "name": "petId",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "integer" }
                        },
                        {
                            "name": "X-Request-Id",
                            "in": "header",
                            "required": false,
                            "schema": { "type": "string" }
                        }
                    ],
                    "responses": {
                        "200": { "description": "A pet" },
                        "404": { "description": "Not found" }
                    }
                }
            }
        }
    }"#
}

fn fixture_graphql_introspection_response() -> &'static str {
    r#"{
        "data": {
            "__schema": {
                "queryType": { "name": "Query" },
                "mutationType": { "name": "Mutation" },
                "subscriptionType": null,
                "types": [
                    {
                        "name": "Query",
                        "kind": "OBJECT",
                        "fields": [
                            {
                                "name": "users",
                                "args": [
                                    { "name": "limit", "type": { "kind": "SCALAR", "name": "Int", "ofType": null } }
                                ],
                                "type": { "kind": "LIST", "name": null, "ofType": { "kind": "OBJECT", "name": "User", "ofType": null } }
                            },
                            {
                                "name": "user",
                                "args": [
                                    { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } } }
                                ],
                                "type": { "kind": "OBJECT", "name": "User", "ofType": null }
                            }
                        ]
                    },
                    {
                        "name": "Mutation",
                        "kind": "OBJECT",
                        "fields": [
                            {
                                "name": "createUser",
                                "args": [
                                    { "name": "input", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "INPUT_OBJECT", "name": "CreateUserInput", "ofType": null } } }
                                ],
                                "type": { "kind": "OBJECT", "name": "User", "ofType": null }
                            }
                        ]
                    },
                    {
                        "name": "User",
                        "kind": "OBJECT",
                        "fields": [
                            {
                                "name": "id",
                                "args": [],
                                "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } }
                            },
                            {
                                "name": "name",
                                "args": [],
                                "type": { "kind": "SCALAR", "name": "String", "ofType": null }
                            }
                        ]
                    }
                ]
            }
        }
    }"#
}

fn fixture_graphql_sdl() -> &'static str {
    r#"
        type Query {
            users(limit: Int): [User]
            user(id: ID!): User
            health: String
        }
        type Mutation {
            createUser(input: CreateUserInput!): User
            deleteUser(id: ID!): Boolean
        }
        type User {
            id: ID!
            name: String
            email: String
        }
        input CreateUserInput {
            name: String!
            email: String!
        }
    "#
}

// ---------------------------------------------------------------------------
// Test 44: openapi_parse_from_live_server
// ---------------------------------------------------------------------------

#[tokio::test]
async fn openapi_parse_from_live_server() {
    let spec = fixture_openapi_spec();
    let router = Router::new().route(
        "/openapi.json",
        get(move || async move { (StatusCode::OK, spec) }),
    );
    let server = TestServer::new(router).await;

    let resp = reqwest::get(format!("{}/openapi.json", server.url()))
        .await
        .expect("request failed");
    let body = resp.text().await.expect("failed to read body");
    let endpoints = parse_openapi_json(&body).expect("failed to parse OpenAPI spec");

    assert_eq!(endpoints.len(), 3);

    let get_pets = endpoints
        .iter()
        .find(|e| e.path == "/pets" && e.method == "GET")
        .expect("GET /pets not found");
    assert_eq!(get_pets.description, Some("List all pets".to_string()));

    let post_pets = endpoints
        .iter()
        .find(|e| e.path == "/pets" && e.method == "POST")
        .expect("POST /pets not found");
    assert_eq!(post_pets.description, Some("Create a pet".to_string()));

    let get_pet_by_id = endpoints
        .iter()
        .find(|e| e.path == "/pets/{petId}")
        .expect("GET /pets/{petId} not found");
    assert_eq!(
        get_pet_by_id.description,
        Some("Get a pet by ID".to_string())
    );
}

// ---------------------------------------------------------------------------
// Test 45: openapi_extracts_parameters
// ---------------------------------------------------------------------------

#[tokio::test]
async fn openapi_extracts_parameters() {
    let spec = fixture_openapi_spec();
    let router = Router::new().route(
        "/openapi.json",
        get(move || async move { (StatusCode::OK, spec) }),
    );
    let server = TestServer::new(router).await;

    let resp = reqwest::get(format!("{}/openapi.json", server.url()))
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    let endpoints = parse_openapi_json(&body).unwrap();

    let get_pets = endpoints
        .iter()
        .find(|e| e.path == "/pets" && e.method == "GET")
        .unwrap();
    assert_eq!(get_pets.parameters.len(), 1);
    assert_eq!(get_pets.parameters[0].name, "limit");
    assert_eq!(get_pets.parameters[0].location, ParameterLocation::Query);
    assert_eq!(get_pets.parameters[0].param_type, "integer");
    assert!(!get_pets.parameters[0].required);

    let get_pet = endpoints
        .iter()
        .find(|e| e.path == "/pets/{petId}")
        .unwrap();
    let path_param = get_pet
        .parameters
        .iter()
        .find(|p| p.location == ParameterLocation::Path)
        .expect("path parameter missing");
    assert_eq!(path_param.name, "petId");
    assert!(path_param.required);

    let header_param = get_pet
        .parameters
        .iter()
        .find(|p| p.location == ParameterLocation::Header)
        .expect("header parameter missing");
    assert_eq!(header_param.name, "X-Request-Id");
    assert!(!header_param.required);
}

// ---------------------------------------------------------------------------
// Test 46: openapi_extracts_request_body
// ---------------------------------------------------------------------------

#[tokio::test]
async fn openapi_extracts_request_body() {
    let spec = fixture_openapi_spec();
    let router = Router::new().route(
        "/openapi.json",
        get(move || async move { (StatusCode::OK, spec) }),
    );
    let server = TestServer::new(router).await;

    let resp = reqwest::get(format!("{}/openapi.json", server.url()))
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    let endpoints = parse_openapi_json(&body).unwrap();

    let post_pets = endpoints
        .iter()
        .find(|e| e.path == "/pets" && e.method == "POST")
        .unwrap();

    let body_params: Vec<_> = post_pets
        .parameters
        .iter()
        .filter(|p| p.location == ParameterLocation::Body)
        .collect();
    assert_eq!(body_params.len(), 3);

    let mut names: Vec<&str> = body_params.iter().map(|p| p.name.as_str()).collect();
    names.sort();
    assert_eq!(names, vec!["age", "name", "tag"]);

    let age_param = body_params.iter().find(|p| p.name == "age").unwrap();
    assert_eq!(age_param.param_type, "integer");

    let name_param = body_params.iter().find(|p| p.name == "name").unwrap();
    assert_eq!(name_param.param_type, "string");

    for p in &body_params {
        assert!(p.required);
    }

    assert!(
        post_pets
            .request_content_types
            .contains(&"application/json".to_string())
    );
}

// ---------------------------------------------------------------------------
// Test 47: graphql_introspection_from_live_server
// ---------------------------------------------------------------------------

#[tokio::test]
async fn graphql_introspection_from_live_server() {
    let introspection_json = fixture_graphql_introspection_response();
    let router = Router::new().route(
        "/graphql",
        get(move || async move { (StatusCode::OK, introspection_json) }),
    );
    let server = TestServer::new(router).await;

    let resp = reqwest::get(format!("{}/graphql", server.url()))
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    let endpoints = parse_graphql_introspection(&body).unwrap();

    let queries: Vec<_> = endpoints
        .iter()
        .filter(|e| {
            e.description
                .as_ref()
                .is_some_and(|d| d.starts_with("Query:"))
        })
        .collect();
    assert_eq!(queries.len(), 2);

    let mutations: Vec<_> = endpoints
        .iter()
        .filter(|e| {
            e.description
                .as_ref()
                .is_some_and(|d| d.starts_with("Mutation:"))
        })
        .collect();
    assert_eq!(mutations.len(), 1);

    let users_query = endpoints
        .iter()
        .find(|e| e.description.as_ref().is_some_and(|d| d.contains("users")))
        .unwrap();
    assert_eq!(users_query.path, "/graphql");
    assert_eq!(users_query.method, "POST");
    assert_eq!(users_query.parameters[0].name, "limit");
    assert_eq!(users_query.response_type, Some("[User]".to_string()));

    let user_query = endpoints
        .iter()
        .find(|e| e.description.as_ref().is_some_and(|d| d == "Query: user"))
        .unwrap();
    assert_eq!(user_query.parameters[0].name, "id");
    assert_eq!(user_query.parameters[0].param_type, "ID!");
    assert!(user_query.parameters[0].required);
}

// ---------------------------------------------------------------------------
// Test 48: graphql_sdl_parse_from_live_server
// ---------------------------------------------------------------------------

#[tokio::test]
async fn graphql_sdl_parse_from_live_server() {
    let sdl = fixture_graphql_sdl();
    let router = Router::new().route(
        "/graphql/sdl",
        get(move || async move { (StatusCode::OK, sdl) }),
    );
    let server = TestServer::new(router).await;

    let resp = reqwest::get(format!("{}/graphql/sdl", server.url()))
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    let endpoints = parse_graphql_sdl(&body).unwrap();

    let queries: Vec<_> = endpoints
        .iter()
        .filter(|e| {
            e.description
                .as_ref()
                .is_some_and(|d| d.starts_with("Query:"))
        })
        .collect();
    assert_eq!(queries.len(), 3);

    let mutations: Vec<_> = endpoints
        .iter()
        .filter(|e| {
            e.description
                .as_ref()
                .is_some_and(|d| d.starts_with("Mutation:"))
        })
        .collect();
    assert_eq!(mutations.len(), 2);

    let health = endpoints
        .iter()
        .find(|e| e.description.as_ref().is_some_and(|d| d.contains("health")))
        .unwrap();
    assert!(health.parameters.is_empty());
    assert_eq!(health.response_type, Some("String".to_string()));
}

// ---------------------------------------------------------------------------
// Test 49: graphql_fallback_discovery_error_based
// ---------------------------------------------------------------------------

#[tokio::test]
async fn graphql_fallback_discovery_error_based() {
    let error_body = r#"{
        "errors": [
            { "message": "Cannot query field \"users\" on type \"Query\". Did you mean \"user\"?" },
            { "message": "Cannot query field \"posts\" on type \"Query\"" }
        ]
    }"#;

    let router = Router::new().route(
        "/graphql",
        get(move || async move { (StatusCode::OK, error_body) }),
    );
    let server = TestServer::new(router).await;

    let resp = reqwest::get(format!("{}/graphql", server.url()))
        .await
        .unwrap();
    let body = resp.text().await.unwrap();

    let result = discover_from_error_responses(&[&body]);
    assert_eq!(result.method, DiscoveryMethod::ErrorBased);
    assert!((result.confidence - 0.6).abs() < f64::EPSILON);

    let descriptions: Vec<String> = result
        .endpoints
        .iter()
        .filter_map(|e| e.description.clone())
        .collect();
    assert!(descriptions.iter().any(|d| d.contains("posts")));
    assert!(descriptions.iter().any(|d| d.contains("user")));
    assert!(descriptions.iter().any(|d| d.contains("users")));
}

// ---------------------------------------------------------------------------
// Test 50: graphql_fallback_discovery_common_fields
// ---------------------------------------------------------------------------

#[tokio::test]
async fn graphql_fallback_discovery_common_fields() {
    let error_body = r#"{ "errors": [{ "message": "Introspection is disabled" }] }"#;

    let router = Router::new().route(
        "/graphql",
        get(move || async move { (StatusCode::OK, error_body) }),
    );
    let server = TestServer::new(router).await;

    let resp = reqwest::get(format!("{}/graphql", server.url()))
        .await
        .unwrap();
    let _body = resp.text().await.unwrap();

    let result = discover_common_fields();
    assert_eq!(result.method, DiscoveryMethod::CommonFieldBrute);
    assert!((result.confidence - 0.3).abs() < f64::EPSILON);
    assert!(!result.endpoints.is_empty());

    let has_users = result
        .endpoints
        .iter()
        .any(|e| e.description.as_ref().is_some_and(|d| d.contains("users")));
    assert!(has_users);

    let has_login = result
        .endpoints
        .iter()
        .any(|e| e.description.as_ref().is_some_and(|d| d.contains("login")));
    assert!(has_login);
}

// ---------------------------------------------------------------------------
// Test 51: graphql_fallback_combined_strategy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn graphql_fallback_combined_strategy() {
    let error_resp = r#"{
        "errors": [
            { "message": "Cannot query field \"customField\" on type \"Query\"" }
        ]
    }"#;

    let router = Router::new().route(
        "/graphql",
        get(move || async move { (StatusCode::OK, error_resp) }),
    );
    let server = TestServer::new(router).await;

    let resp = reqwest::get(format!("{}/graphql", server.url()))
        .await
        .unwrap();
    let body = resp.text().await.unwrap();

    let error_result = discover_from_error_responses(&[&body]);
    let common_result = discover_common_fields();

    let error_count = error_result.endpoints.len();
    let common_count = common_result.endpoints.len();

    let merged = merge_discovery_results(&[error_result, common_result]);
    assert_eq!(merged.method, DiscoveryMethod::Combined);
    assert!(merged.endpoints.len() >= error_count);
    assert!(merged.endpoints.len() >= common_count);
    assert!(merged.endpoints.len() <= error_count + common_count);
    assert!((merged.confidence - 0.6).abs() < f64::EPSILON);

    let has_custom = merged.endpoints.iter().any(|e| {
        e.description
            .as_ref()
            .is_some_and(|d| d.contains("customField"))
    });
    assert!(has_custom);
}

// ---------------------------------------------------------------------------
// Test 52: route_parser_express_real_source
// ---------------------------------------------------------------------------

#[test]
fn route_parser_express_real_source() {
    let source = r#"
const express = require('express');
const app = express();

app.get('/api/users', listUsers);
app.post('/api/users', createUser);
app.get('/api/users/:id', getUser);
app.put('/api/users/:id', updateUser);
app.delete('/api/users/:id', deleteUser);
app.patch('/api/users/:id/role', patchRole);
app.use('/api/admin', adminRouter);

router.get('/items', listItems);
router.post('/items', createItem);

app.listen(3000);
"#;
    let routes = parse_routes_from_source(source, "server.js", Framework::Express).unwrap();

    assert_eq!(routes.len(), 9);
    assert_eq!(routes[0].path_pattern, "/api/users");
    assert_eq!(routes[0].http_method, HttpMethod::Get);
    assert_eq!(routes[0].handler_name, Some("listUsers".to_string()));
    assert_eq!(routes[0].framework, Framework::Express);
    assert_eq!(routes[0].source_file, "server.js");
    assert!(routes[0].line_number.is_some());

    let put = routes.iter().find(|r| r.http_method == HttpMethod::Put);
    assert!(put.is_some());
    assert_eq!(put.unwrap().path_pattern, "/api/users/:id");

    let use_route = routes
        .iter()
        .find(|r| r.http_method == HttpMethod::Any)
        .unwrap();
    assert_eq!(use_route.path_pattern, "/api/admin");
}

// ---------------------------------------------------------------------------
// Test 53: route_parser_flask_real_source
// ---------------------------------------------------------------------------

#[test]
fn route_parser_flask_real_source() {
    let source = r#"
from flask import Flask
app = Flask(__name__)

@app.route('/login', methods=['GET', 'POST'])
def login():
    pass

@app.route('/dashboard')
def dashboard():
    pass

@app.get('/api/items')
def list_items():
    pass

@app.post('/api/items')
def create_item():
    pass

@app.delete('/api/items/<int:item_id>')
def delete_item(item_id):
    pass
"#;
    let routes = parse_routes_from_source(source, "app.py", Framework::Flask).unwrap();

    assert_eq!(routes.len(), 6);

    let login_routes: Vec<_> = routes
        .iter()
        .filter(|r| r.path_pattern == "/login")
        .collect();
    assert_eq!(login_routes.len(), 2);
    assert!(
        login_routes
            .iter()
            .any(|r| r.http_method == HttpMethod::Get)
    );
    assert!(
        login_routes
            .iter()
            .any(|r| r.http_method == HttpMethod::Post)
    );
    assert_eq!(login_routes[0].handler_name, Some("login".to_string()));

    let dashboard = routes
        .iter()
        .find(|r| r.path_pattern == "/dashboard")
        .unwrap();
    assert_eq!(dashboard.http_method, HttpMethod::Get);
    assert_eq!(dashboard.handler_name, Some("dashboard".to_string()));

    let delete = routes
        .iter()
        .find(|r| r.http_method == HttpMethod::Delete)
        .unwrap();
    assert_eq!(delete.path_pattern, "/api/items/<int:item_id>");
}

// ---------------------------------------------------------------------------
// Test 54: route_parser_fastapi_real_source
// ---------------------------------------------------------------------------

#[test]
fn route_parser_fastapi_real_source() {
    let source = r#"
from fastapi import FastAPI, APIRouter

app = FastAPI()
router = APIRouter()

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.post("/api/users")
async def create_user(user: UserCreate):
    pass

@app.put("/api/users/{user_id}")
async def update_user(user_id: int):
    pass

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int):
    pass

@router.get("/items")
async def list_items():
    pass

@router.patch("/items/{item_id}")
async def patch_item(item_id: int):
    pass
"#;
    let routes = parse_routes_from_source(source, "main.py", Framework::FastApi).unwrap();

    assert_eq!(routes.len(), 6);

    let health = routes.iter().find(|r| r.path_pattern == "/health").unwrap();
    assert_eq!(health.http_method, HttpMethod::Get);
    assert_eq!(health.handler_name, Some("health_check".to_string()));
    assert_eq!(health.framework, Framework::FastApi);

    let patch = routes
        .iter()
        .find(|r| r.http_method == HttpMethod::Patch)
        .unwrap();
    assert_eq!(patch.path_pattern, "/items/{item_id}");
    assert_eq!(patch.handler_name, Some("patch_item".to_string()));

    let create = routes
        .iter()
        .find(|r| r.path_pattern == "/api/users" && r.http_method == HttpMethod::Post)
        .unwrap();
    assert_eq!(create.handler_name, Some("create_user".to_string()));
}

// ---------------------------------------------------------------------------
// Test 55: route_parser_django_real_source
// ---------------------------------------------------------------------------

#[test]
fn route_parser_django_real_source() {
    let source = r#"
from django.urls import path
from . import views

urlpatterns = [
    path('users/', views.user_list),
    path('users/<int:pk>/', views.user_detail),
    path('posts/', views.post_list),
    path('admin/settings/', views.admin_settings),
]
"#;
    let routes = parse_routes_from_source(source, "urls.py", Framework::Django).unwrap();

    assert_eq!(routes.len(), 4);

    assert_eq!(routes[0].path_pattern, "/users/");
    assert_eq!(routes[0].http_method, HttpMethod::Any);
    assert_eq!(routes[0].handler_name, Some("views.user_list".to_string()));
    assert_eq!(routes[0].framework, Framework::Django);

    assert_eq!(routes[1].path_pattern, "/users/<int:pk>/");
    assert_eq!(
        routes[1].handler_name,
        Some("views.user_detail".to_string())
    );

    assert_eq!(routes[3].path_pattern, "/admin/settings/");
    assert_eq!(
        routes[3].handler_name,
        Some("views.admin_settings".to_string())
    );
}

// ---------------------------------------------------------------------------
// Test 56: route_parser_spring_real_source
// ---------------------------------------------------------------------------

#[test]
fn route_parser_spring_real_source() {
    let source = r#"
@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/users")
    public List<User> getUsers() {
        return userService.findAll();
    }

    @PostMapping("/users")
    public User createUser(@RequestBody UserDTO dto) {
        return userService.create(dto);
    }

    @PutMapping("/users/{id}")
    public User updateUser(@PathVariable Long id) {
        return userService.update(id);
    }

    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.delete(id);
    }

    @PatchMapping("/users/{id}/status")
    public void patchStatus(@PathVariable Long id) {
        userService.patchStatus(id);
    }
}
"#;
    let routes =
        parse_routes_from_source(source, "UserController.java", Framework::Spring).unwrap();

    assert_eq!(routes.len(), 6);

    let request_mapping = routes.iter().find(|r| r.path_pattern == "/api").unwrap();
    assert_eq!(request_mapping.http_method, HttpMethod::Any);
    assert_eq!(request_mapping.framework, Framework::Spring);

    let get_users = routes
        .iter()
        .find(|r| r.path_pattern == "/users" && r.http_method == HttpMethod::Get)
        .unwrap();
    assert!(get_users.line_number.is_some());

    let delete = routes
        .iter()
        .find(|r| r.http_method == HttpMethod::Delete)
        .unwrap();
    assert_eq!(delete.path_pattern, "/users/{id}");

    let patch = routes
        .iter()
        .find(|r| r.http_method == HttpMethod::Patch)
        .unwrap();
    assert_eq!(patch.path_pattern, "/users/{id}/status");
}

// ---------------------------------------------------------------------------
// Test 57: auth_matrix_from_live_server
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_matrix_from_live_server() {
    async fn public_handler() -> impl IntoResponse {
        StatusCode::OK
    }

    async fn admin_handler(headers: axum::http::HeaderMap) -> impl IntoResponse {
        match headers.get("authorization").and_then(|v| v.to_str().ok()) {
            Some("Bearer admin-token") => StatusCode::OK,
            Some("Bearer user-token") => StatusCode::OK,
            Some(_) => StatusCode::FORBIDDEN,
            None => StatusCode::UNAUTHORIZED,
        }
    }

    async fn admin_only_handler(headers: axum::http::HeaderMap) -> impl IntoResponse {
        match headers.get("authorization").and_then(|v| v.to_str().ok()) {
            Some("Bearer admin-token") => StatusCode::OK,
            Some(_) => StatusCode::FORBIDDEN,
            None => StatusCode::UNAUTHORIZED,
        }
    }

    let router = Router::new()
        .route("/public", get(public_handler))
        .route("/admin/dashboard", get(admin_handler))
        .route("/admin/config", get(admin_only_handler));

    let server = TestServer::new(router).await;

    let credentials = vec![
        Credential {
            label: "unauth".to_string(),
            privilege_level: PrivilegeLevel::Unauthenticated,
            auth_header: None,
        },
        Credential {
            label: "user".to_string(),
            privilege_level: PrivilegeLevel::User,
            auth_header: Some("Bearer user-token".to_string()),
        },
        Credential {
            label: "admin".to_string(),
            privilege_level: PrivilegeLevel::Admin,
            auth_header: Some("Bearer admin-token".to_string()),
        },
    ];

    let endpoints = [
        ("/public", "GET"),
        ("/admin/dashboard", "GET"),
        ("/admin/config", "GET"),
    ];

    let client = reqwest::Client::new();
    let mut matrix = AuthorizationMatrix::new(credentials.clone());

    for (path, method) in &endpoints {
        for cred in &credentials {
            let url = format!("{}{}", server.url(), path);
            let mut req = client.get(&url);
            if let Some(ref header) = cred.auth_header {
                req = req.header("Authorization", header);
            }
            let resp = req.send().await.unwrap();
            matrix.record_access(EndpointAccess {
                endpoint: path.to_string(),
                method: method.to_string(),
                credential_label: cred.label.clone(),
                status_code: resp.status().as_u16(),
            });
        }
    }

    assert_eq!(matrix.endpoint_count(), 3);

    assert_eq!(
        matrix.status_for("/admin/config", "GET", "admin"),
        Some(200)
    );
    assert_eq!(matrix.status_for("/admin/config", "GET", "user"), Some(403));
    assert_eq!(
        matrix.status_for("/admin/config", "GET", "unauth"),
        Some(401)
    );

    let anomalies = matrix.detect_anomalies();
    assert!(!anomalies.is_empty());

    let missing_auth: Vec<_> = anomalies
        .iter()
        .filter(|a| a.anomaly_type == AnomalyType::MissingAuthentication)
        .collect();
    assert!(
        !missing_auth.is_empty(),
        "expected MissingAuthentication anomaly on /public"
    );

    let priv_esc: Vec<_> = anomalies
        .iter()
        .filter(|a| {
            a.anomaly_type == AnomalyType::PrivilegeEscalation && a.endpoint == "/admin/dashboard"
        })
        .collect();
    assert!(
        !priv_esc.is_empty(),
        "expected PrivilegeEscalation on /admin/dashboard"
    );
}

// ---------------------------------------------------------------------------
// Test 58: auth_flow_template_rendering
// ---------------------------------------------------------------------------

#[test]
fn auth_flow_template_rendering() {
    let mut vars = HashMap::new();
    vars.insert("username".to_string(), "alice".to_string());
    vars.insert("password".to_string(), "s3cret!".to_string());
    vars.insert("token".to_string(), "eyJhbGciOi...".to_string());

    let template = r#"{"username":"{{username}}","password":"{{password}}"}"#;
    let rendered = render_template(template, &vars).unwrap();
    assert_eq!(rendered, r#"{"username":"alice","password":"s3cret!"}"#);

    let bearer_template = "Bearer {{token}}";
    let rendered_bearer = render_template(bearer_template, &vars).unwrap();
    assert_eq!(rendered_bearer, "Bearer eyJhbGciOi...");

    let no_vars = "no placeholders here";
    let rendered_plain = render_template(no_vars, &vars).unwrap();
    assert_eq!(rendered_plain, "no placeholders here");

    let multi_same = "{{username}}-{{username}}";
    let rendered_multi = render_template(multi_same, &vars).unwrap();
    assert_eq!(rendered_multi, "alice-alice");

    let missing_result = render_template("{{nonexistent}}", &vars);
    assert!(missing_result.is_err());
}

// ---------------------------------------------------------------------------
// Test 59: auth_flow_session_fixation_detection
// ---------------------------------------------------------------------------

#[test]
fn auth_flow_session_fixation_detection() {
    let pre_login = "session_abc123";
    let post_login_same = "session_abc123";
    let post_login_different = "session_xyz789";

    let finding = detect_session_fixation(Some(pre_login), Some(post_login_same));
    assert!(finding.is_some());
    let f = finding.unwrap();
    assert_eq!(f.vulnerability, AuthFlowVulnerability::SessionFixation);
    assert!(f.evidence.contains(pre_login));
    assert_eq!(f.affected_step, "login");

    let no_finding = detect_session_fixation(Some(pre_login), Some(post_login_different));
    assert!(no_finding.is_none());

    assert!(detect_session_fixation(None, Some("abc")).is_none());
    assert!(detect_session_fixation(Some("abc"), None).is_none());
    assert!(detect_session_fixation(None, None).is_none());
}

// ---------------------------------------------------------------------------
// Test 60: auth_flow_weak_session_id_detection
// ---------------------------------------------------------------------------

#[test]
fn auth_flow_weak_session_id_detection() {
    let short_id = "abc123";
    let finding = detect_weak_session_id(short_id);
    assert!(finding.is_some());
    let f = finding.unwrap();
    assert_eq!(f.vulnerability, AuthFlowVulnerability::WeakSessionId);
    assert!(f.description.contains("too short"));

    let all_digits = "1234567890123456";
    let finding2 = detect_weak_session_id(all_digits);
    assert!(finding2.is_some());
    let f2 = finding2.unwrap();
    assert_eq!(f2.vulnerability, AuthFlowVulnerability::WeakSessionId);
    assert!(f2.evidence.contains("all-digit"));

    let predictable_but_long = "1111111111111111";
    let finding3 = detect_weak_session_id(predictable_but_long);
    assert!(finding3.is_some());

    let strong_id = "a3f8c2e1b9d0456789abcdef01234567";
    assert!(detect_weak_session_id(strong_id).is_none());
}

// ---------------------------------------------------------------------------
// Test 61: auth_flow_insecure_cookie_detection
// ---------------------------------------------------------------------------

#[test]
fn auth_flow_insecure_cookie_detection() {
    let bare_cookie = "session=abc123; Path=/";
    let issues = detect_insecure_cookie(bare_cookie);
    assert_eq!(issues.len(), 3);
    assert!(
        issues
            .iter()
            .all(|v| *v == AuthFlowVulnerability::InsecureCookieAttributes)
    );

    let no_secure = "session=abc; HttpOnly; SameSite=Strict";
    let issues2 = detect_insecure_cookie(no_secure);
    assert!(!issues2.is_empty());

    let no_httponly = "session=abc; Secure; SameSite=Strict";
    let issues3 = detect_insecure_cookie(no_httponly);
    assert!(!issues3.is_empty());

    let no_samesite = "session=abc; Secure; HttpOnly";
    let issues4 = detect_insecure_cookie(no_samesite);
    assert!(!issues4.is_empty());

    let fully_secure = "session=abc; Secure; HttpOnly; SameSite=Strict; Path=/";
    let issues5 = detect_insecure_cookie(fully_secure);
    assert!(issues5.is_empty());
}
