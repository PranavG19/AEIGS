#[cfg(test)]
mod tests {
    use crate::route_parser::{Framework, HttpMethod, RouteParseError, parse_routes_from_source};

    #[test]
    fn parse_express_get_route() {
        let source = r#"
app.get('/users', getUsers);
app.post('/users', createUser);
"#;
        let routes = parse_routes_from_source(source, "app.js", Framework::Express).unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].path_pattern, "/users");
        assert_eq!(routes[0].http_method, HttpMethod::Get);
        assert_eq!(routes[0].handler_name, Some("getUsers".to_string()));
        assert_eq!(routes[1].http_method, HttpMethod::Post);
    }

    #[test]
    fn parse_express_router_routes() {
        let source = r#"
router.get('/items', listItems);
router.delete('/items/:id', deleteItem);
"#;
        let routes = parse_routes_from_source(source, "routes.js", Framework::Express).unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].http_method, HttpMethod::Get);
        assert_eq!(routes[1].path_pattern, "/items/:id");
        assert_eq!(routes[1].http_method, HttpMethod::Delete);
    }

    #[test]
    fn parse_express_app_use() {
        let source = "app.use('/api', apiRouter);\n";
        let routes = parse_routes_from_source(source, "app.js", Framework::Express).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].http_method, HttpMethod::Any);
        assert_eq!(routes[0].path_pattern, "/api");
    }

    #[test]
    fn parse_flask_route_decorator() {
        let source = r#"
@app.route('/login', methods=['GET', 'POST'])
def login():
    pass
"#;
        let routes = parse_routes_from_source(source, "app.py", Framework::Flask).unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].path_pattern, "/login");
        assert_eq!(routes[0].http_method, HttpMethod::Get);
        assert_eq!(routes[0].handler_name, Some("login".to_string()));
        assert_eq!(routes[1].http_method, HttpMethod::Post);
    }

    #[test]
    fn parse_flask_method_decorators() {
        let source = r#"
@app.get('/items')
def list_items():
    pass

@app.post('/items')
def create_item():
    pass
"#;
        let routes = parse_routes_from_source(source, "app.py", Framework::Flask).unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].http_method, HttpMethod::Get);
        assert_eq!(routes[0].handler_name, Some("list_items".to_string()));
        assert_eq!(routes[1].http_method, HttpMethod::Post);
    }

    #[test]
    fn parse_fastapi_routes() {
        let source = r#"
@app.get("/users/{user_id}")
async def get_user(user_id: int):
    pass

@app.post("/users")
async def create_user(user: UserCreate):
    pass
"#;
        let routes = parse_routes_from_source(source, "main.py", Framework::FastApi).unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].path_pattern, "/users/{user_id}");
        assert_eq!(routes[0].http_method, HttpMethod::Get);
        assert_eq!(routes[0].handler_name, Some("get_user".to_string()));
        assert_eq!(routes[1].http_method, HttpMethod::Post);
    }

    #[test]
    fn parse_fastapi_router_routes() {
        let source = r#"
@router.get("/items")
async def list_items():
    pass
"#;
        let routes = parse_routes_from_source(source, "routes.py", Framework::FastApi).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].path_pattern, "/items");
    }

    #[test]
    fn parse_django_path_routes() {
        let source = r#"
urlpatterns = [
    path('users/', views.user_list),
    path('users/<int:pk>/', views.user_detail),
]
"#;
        let routes = parse_routes_from_source(source, "urls.py", Framework::Django).unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].path_pattern, "/users/");
        assert_eq!(routes[0].http_method, HttpMethod::Any);
        assert_eq!(routes[0].handler_name, Some("views.user_list".to_string()));
    }

    #[test]
    fn parse_spring_annotations() {
        let source = r#"
@GetMapping("/api/users")
public List<User> getUsers() {}

@PostMapping("/api/users")
public User createUser() {}

@DeleteMapping("/api/users/{id}")
public void deleteUser() {}
"#;
        let routes =
            parse_routes_from_source(source, "Controller.java", Framework::Spring).unwrap();
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].path_pattern, "/api/users");
        assert_eq!(routes[0].http_method, HttpMethod::Get);
        assert_eq!(routes[1].http_method, HttpMethod::Post);
        assert_eq!(routes[2].http_method, HttpMethod::Delete);
        assert_eq!(routes[2].path_pattern, "/api/users/{id}");
    }

    #[test]
    fn parse_spring_request_mapping() {
        let source = "@RequestMapping(\"/api\")\npublic class Controller {}\n";
        let routes =
            parse_routes_from_source(source, "Controller.java", Framework::Spring).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].http_method, HttpMethod::Any);
    }

    #[test]
    fn unsupported_framework_returns_error() {
        let result = parse_routes_from_source("code", "file.rs", Framework::Rails);
        assert!(matches!(
            result,
            Err(RouteParseError::UnsupportedFramework(_))
        ));
    }

    #[test]
    fn line_numbers_are_correct() {
        let source = "\n\napp.get('/test', handler);\n";
        let routes = parse_routes_from_source(source, "app.js", Framework::Express).unwrap();
        assert_eq!(routes[0].line_number, Some(3));
    }

    #[test]
    fn empty_source_returns_empty() {
        let routes = parse_routes_from_source("", "app.js", Framework::Express).unwrap();
        assert!(routes.is_empty());
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
        assert_eq!(HttpMethod::Any.to_string(), "ANY");
    }

    #[test]
    fn framework_display() {
        assert_eq!(Framework::Express.to_string(), "express");
        assert_eq!(Framework::Flask.to_string(), "flask");
        assert_eq!(Framework::Django.to_string(), "django");
        assert_eq!(Framework::FastApi.to_string(), "fastapi");
        assert_eq!(Framework::Spring.to_string(), "spring");
        assert_eq!(Framework::Rails.to_string(), "rails");
        assert_eq!(Framework::GoNet.to_string(), "go-net-http");
        assert_eq!(Framework::Actix.to_string(), "actix-web");
        assert_eq!(Framework::Axum.to_string(), "axum");
    }

    #[test]
    fn error_display_is_descriptive() {
        let err = RouteParseError::UnsupportedFramework("rails".to_string());
        assert!(err.to_string().contains("unsupported framework"));

        let err =
            RouteParseError::IoError(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"));
        assert!(err.to_string().contains("io error"));
    }

    #[test]
    fn parse_file_nonexistent_returns_error() {
        use crate::route_parser::parse_routes_from_file;
        let result =
            parse_routes_from_file(std::path::Path::new("/nonexistent"), Framework::Express);
        assert!(matches!(result, Err(RouteParseError::IoError(_))));
    }

    #[test]
    fn single_quoted_paths_supported() {
        let source = "app.get('/api/v1/data', handler);\n";
        let routes = parse_routes_from_source(source, "app.js", Framework::Express).unwrap();
        assert_eq!(routes[0].path_pattern, "/api/v1/data");
    }

    #[test]
    fn express_put_and_patch_routes() {
        let source = "app.put('/items/:id', updateItem);\napp.patch('/items/:id', patchItem);\n";
        let routes = parse_routes_from_source(source, "app.js", Framework::Express).unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].http_method, HttpMethod::Put);
        assert_eq!(routes[1].http_method, HttpMethod::Patch);
    }

    #[test]
    fn flask_default_method_is_get() {
        let source = "@app.route('/home')\ndef home():\n    pass\n";
        let routes = parse_routes_from_source(source, "app.py", Framework::Flask).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].http_method, HttpMethod::Get);
    }
}
