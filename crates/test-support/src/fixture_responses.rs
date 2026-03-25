use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Category of fixture response for filtering and lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResponseCategory {
    WafBlock,
    ErrorPage,
    LoginPage,
    ApiJson,
    ApiXml,
    ApiGraphQl,
    VulnerableResponse,
}

/// A single canned HTTP response with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureResponse {
    pub id: String,
    pub category: ResponseCategory,
    pub vendor: String,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub description: String,
}

/// Library of realistic HTTP responses for offline scanner testing.
///
/// Contains WAF block pages (per vendor), framework error pages,
/// CMS login pages, API responses (JSON/XML/GraphQL), and responses
/// with embedded vulnerabilities for scanner verification.
pub struct FixtureResponseLibrary {
    responses: Vec<FixtureResponse>,
}

impl FixtureResponseLibrary {
    /// Builds the full library with all fixture responses.
    pub fn build() -> Self {
        let responses = vec![
            // --- WAF Block Pages ---
            waf_cloudflare(),
            waf_aws_waf(),
            waf_akamai(),
            waf_modsecurity(),
            waf_imperva(),
            waf_sucuri(),
            // --- Framework Error Pages ---
            error_django_debug(),
            error_rails_500(),
            error_spring_whitelabel(),
            error_express_default(),
            error_laravel_debug(),
            error_flask_debug(),
            // --- CMS Login Pages ---
            login_wordpress(),
            login_drupal(),
            login_joomla(),
            // --- API Responses: JSON ---
            api_json_success(),
            api_json_paginated(),
            api_json_error_validation(),
            api_json_auth_error(),
            // --- API Responses: XML ---
            api_xml_soap_response(),
            api_xml_rss_feed(),
            // --- API Responses: GraphQL ---
            api_graphql_data(),
            api_graphql_error(),
            api_graphql_introspection(),
            // --- Vulnerable Responses (for scanner verification) ---
            vuln_sqli_error(),
            vuln_xss_reflected(),
            vuln_path_traversal(),
            vuln_ssrf_metadata(),
            vuln_sensitive_data_leak(),
            vuln_server_version_header(),
            vuln_directory_listing(),
            vuln_stack_trace_leak(),
        ];

        Self { responses }
    }

    /// Returns all fixture responses.
    pub fn all(&self) -> &[FixtureResponse] {
        &self.responses
    }

    /// Returns total count of fixture responses.
    pub fn count(&self) -> usize {
        self.responses.len()
    }

    /// Returns responses matching a specific category.
    pub fn by_category(&self, category: ResponseCategory) -> Vec<&FixtureResponse> {
        self.responses
            .iter()
            .filter(|r| r.category == category)
            .collect()
    }

    /// Returns a response by its unique id.
    pub fn by_id(&self, id: &str) -> Option<&FixtureResponse> {
        self.responses.iter().find(|r| r.id == id)
    }

    /// Returns responses from a specific vendor.
    pub fn by_vendor(&self, vendor: &str) -> Vec<&FixtureResponse> {
        self.responses
            .iter()
            .filter(|r| r.vendor.eq_ignore_ascii_case(vendor))
            .collect()
    }

    /// Returns all unique vendor names in the library.
    pub fn vendors(&self) -> Vec<String> {
        let mut vendors: Vec<String> = self
            .responses
            .iter()
            .map(|r| r.vendor.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        vendors.sort();
        vendors
    }

    /// Returns all responses that should trigger vulnerability detection.
    pub fn vulnerable_responses(&self) -> Vec<&FixtureResponse> {
        self.by_category(ResponseCategory::VulnerableResponse)
    }

    /// Serializes the entire library to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.responses).unwrap_or_default()
    }
}

fn fixture(
    id: &str,
    category: ResponseCategory,
    vendor: &str,
    status: u16,
    headers: &[(&str, &str)],
    body: &str,
    desc: &str,
) -> FixtureResponse {
    FixtureResponse {
        id: id.to_string(),
        category,
        vendor: vendor.to_string(),
        status_code: status,
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: body.to_string(),
        description: desc.to_string(),
    }
}

// ---------------------------------------------------------------------------
// WAF Block Pages
// ---------------------------------------------------------------------------

fn waf_cloudflare() -> FixtureResponse {
    fixture(
        "waf-cloudflare",
        ResponseCategory::WafBlock,
        "Cloudflare",
        403,
        &[
            ("server", "cloudflare"),
            ("cf-ray", "8a1b2c3d4e5f6g-SJC"),
            ("content-type", "text/html; charset=UTF-8"),
        ],
        r#"<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head>
<body><div class="cf-browser-verification"><h1>Sorry, you have been blocked</h1>
<p>You are unable to access this website.</p>
<p>Ray ID: 8a1b2c3d4e5f6g</p>
<p>Cloudflare Ray ID found at the bottom of this page.</p>
<div class="cf-error-details">This request was blocked by the security rules.</div>
</div></body></html>"#,
        "Cloudflare WAF 403 block page with Ray ID",
    )
}

fn waf_aws_waf() -> FixtureResponse {
    fixture(
        "waf-aws",
        ResponseCategory::WafBlock,
        "AWS",
        403,
        &[
            ("server", "awselb/2.0"),
            ("content-type", "text/html"),
            ("x-amzn-requestid", "a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
        ],
        r#"<!DOCTYPE html><html><head><title>403 Forbidden</title></head>
<body><h1>403 Forbidden</h1>
<p>Request blocked by AWS WAF.</p>
<p>If you believe this is an error, contact the site administrator.</p>
<p>Request ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890</p>
</body></html>"#,
        "AWS WAF block page with request ID",
    )
}

fn waf_akamai() -> FixtureResponse {
    fixture(
        "waf-akamai",
        ResponseCategory::WafBlock,
        "Akamai",
        403,
        &[
            ("server", "AkamaiGHost"),
            ("content-type", "text/html"),
            ("x-akamai-request-id", "1a2b3c.4d5e6f"),
        ],
        r#"<html><head><title>Access Denied</title></head>
<body><h1>Access Denied</h1>
<p>You don't have permission to access this resource.</p>
<p>Reference#18.abcdef12.1234567890.12345678</p>
<p>Powered by Akamai</p>
</body></html>"#,
        "Akamai WAF block page with reference number",
    )
}

fn waf_modsecurity() -> FixtureResponse {
    fixture(
        "waf-modsecurity",
        ResponseCategory::WafBlock,
        "ModSecurity",
        403,
        &[
            ("server", "Apache/2.4.52 (Ubuntu)"),
            ("content-type", "text/html; charset=iso-8859-1"),
        ],
        r#"<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>403 Forbidden</title></head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<p>ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Rx' with parameter
`(?i:(?:[\s(]*?(?:select|union|insert|update|delete|drop|alter|create|truncate)[\s(]))'
against variable `ARGS:input' (Value: `' OR 1=1--' )</p>
<p>Apache/2.4.52 (Ubuntu) Server</p>
</body></html>"#,
        "ModSecurity block page showing matched rule and payload",
    )
}

fn waf_imperva() -> FixtureResponse {
    fixture(
        "waf-imperva",
        ResponseCategory::WafBlock,
        "Imperva",
        403,
        &[
            ("server", "Imperva"),
            ("content-type", "text/html"),
            (
                "x-iinfo",
                "1-23456789-0 0NNN RT(1234567890 0) q(0 -1 -1 -1)",
            ),
        ],
        r#"<html><head><title>Error</title></head>
<body><div style="text-align:center">
<h2>This request was blocked by the security rules</h2>
<p>Your request was flagged as a potential attack.</p>
<p>Incident ID: 1234567890123456789-1234567890</p>
<p>Powered by Incapsula</p>
</div></body></html>"#,
        "Imperva/Incapsula WAF block page",
    )
}

fn waf_sucuri() -> FixtureResponse {
    fixture(
        "waf-sucuri",
        ResponseCategory::WafBlock,
        "Sucuri",
        403,
        &[
            ("server", "Sucuri/Cloudproxy"),
            ("content-type", "text/html"),
            ("x-sucuri-id", "12345"),
        ],
        r#"<html><head><title>Access Denied - Sucuri Website Firewall</title></head>
<body><h1>Access Denied - Sucuri Website Firewall</h1>
<p>If you are the site owner, click the link below to whitelist your IP.</p>
<p>Your request was blocked due to security rules. Sucuri CloudProxy.</p>
<p>Block Reference: #abcdef1234567890</p>
</body></html>"#,
        "Sucuri CloudProxy WAF block page",
    )
}

// ---------------------------------------------------------------------------
// Framework Error Pages
// ---------------------------------------------------------------------------

fn error_django_debug() -> FixtureResponse {
    fixture(
        "error-django-debug",
        ResponseCategory::ErrorPage,
        "Django",
        500,
        &[("content-type", "text/html"), ("x-frame-options", "DENY")],
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>OperationalError at /api/users</title>
<style>body{font-family:sans-serif}</style></head>
<body><div id="summary">
<h1>OperationalError at /api/users</h1>
<h2>no such table: auth_user</h2>
<table><tr><th>Request Method:</th><td>GET</td></tr>
<tr><th>Request URL:</th><td>http://localhost:8000/api/users?q=test</td></tr>
<tr><th>Django Version:</th><td>4.2.7</td></tr>
<tr><th>Python Version:</th><td>3.11.6</td></tr>
<tr><th>Python Executable:</th><td>/usr/bin/python3</td></tr>
<tr><th>Python Path:</th><td>['/app', '/usr/lib/python3/dist-packages']</td></tr>
<tr><th>Server time:</th><td>Thu, 14 Dec 2023 10:30:00 +0000</td></tr>
<tr><th>Installed Apps:</th><td>['django.contrib.admin','django.contrib.auth','myapp']</td></tr>
<tr><th>DATABASE_URL:</th><td>sqlite:///db.sqlite3</td></tr></table>
<div id="traceback"><pre>Traceback:
File "/usr/lib/python3/dist-packages/django/db/backends/sqlite3/base.py" in execute
  328. return self.cursor.execute(sql, params)
File "/app/myapp/views.py" in list_users
  42. users = User.objects.filter(name__contains=request.GET['q'])</pre></div>
</div></body></html>"#,
        "Django debug 500 page with full traceback, DB URL, installed apps",
    )
}

fn error_rails_500() -> FixtureResponse {
    fixture(
        "error-rails-500",
        ResponseCategory::ErrorPage,
        "Rails",
        500,
        &[
            ("content-type", "text/html; charset=utf-8"),
            ("x-request-id", "a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
            ("x-runtime", "0.012345"),
        ],
        r#"<!DOCTYPE html><html><head><title>Action Controller: Exception caught</title></head>
<body><h1>ActiveRecord::RecordNotFound</h1>
<h2>Couldn't find User with 'id'=999</h2>
<pre id="Framework-Trace">
app/controllers/users_controller.rb:15:in `show'
actionpack (7.0.8) lib/action_controller/metal/basic_implicit_render.rb:6
actionpack (7.0.8) lib/action_controller/metal.rb:183:in `dispatch'
actionpack (7.0.8) lib/action_dispatch/routing/route_set.rb:48
rack (2.2.8) lib/rack/tempfile_reaper.rb:15:in `call'
puma (6.4.0) lib/puma/configuration.rb:272:in `call'
</pre>
<h2>Request</h2>
<table><tr><th>RAILS_ENV</th><td>production</td></tr>
<tr><th>RAILS_LOG_LEVEL</th><td>debug</td></tr>
<tr><th>SECRET_KEY_BASE</th><td>abcdef1234567890...</td></tr></table>
</body></html>"#,
        "Rails exception page with gem versions and environment variables",
    )
}

fn error_spring_whitelabel() -> FixtureResponse {
    fixture(
        "error-spring-whitelabel",
        ResponseCategory::ErrorPage,
        "Spring",
        500,
        &[
            ("content-type", "text/html;charset=UTF-8"),
            ("connection", "close"),
        ],
        r#"<!DOCTYPE html><html><body>
<h1>Whitelabel Error Page</h1>
<p>This application has no explicit mapping for /error, so you are seeing this as a fallback.</p>
<div>There was an unexpected error (type=Internal Server Error, status=500).</div>
<div>java.lang.NullPointerException: Cannot invoke "String.length()" because "str" is null
at com.example.api.UserService.findUser(UserService.java:42)
at com.example.api.UserController.getUser(UserController.java:28)
at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
at org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:897)
at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:178)
</div>
<div>Spring Boot Version: 2.7.18, Java: 11.0.2, Tomcat: 9.0.83</div>
</body></html>"#,
        "Spring Boot whitelabel error with full Java stack trace",
    )
}

fn error_express_default() -> FixtureResponse {
    fixture(
        "error-express-default",
        ResponseCategory::ErrorPage,
        "Express",
        500,
        &[
            ("content-type", "text/html; charset=utf-8"),
            ("x-powered-by", "Express"),
        ],
        r#"<!DOCTYPE html><html><head><title>Error</title></head>
<body><pre>TypeError: Cannot read properties of undefined (reading 'id')
    at /app/routes/users.js:23:18
    at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)
    at next (/app/node_modules/express/lib/router/route.js:144:13)
    at Route.dispatch (/app/node_modules/express/lib/router/route.js:114:3)
    at /app/node_modules/express/lib/router/index.js:284:15</pre>
</body></html>"#,
        "Express default error page with Node.js stack trace",
    )
}

fn error_laravel_debug() -> FixtureResponse {
    fixture(
        "error-laravel-debug",
        ResponseCategory::ErrorPage,
        "Laravel",
        500,
        &[("content-type", "text/html; charset=UTF-8")],
        r#"<!DOCTYPE html><html><head><title>Whoops! There was an error.</title></head>
<body class="ignition"><div class="exception">
<h1>Illuminate\Database\QueryException</h1>
<h2>SQLSTATE[42S02]: Base table or view not found: 1146 Table 'mydb.users' doesn't exist
(SQL: select * from `users` where `email` = test@example.com)</h2>
<div class="trace"><pre>
#0 /var/www/html/vendor/laravel/framework/src/Illuminate/Database/Connection.php(760)
#1 /var/www/html/vendor/laravel/framework/src/Illuminate/Database/Query/Builder.php(2896)
#2 /var/www/html/app/Http/Controllers/UserController.php(34)
</pre></div>
<div class="env"><table>
<tr><td>APP_KEY</td><td>base64:abcdefghijklmnopqrstuvwxyz1234567890</td></tr>
<tr><td>DB_PASSWORD</td><td>secret_db_pass</td></tr>
<tr><td>MAIL_PASSWORD</td><td>smtp_password_123</td></tr>
</table></div>
</div></body></html>"#,
        "Laravel Ignition debug page with SQL query and env vars",
    )
}

fn error_flask_debug() -> FixtureResponse {
    fixture(
        "error-flask-debug",
        ResponseCategory::ErrorPage,
        "Flask",
        500,
        &[
            ("content-type", "text/html; charset=utf-8"),
            ("server", "Werkzeug/2.3.7 Python/3.11.6"),
        ],
        r#"<!DOCTYPE html><html><head><title>ZeroDivisionError: division by zero // Werkzeug Debugger</title></head>
<body><div class="debugger">
<h1>ZeroDivisionError</h1>
<h2 class="traceback">division by zero</h2>
<div class="traceback"><pre>
Traceback (most recent call last):
  File "/app/venv/lib/python3.11/site-packages/flask/app.py", line 1478, in __call__
    return self.wsgi_app(environ, start_response)
  File "/app/app.py", line 42, in calculate
    result = amount / divisor
ZeroDivisionError: division by zero
</pre></div>
<div class="console"><p>Interactive Debugger PIN: 123-456-789</p></div>
</div></body></html>"#,
        "Flask/Werkzeug debug page with interactive debugger PIN",
    )
}

// ---------------------------------------------------------------------------
// CMS Login Pages
// ---------------------------------------------------------------------------

fn login_wordpress() -> FixtureResponse {
    fixture(
        "login-wordpress",
        ResponseCategory::LoginPage,
        "WordPress",
        200,
        &[
            ("content-type", "text/html; charset=UTF-8"),
            ("x-powered-by", "PHP/8.1.0"),
        ],
        r#"<!DOCTYPE html><html lang="en-US"><head>
<title>Log In &lsaquo; My Site &#8212; WordPress</title>
<meta name="generator" content="WordPress 6.4.2" />
<link rel="stylesheet" href="/wp-admin/css/login.min.css" />
</head><body class="login wp-core-ui">
<div id="login"><h1><a href="https://wordpress.org/">WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" /></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" /></p>
<p class="submit"><input type="submit" name="wp-submit" value="Log In" /></p>
<input type="hidden" name="redirect_to" value="/wp-admin/" />
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
</div></body></html>"#,
        "WordPress wp-login.php with version in meta generator",
    )
}

fn login_drupal() -> FixtureResponse {
    fixture(
        "login-drupal",
        ResponseCategory::LoginPage,
        "Drupal",
        200,
        &[
            ("content-type", "text/html; charset=UTF-8"),
            ("x-generator", "Drupal 10 (https://www.drupal.org)"),
            ("x-drupal-cache", "MISS"),
        ],
        r#"<!DOCTYPE html><html><head><title>Log in | My Drupal Site</title>
<meta name="Generator" content="Drupal 10 (https://www.drupal.org)" />
</head><body class="user-login-form">
<main><article>
<h1>Log in</h1>
<form action="/user/login" method="post" accept-charset="UTF-8">
<div class="form-item"><label for="edit-name">Username</label>
<input type="text" id="edit-name" name="name" maxlength="60" /></div>
<div class="form-item"><label for="edit-pass">Password</label>
<input type="password" id="edit-pass" name="pass" /></div>
<input type="hidden" name="form_build_id" value="form-Xk7q9" />
<input type="hidden" name="form_id" value="user_login_form" />
<button type="submit">Log in</button>
</form></article></main>
</body></html>"#,
        "Drupal login page with version in X-Generator header",
    )
}

fn login_joomla() -> FixtureResponse {
    fixture(
        "login-joomla",
        ResponseCategory::LoginPage,
        "Joomla",
        200,
        &[
            ("content-type", "text/html; charset=utf-8"),
            ("x-powered-by", "JoomlaVer/4.4.1"),
        ],
        r#"<!DOCTYPE html><html lang="en-gb"><head>
<meta name="generator" content="Joomla! - Open Source Content Management - Version 4.4.1" />
<title>My Joomla Site - Administration</title>
</head><body class="admin login">
<form action="/administrator/index.php" method="post" id="form-login">
<div class="form-group"><label for="mod-login-username">Username</label>
<input name="username" id="mod-login-username" type="text" /></div>
<div class="form-group"><label for="mod-login-password">Password</label>
<input name="passwd" id="mod-login-password" type="password" /></div>
<input type="hidden" name="option" value="com_login" />
<input type="hidden" name="task" value="login" />
<input type="hidden" name="return" value="aW5kZXgucGhw" />
<button type="submit">Log in</button>
</form></body></html>"#,
        "Joomla admin login page with version in meta generator",
    )
}

// ---------------------------------------------------------------------------
// API Responses: JSON
// ---------------------------------------------------------------------------

fn api_json_success() -> FixtureResponse {
    fixture(
        "api-json-success",
        ResponseCategory::ApiJson,
        "Generic",
        200,
        &[
            ("content-type", "application/json"),
            ("x-request-id", "req_abc123"),
        ],
        r#"{"status":"ok","data":{"users":[{"id":1,"name":"Alice Nakamura","email":"alice@example.com","role":"admin"},{"id":2,"name":"Bruno Rossi","email":"bruno@example.com","role":"user"}]},"meta":{"total":2,"page":1,"per_page":20}}"#,
        "Standard JSON API success response with pagination meta",
    )
}

fn api_json_paginated() -> FixtureResponse {
    fixture(
        "api-json-paginated",
        ResponseCategory::ApiJson,
        "Generic",
        200,
        &[
            ("content-type", "application/json"),
            (
                "link",
                r#"<https://api.example.com/users?page=2>; rel="next", <https://api.example.com/users?page=5>; rel="last""#,
            ),
        ],
        r#"{"data":[{"id":1,"name":"User 1"},{"id":2,"name":"User 2"}],"pagination":{"current_page":1,"total_pages":5,"total_count":100,"per_page":20,"next_cursor":"eyJpZCI6MjB9"}}"#,
        "Paginated JSON response with Link header and cursor",
    )
}

fn api_json_error_validation() -> FixtureResponse {
    fixture(
        "api-json-error-validation",
        ResponseCategory::ApiJson,
        "Generic",
        422,
        &[("content-type", "application/json")],
        r#"{"error":"Validation Error","code":"VALIDATION_FAILED","details":[{"field":"email","message":"must be a valid email address","code":"INVALID_FORMAT"},{"field":"age","message":"must be at least 18","code":"OUT_OF_RANGE"}]}"#,
        "JSON API 422 validation error with field-level details",
    )
}

fn api_json_auth_error() -> FixtureResponse {
    fixture(
        "api-json-auth-error",
        ResponseCategory::ApiJson,
        "Generic",
        401,
        &[
            ("content-type", "application/json"),
            ("www-authenticate", "Bearer realm=\"api\""),
        ],
        r#"{"error":"Unauthorized","message":"Invalid or expired token","code":"AUTH_TOKEN_INVALID"}"#,
        "JSON API 401 unauthorized with Bearer challenge",
    )
}

// ---------------------------------------------------------------------------
// API Responses: XML
// ---------------------------------------------------------------------------

fn api_xml_soap_response() -> FixtureResponse {
    fixture(
        "api-xml-soap",
        ResponseCategory::ApiXml,
        "Generic",
        200,
        &[("content-type", "text/xml; charset=utf-8")],
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUserResponse xmlns="http://example.com/api">
      <User>
        <Id>1</Id>
        <Name>Alice Nakamura</Name>
        <Email>alice@example.com</Email>
        <Role>admin</Role>
      </User>
    </GetUserResponse>
  </soap:Body>
</soap:Envelope>"#,
        "SOAP XML response with user data",
    )
}

fn api_xml_rss_feed() -> FixtureResponse {
    fixture(
        "api-xml-rss",
        ResponseCategory::ApiXml,
        "Generic",
        200,
        &[("content-type", "application/rss+xml; charset=UTF-8")],
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Example Blog</title>
    <link>https://example.com</link>
    <description>Latest posts</description>
    <item>
      <title>Security Update v2.1</title>
      <link>https://example.com/blog/security-update</link>
      <description>Important security patches applied.</description>
      <pubDate>Thu, 14 Dec 2023 10:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>"#,
        "RSS 2.0 XML feed response",
    )
}

// ---------------------------------------------------------------------------
// API Responses: GraphQL
// ---------------------------------------------------------------------------

fn api_graphql_data() -> FixtureResponse {
    fixture(
        "api-graphql-data",
        ResponseCategory::ApiGraphQl,
        "Generic",
        200,
        &[("content-type", "application/json")],
        r#"{"data":{"user":{"id":"1","name":"Alice Nakamura","email":"alice@example.com","orders":[{"id":"ord-001","total":149.99},{"id":"ord-002","total":89.50}]}}}"#,
        "GraphQL successful data response with nested objects",
    )
}

fn api_graphql_error() -> FixtureResponse {
    fixture(
        "api-graphql-error",
        ResponseCategory::ApiGraphQl,
        "Generic",
        200,
        &[("content-type", "application/json")],
        r#"{"data":null,"errors":[{"message":"Cannot query field \"password\" on type \"User\".","locations":[{"line":3,"column":5}],"extensions":{"code":"GRAPHQL_VALIDATION_FAILED","hint":"Available fields: id, name, email, role"}}]}"#,
        "GraphQL validation error leaking available field names",
    )
}

fn api_graphql_introspection() -> FixtureResponse {
    fixture(
        "api-graphql-introspection",
        ResponseCategory::ApiGraphQl,
        "Generic",
        200,
        &[("content-type", "application/json")],
        r#"{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"types":[{"kind":"OBJECT","name":"Query","fields":[{"name":"user","args":[{"name":"id"}]},{"name":"users"},{"name":"adminPanel"},{"name":"internalMetrics"}]},{"kind":"OBJECT","name":"User","fields":[{"name":"id"},{"name":"email"},{"name":"password_hash"},{"name":"ssn"}]}]}}}"#,
        "GraphQL introspection exposing sensitive fields and admin queries",
    )
}

// ---------------------------------------------------------------------------
// Vulnerable Responses (scanner verification)
// ---------------------------------------------------------------------------

fn vuln_sqli_error() -> FixtureResponse {
    fixture(
        "vuln-sqli-error",
        ResponseCategory::VulnerableResponse,
        "Generic",
        500,
        &[("content-type", "text/html")],
        r#"<html><body><h1>Database Error</h1>
<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version
for the right syntax to use near '' OR 1=1--' at line 1</p>
<p>Query: SELECT * FROM users WHERE username = '' OR 1=1--'</p>
</body></html>"#,
        "MySQL error page revealing SQL query and injection point",
    )
}

fn vuln_xss_reflected() -> FixtureResponse {
    fixture(
        "vuln-xss-reflected",
        ResponseCategory::VulnerableResponse,
        "Generic",
        200,
        &[("content-type", "text/html")],
        r#"<html><body>
<h1>Search Results</h1>
<p>You searched for: <script>alert('XSS')</script></p>
<p>No results found.</p>
</body></html>"#,
        "Reflected XSS in search results page",
    )
}

fn vuln_path_traversal() -> FixtureResponse {
    fixture(
        "vuln-path-traversal",
        ResponseCategory::VulnerableResponse,
        "Generic",
        200,
        &[("content-type", "text/plain")],
        "root:x:0:0:root:/root:/bin/bash\n\
         daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
         bin:x:2:2:bin:/bin:/usr/sbin/nologin\n\
         sys:x:3:3:sys:/dev:/usr/sbin/nologin\n\
         www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
        "Path traversal response returning /etc/passwd contents",
    )
}

fn vuln_ssrf_metadata() -> FixtureResponse {
    fixture(
        "vuln-ssrf-metadata",
        ResponseCategory::VulnerableResponse,
        "Generic",
        200,
        &[("content-type", "application/json")],
        r#"{"Code":"Success","LastUpdated":"2023-12-14T10:30:00Z","Type":"AWS-HMAC","AccessKeyId":"ASIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Token":"FwoGZXIvYXdzEBYaDHqa0AP1","Expiration":"2023-12-14T16:30:00Z"}"#,
        "SSRF response from AWS metadata endpoint with IAM credentials",
    )
}

fn vuln_sensitive_data_leak() -> FixtureResponse {
    fixture(
        "vuln-sensitive-data",
        ResponseCategory::VulnerableResponse,
        "Generic",
        200,
        &[("content-type", "application/json")],
        r#"{"config":{"database":{"host":"db.internal","port":5432,"username":"admin","password":"Pr0d_P@ssw0rd!"},"redis":{"host":"redis.internal","auth":"r3d1s_s3cr3t"},"api_keys":{"stripe":"sk_live_4eC39HqLyjWDarjtT1zdp7dc","sendgrid":"SG.abcdefghijklmnop"}}}"#,
        "Configuration endpoint leaking database credentials and API keys",
    )
}

fn vuln_server_version_header() -> FixtureResponse {
    fixture(
        "vuln-server-version",
        ResponseCategory::VulnerableResponse,
        "Generic",
        200,
        &[
            ("content-type", "text/html"),
            ("server", "Apache/2.4.49 (Unix) OpenSSL/1.1.1k PHP/7.4.3"),
            ("x-powered-by", "PHP/7.4.3"),
            ("x-aspnet-version", "4.0.30319"),
        ],
        r#"<html><body>OK</body></html>"#,
        "Response with verbose Server and X-Powered-By headers revealing versions",
    )
}

fn vuln_directory_listing() -> FixtureResponse {
    fixture(
        "vuln-directory-listing",
        ResponseCategory::VulnerableResponse,
        "Generic",
        200,
        &[("content-type", "text/html")],
        r#"<!DOCTYPE html><html><head><title>Index of /backup</title></head>
<body><h1>Index of /backup</h1>
<pre><a href="../">../</a>
<a href="database_dump.sql">database_dump.sql</a>      14-Dec-2023 10:00   45M
<a href="config.yml.bak">config.yml.bak</a>          14-Dec-2023 09:00   2.1K
<a href=".env.production">.env.production</a>         14-Dec-2023 08:00   512
<a href="id_rsa">id_rsa</a>                  14-Dec-2023 07:00   1.6K
<a href="users_export.csv">users_export.csv</a>        13-Dec-2023 23:00   12M
</pre></body></html>"#,
        "Apache directory listing exposing backup files and private keys",
    )
}

fn vuln_stack_trace_leak() -> FixtureResponse {
    fixture(
        "vuln-stack-trace",
        ResponseCategory::VulnerableResponse,
        "Generic",
        500,
        &[
            ("content-type", "application/json"),
            ("x-powered-by", "Express"),
        ],
        r#"{"error":"InternalServerError","message":"Cannot read properties of null (reading 'id')","stack":"TypeError: Cannot read properties of null (reading 'id')\n    at UserService.findById (/app/src/services/user.service.js:42:25)\n    at processTicksAndRejections (node:internal/process/task_queues:95:5)\n    at async UserController.getUser (/app/src/controllers/user.controller.js:18:20)","env":"production","node_version":"v18.17.0"}"#,
        "JSON error response with full stack trace and environment info",
    )
}

#[cfg(test)]
#[path = "fixture_responses_test.rs"]
mod tests;
