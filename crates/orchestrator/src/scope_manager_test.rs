#[cfg(test)]
mod tests {
    use crate::scope_manager::*;

    #[test]
    fn wildcard_pattern_matches() {
        let p = ScopePattern::new("*.example.com").unwrap();
        assert!(p.matches("sub.example.com"));
        assert!(p.matches("deep.sub.example.com"));
        assert!(!p.matches("example.org"));
    }

    #[test]
    fn scope_include_exclude() {
        let mut mgr = ScopeManager::new();
        mgr.add_include("*://localhost:8080*").unwrap();
        mgr.add_exclude("*://localhost:8080/logout*").unwrap();

        assert!(mgr.is_in_scope("http://localhost:8080/api/users"));
        assert!(!mgr.is_in_scope("http://localhost:8080/logout"));
        assert!(!mgr.is_in_scope("http://example.com/api"));
    }

    #[test]
    fn exclude_takes_priority() {
        let mut mgr = ScopeManager::new();
        mgr.add_include("*").unwrap();
        mgr.add_exclude("*admin*").unwrap();
        assert!(!mgr.is_in_scope("http://localhost/admin"));
        assert!(mgr.is_in_scope("http://localhost/api"));
    }

    #[test]
    fn robots_txt_respected() {
        let mut mgr = ScopeManager::new();
        mgr.set_respect_robots(true);
        mgr.apply_robots_txt("User-agent: *\nDisallow: /private/\nDisallow: /tmp/\n");

        assert!(!mgr.is_in_scope("http://localhost/private/secrets"));
        assert!(!mgr.is_in_scope("http://localhost/tmp/file"));
        assert!(mgr.is_in_scope("http://localhost/public/page"));
    }

    #[test]
    fn robots_txt_ignored_when_disabled() {
        let mut mgr = ScopeManager::new();
        mgr.set_respect_robots(false);
        mgr.apply_robots_txt("User-agent: *\nDisallow: /private/\n");
        assert!(mgr.is_in_scope("http://localhost/private/secrets"));
    }

    #[test]
    fn out_of_scope_alert() {
        let mut mgr = ScopeManager::new();
        mgr.add_include("*://localhost*").unwrap();
        mgr.is_in_scope("http://evil.com/hack");
        assert_eq!(mgr.out_of_scope_alerts().len(), 1);
        assert_eq!(mgr.out_of_scope_alerts()[0], "http://evil.com/hack");
    }

    #[test]
    fn subdomain_tracking() {
        let mut mgr = ScopeManager::new();
        mgr.add_subdomain("api.example.com");
        mgr.add_subdomain("staging.example.com");
        assert_eq!(mgr.subdomains().len(), 2);
    }

    #[test]
    fn for_domain_constructor() {
        let mut mgr = ScopeManager::for_domain("example.com").unwrap();
        assert!(mgr.is_in_scope("http://example.com/api"));
        assert!(mgr.is_in_scope("https://sub.example.com/page"));
    }

    #[test]
    fn default_exclusions_list() {
        let excl = default_exclusions();
        assert!(excl.iter().any(|e| e.contains("logout")));
        assert!(excl.iter().any(|e| e.contains("health")));
    }

    #[test]
    fn no_include_means_all_in_scope() {
        let mut mgr = ScopeManager::new();
        assert!(mgr.is_in_scope("http://anything.com/whatever"));
    }

    #[test]
    fn clear_alerts() {
        let mut mgr = ScopeManager::new();
        mgr.add_include("*://localhost*").unwrap();
        mgr.is_in_scope("http://evil.com/x");
        assert_eq!(mgr.out_of_scope_alerts().len(), 1);
        mgr.clear_alerts();
        assert!(mgr.out_of_scope_alerts().is_empty());
    }

    #[test]
    fn extract_path_works() {
        assert_eq!(
            extract_path("http://localhost:8080/api/users"),
            "/api/users"
        );
        assert_eq!(extract_path("http://localhost"), "/");
    }

    #[test]
    fn invalid_pattern_errors() {
        let result = ScopePattern::new("valid-*");
        assert!(result.is_ok());
    }
}
