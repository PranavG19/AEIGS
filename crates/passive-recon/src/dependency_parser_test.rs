#[cfg(test)]
mod tests {
    use crate::dependency_parser::{
        Ecosystem, ParseError, ParsedDependency, detect_ecosystem, parse_lock_file_content,
    };

    #[test]
    fn detect_ecosystem_package_lock() {
        assert_eq!(detect_ecosystem("package-lock.json"), Some(Ecosystem::Npm));
    }

    #[test]
    fn detect_ecosystem_cargo_lock() {
        assert_eq!(detect_ecosystem("Cargo.lock"), Some(Ecosystem::Cargo));
    }

    #[test]
    fn detect_ecosystem_requirements_txt() {
        assert_eq!(detect_ecosystem("requirements.txt"), Some(Ecosystem::PyPi));
    }

    #[test]
    fn detect_ecosystem_go_sum() {
        assert_eq!(detect_ecosystem("go.sum"), Some(Ecosystem::Go));
    }

    #[test]
    fn detect_ecosystem_gemfile_lock() {
        assert_eq!(detect_ecosystem("Gemfile.lock"), Some(Ecosystem::RubyGems));
    }

    #[test]
    fn detect_ecosystem_unknown_returns_none() {
        assert_eq!(detect_ecosystem("unknown.lock"), None);
        assert_eq!(detect_ecosystem("Makefile"), None);
    }

    #[test]
    fn detect_ecosystem_yarn_and_pnpm() {
        assert_eq!(detect_ecosystem("yarn.lock"), Some(Ecosystem::Npm));
        assert_eq!(detect_ecosystem("pnpm-lock.yaml"), Some(Ecosystem::Npm));
    }

    #[test]
    fn detect_ecosystem_pipfile_and_poetry() {
        assert_eq!(detect_ecosystem("Pipfile.lock"), Some(Ecosystem::PyPi));
        assert_eq!(detect_ecosystem("poetry.lock"), Some(Ecosystem::PyPi));
    }

    #[test]
    fn parse_package_lock_v3_packages() {
        let content = r#"{
            "packages": {
                "": {},
                "node_modules/express": { "version": "4.18.2" },
                "node_modules/lodash": { "version": "4.17.21" }
            }
        }"#;

        let deps = parse_lock_file_content("package-lock.json", content).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "express");
        assert_eq!(deps[0].version, "4.18.2");
        assert_eq!(deps[0].ecosystem, Ecosystem::Npm);
        assert_eq!(deps[1].name, "lodash");
        assert_eq!(deps[1].version, "4.17.21");
    }

    #[test]
    fn parse_package_lock_v1_dependencies_fallback() {
        let content = r#"{
            "dependencies": {
                "react": { "version": "18.2.0" },
                "react-dom": { "version": "18.2.0" }
            }
        }"#;

        let deps = parse_lock_file_content("package-lock.json", content).unwrap();
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn parse_cargo_lock() {
        let content = r#"version = 3

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[package]]
name = "tokio"
version = "1.37.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"
"#;

        let deps = parse_lock_file_content("Cargo.lock", content).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].version, "1.0.200");
        assert_eq!(deps[0].ecosystem, Ecosystem::Cargo);
        assert_eq!(deps[1].name, "tokio");
        assert_eq!(deps[1].version, "1.37.0");
    }

    #[test]
    fn parse_requirements_txt() {
        let content = r#"
# Comments are ignored
requests==2.31.0
flask>=2.3.0
numpy~=1.24.0
-r other-requirements.txt
"#;

        let deps = parse_lock_file_content("requirements.txt", content).unwrap();
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version, "2.31.0");
        assert_eq!(deps[0].ecosystem, Ecosystem::PyPi);
        assert_eq!(deps[1].name, "flask");
        assert_eq!(deps[1].version, "2.3.0");
        assert_eq!(deps[2].name, "numpy");
        assert_eq!(deps[2].version, "1.24.0");
    }

    #[test]
    fn parse_requirements_txt_with_extras() {
        let content = "django==4.2.0\ncelery[redis]>=5.3.0\n";
        let deps = parse_lock_file_content("requirements.txt", content).unwrap();
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn parse_go_sum() {
        let content = r#"
github.com/gin-gonic/gin v1.9.1 h1:abc123
github.com/gin-gonic/gin v1.9.1/go.mod h1:def456
github.com/go-sql-driver/mysql v1.7.0 h1:xyz789
"#;

        let deps = parse_lock_file_content("go.sum", content).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
        assert_eq!(deps[0].version, "1.9.1");
        assert_eq!(deps[0].ecosystem, Ecosystem::Go);
        assert_eq!(deps[1].name, "github.com/go-sql-driver/mysql");
        assert_eq!(deps[1].version, "1.7.0");
    }

    #[test]
    fn parse_gemfile_lock() {
        let content = r#"GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.8)
    rails (7.0.8)
      actionpack (= 7.0.8)

PLATFORMS
  ruby

BUNDLED WITH
   2.4.0
"#;

        let deps = parse_lock_file_content("Gemfile.lock", content).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "rack");
        assert_eq!(deps[0].version, "2.2.8");
        assert_eq!(deps[0].ecosystem, Ecosystem::RubyGems);
        assert_eq!(deps[1].name, "rails");
        assert_eq!(deps[1].version, "7.0.8");
    }

    #[test]
    fn unsupported_format_returns_error() {
        let result = parse_lock_file_content("unknown.lock", "content");
        assert!(matches!(result, Err(ParseError::UnsupportedFormat(_))));
    }

    #[test]
    fn empty_package_lock_returns_empty() {
        let content = r#"{ "packages": {} }"#;
        let deps = parse_lock_file_content("package-lock.json", content).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn empty_cargo_lock_returns_empty() {
        let deps = parse_lock_file_content("Cargo.lock", "").unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn empty_requirements_returns_empty() {
        let content = "# only comments\n\n";
        let deps = parse_lock_file_content("requirements.txt", content).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn ecosystem_display() {
        assert_eq!(Ecosystem::Npm.to_string(), "npm");
        assert_eq!(Ecosystem::Cargo.to_string(), "cargo");
        assert_eq!(Ecosystem::PyPi.to_string(), "pypi");
        assert_eq!(Ecosystem::Go.to_string(), "go");
        assert_eq!(Ecosystem::RubyGems.to_string(), "rubygems");
    }

    #[test]
    fn error_display_is_descriptive() {
        let err = ParseError::UnsupportedFormat("test.lock".to_string());
        assert!(err.to_string().contains("unsupported"));

        let err = ParseError::MalformedContent("bad data".to_string());
        assert!(err.to_string().contains("malformed"));

        let err = ParseError::IoError(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"));
        assert!(err.to_string().contains("io error"));
    }

    #[test]
    fn parse_lock_file_nonexistent_path() {
        use crate::dependency_parser::parse_lock_file;
        let result = parse_lock_file(std::path::Path::new("/nonexistent/Cargo.lock"));
        assert!(matches!(result, Err(ParseError::IoError(_))));
    }

    #[test]
    fn parse_requirements_with_version_constraints() {
        let content = "package1!=2.0.0\npackage2>1.0\npackage3<3.0\npackage4<=2.5\n";
        let deps = parse_lock_file_content("requirements.txt", content).unwrap();
        assert_eq!(deps.len(), 4);
        assert_eq!(deps[0].name, "package1");
        assert_eq!(deps[0].version, "2.0.0");
    }

    #[test]
    fn cargo_lock_with_extra_fields_still_parses() {
        let content = r#"version = 3

[[package]]
name = "proc-macro2"
version = "1.0.80"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

[[package]]
name = "quote"
version = "1.0.35"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

[[package]]
name = "syn"
version = "2.0.50"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
dependencies = ["proc-macro2", "quote"]
"#;

        let deps = parse_lock_file_content("Cargo.lock", content).unwrap();
        assert_eq!(deps.len(), 3);
        let syn_dep = deps.iter().find(|d| d.name == "syn").unwrap();
        assert_eq!(syn_dep.version, "2.0.50");
    }

    #[test]
    fn json_parse_error_propagated() {
        let result = parse_lock_file_content("package-lock.json", "not json{{{");
        assert!(matches!(result, Err(ParseError::JsonError(_))));
    }

    #[test]
    fn parsed_dependency_equality() {
        let dep1 = ParsedDependency {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
        };
        let dep2 = ParsedDependency {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
        };
        assert_eq!(dep1, dep2);
    }

    /// ParseError::JsonError display variant (line 47) via From<serde_json::Error> impl.
    #[test]
    fn json_error_display_variant() {
        let serde_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = ParseError::from(serde_err);
        assert!(err.to_string().contains("json parse error"));
    }

    /// parse_go_sum with a single-token line (parts.len() < 2) is skipped silently.
    #[test]
    fn parse_go_sum_skips_malformed_single_token_lines() {
        let content = "github.com/orphan-module\ngithub.com/gin-gonic/gin v1.9.1 h1:abc\n";
        let deps = parse_lock_file_content("go.sum", content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
    }

    /// parse_go_sum: version without 'v' prefix (strip_prefix returns None, fallback used).
    #[test]
    fn parse_go_sum_version_without_v_prefix() {
        let content = "github.com/example/pkg 1.2.3 h1:abc\n";
        let deps = parse_lock_file_content("go.sum", content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version, "1.2.3");
    }

    /// parse_gemfile_lock: a spec line with no parentheses is skipped (parse_gem_spec_line returns None).
    #[test]
    fn parse_gemfile_lock_skips_spec_line_without_parens() {
        let content = "GEM\n  remote: https://rubygems.org/\n  specs:\n    no-version-here\n    rack (2.2.8)\n\nPLATFORMS\n  ruby\n";
        let deps = parse_lock_file_content("Gemfile.lock", content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "rack");
    }
}
