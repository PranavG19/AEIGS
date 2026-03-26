#[cfg(test)]
mod tests {
    use crate::CliArgs;

    #[test]
    fn cli_args_defaults() {
        let args = CliArgs {
            target: None,
            port: 7777,
            profile: "quick".to_string(),
            demo: false,
        };
        assert_eq!(args.port, 7777);
        assert_eq!(args.profile, "quick");
        assert!(!args.demo);
        assert!(args.target.is_none());
    }

    #[test]
    fn cli_args_demo_mode() {
        let args = CliArgs {
            target: None,
            port: 8080,
            profile: "thorough".to_string(),
            demo: true,
        };
        assert!(args.demo);
        assert_eq!(args.port, 8080);
    }

    #[test]
    fn cli_args_with_target() {
        let args = CliArgs {
            target: Some("https://example.com".to_string()),
            port: 7777,
            profile: "quick".to_string(),
            demo: false,
        };
        assert_eq!(args.target.as_deref(), Some("https://example.com"));
    }
}
