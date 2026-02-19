#[cfg(test)]
mod tests {
    use crate::header_transformer::HeaderTransformer;
    use crate::persona::{Persona, PersonaId};

    fn chrome_persona() -> Persona {
        Persona::custom(PersonaId::ChromeDesktop)
            .with_user_agent("Mozilla/5.0 Chrome/131")
            .with_accept_header("text/html,*/*;q=0.8")
            .with_accept_language("en-US,en;q=0.9")
            .with_accept_encoding("gzip, deflate, br")
            .with_sec_fetch_headers(vec![
                ("Sec-Fetch-Site".to_string(), "none".to_string()),
                ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
                ("Sec-Fetch-Dest".to_string(), "document".to_string()),
            ])
            .with_header_order(vec![
                "Host".to_string(),
                "User-Agent".to_string(),
                "Accept".to_string(),
                "Sec-Fetch-Site".to_string(),
                "Sec-Fetch-Mode".to_string(),
                "Sec-Fetch-Dest".to_string(),
                "Accept-Encoding".to_string(),
                "Accept-Language".to_string(),
            ])
            .build()
    }

    fn googlebot_persona() -> Persona {
        Persona::custom(PersonaId::Googlebot)
            .with_user_agent("Googlebot/2.1")
            .with_accept_header("text/html,*/*;q=0.8")
            .with_accept_language("en")
            .with_accept_encoding("gzip, deflate")
            .with_sec_fetch_headers(vec![])
            .with_header_order(vec![
                "Host".to_string(),
                "User-Agent".to_string(),
                "Accept".to_string(),
                "Accept-Encoding".to_string(),
            ])
            .build()
    }

    #[test]
    fn transform_adds_persona_user_agent() {
        let transformer = HeaderTransformer::new();
        let persona = chrome_persona();
        let result = transformer.transform(&[], &persona);
        let ua = result
            .headers
            .iter()
            .find(|(k, _)| k == "User-Agent")
            .unwrap();
        assert_eq!(ua.1, "Mozilla/5.0 Chrome/131");
    }

    #[test]
    fn transform_adds_accept_headers() {
        let transformer = HeaderTransformer::new();
        let persona = chrome_persona();
        let result = transformer.transform(&[], &persona);

        let accept = result.headers.iter().find(|(k, _)| k == "Accept").unwrap();
        assert_eq!(accept.1, "text/html,*/*;q=0.8");

        let lang = result
            .headers
            .iter()
            .find(|(k, _)| k == "Accept-Language")
            .unwrap();
        assert_eq!(lang.1, "en-US,en;q=0.9");

        let enc = result
            .headers
            .iter()
            .find(|(k, _)| k == "Accept-Encoding")
            .unwrap();
        assert_eq!(enc.1, "gzip, deflate, br");
    }

    #[test]
    fn transform_adds_sec_fetch_headers() {
        let transformer = HeaderTransformer::new();
        let persona = chrome_persona();
        let result = transformer.transform(&[], &persona);

        let site = result
            .headers
            .iter()
            .find(|(k, _)| k == "Sec-Fetch-Site")
            .unwrap();
        assert_eq!(site.1, "none");

        let mode = result
            .headers
            .iter()
            .find(|(k, _)| k == "Sec-Fetch-Mode")
            .unwrap();
        assert_eq!(mode.1, "navigate");

        let dest = result
            .headers
            .iter()
            .find(|(k, _)| k == "Sec-Fetch-Dest")
            .unwrap();
        assert_eq!(dest.1, "document");
    }

    #[test]
    fn existing_headers_are_preserved() {
        let transformer = HeaderTransformer::new();
        let persona = chrome_persona();
        let existing = vec![("X-Custom".to_string(), "my-value".to_string())];
        let result = transformer.transform(&existing, &persona);

        let custom = result
            .headers
            .iter()
            .find(|(k, _)| k == "X-Custom")
            .unwrap();
        assert_eq!(custom.1, "my-value");
    }

    #[test]
    fn persona_header_order_is_respected() {
        let transformer = HeaderTransformer::new();
        let persona = chrome_persona();
        let result = transformer.transform(&[], &persona);

        let names: Vec<&str> = result.headers.iter().map(|(k, _)| k.as_str()).collect();
        let ua_pos = names.iter().position(|&n| n == "User-Agent").unwrap();
        let accept_pos = names.iter().position(|&n| n == "Accept").unwrap();
        let sec_site_pos = names.iter().position(|&n| n == "Sec-Fetch-Site").unwrap();
        let enc_pos = names.iter().position(|&n| n == "Accept-Encoding").unwrap();
        let lang_pos = names.iter().position(|&n| n == "Accept-Language").unwrap();

        assert!(ua_pos < accept_pos);
        assert!(accept_pos < sec_site_pos);
        assert!(sec_site_pos < enc_pos);
        assert!(enc_pos < lang_pos);
    }

    #[test]
    fn duplicate_keys_persona_takes_precedence() {
        let transformer = HeaderTransformer::new();
        let persona = chrome_persona();
        let existing = vec![("User-Agent".to_string(), "curl/7.0".to_string())];
        let result = transformer.transform(&existing, &persona);

        let ua_entries: Vec<_> = result
            .headers
            .iter()
            .filter(|(k, _)| k == "User-Agent")
            .collect();
        assert_eq!(ua_entries.len(), 1);
        assert_eq!(ua_entries[0].1, "Mozilla/5.0 Chrome/131");
    }

    #[test]
    fn referer_is_added_when_provided() {
        let transformer = HeaderTransformer::new();
        let persona = chrome_persona();
        let result = transformer.transform_with_referer(&[], &persona, "https://example.com/page");

        let referer = result.headers.iter().find(|(k, _)| k == "Referer").unwrap();
        assert_eq!(referer.1, "https://example.com/page");
    }

    #[test]
    fn empty_existing_headers_works() {
        let transformer = HeaderTransformer::new();
        let persona = chrome_persona();
        let result = transformer.transform(&[], &persona);
        assert!(!result.headers.is_empty());
        assert!(result.headers.len() >= 4);
    }

    #[test]
    fn googlebot_persona_has_no_sec_fetch_headers() {
        let transformer = HeaderTransformer::new();
        let persona = googlebot_persona();
        let result = transformer.transform(&[], &persona);

        let sec_headers: Vec<_> = result
            .headers
            .iter()
            .filter(|(k, _)| k.starts_with("Sec-Fetch"))
            .collect();
        assert!(sec_headers.is_empty());
    }

    #[test]
    fn googlebot_user_agent_is_set() {
        let transformer = HeaderTransformer::new();
        let persona = googlebot_persona();
        let result = transformer.transform(&[], &persona);

        let ua = result
            .headers
            .iter()
            .find(|(k, _)| k == "User-Agent")
            .unwrap();
        assert_eq!(ua.1, "Googlebot/2.1");
    }

    #[test]
    fn headers_not_in_order_list_go_at_end() {
        let transformer = HeaderTransformer::new();
        let persona = chrome_persona();
        let existing = vec![("X-Trailing".to_string(), "end-value".to_string())];
        let result = transformer.transform(&existing, &persona);

        let names: Vec<&str> = result.headers.iter().map(|(k, _)| k.as_str()).collect();
        let trailing_pos = names.iter().position(|&n| n == "X-Trailing").unwrap();
        let last_ordered_pos = names.iter().position(|&n| n == "Accept-Language").unwrap();
        assert!(trailing_pos > last_ordered_pos);
    }

    #[test]
    fn transform_with_referer_preserves_existing_headers() {
        let transformer = HeaderTransformer::new();
        let persona = chrome_persona();
        let existing = vec![("X-Request-Id".to_string(), "abc-123".to_string())];
        let result = transformer.transform_with_referer(&existing, &persona, "https://example.com");

        assert!(result.headers.iter().any(|(k, _)| k == "X-Request-Id"));
        assert!(result.headers.iter().any(|(k, _)| k == "Referer"));
        assert!(result.headers.iter().any(|(k, _)| k == "User-Agent"));
    }

    #[test]
    fn case_insensitive_duplicate_detection() {
        let transformer = HeaderTransformer::new();
        let persona = chrome_persona();
        let existing = vec![("user-agent".to_string(), "curl/7.0".to_string())];
        let result = transformer.transform(&existing, &persona);

        let ua_entries: Vec<_> = result
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .collect();
        assert_eq!(ua_entries.len(), 1);
        assert_eq!(ua_entries[0].1, "Mozilla/5.0 Chrome/131");
    }

    #[test]
    fn transformed_headers_is_clone() {
        let transformer = HeaderTransformer::new();
        let persona = chrome_persona();
        let result = transformer.transform(&[], &persona);
        let cloned = result.clone();
        assert_eq!(result.headers.len(), cloned.headers.len());
    }

    #[test]
    fn transformed_headers_is_debug() {
        let transformer = HeaderTransformer::new();
        let persona = chrome_persona();
        let result = transformer.transform(&[], &persona);
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("TransformedHeaders"));
    }

    #[test]
    fn default_impl_creates_transformer() {
        let transformer = HeaderTransformer::default();
        let persona = chrome_persona();
        let result = transformer.transform(&[], &persona);
        assert!(!result.headers.is_empty());
    }

    #[test]
    fn normalize_preserves_empty_segment() {
        let transformer = HeaderTransformer::new();
        let persona = googlebot_persona();
        let existing = vec![("x-".to_string(), "value".to_string())];
        let result = transformer.transform(&existing, &persona);
        assert!(result.headers.iter().any(|(_, v)| v == "value"));
    }
}
