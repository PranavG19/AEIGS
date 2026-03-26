#[cfg(test)]
mod tests {
    use crate::gpu_browser::{
        all_gpu_identities, chrome_desktop, firefox_desktop, safari_desktop, CdpCommand,
        ChromiumArgs, GpuBrowser, GpuBrowserConfig, GpuBrowserError,
    };

    fn default_config() -> GpuBrowserConfig {
        GpuBrowserConfig::default()
    }

    #[test]
    fn chromium_args_headless_includes_headless_flag() {
        let config = default_config().with_headless(true);
        let args = ChromiumArgs::from_config(&config);
        assert!(args.contains("--headless"));
    }

    #[test]
    fn chromium_args_no_headless_omits_flag() {
        let config = default_config().with_headless(false);
        let args = ChromiumArgs::from_config(&config);
        assert!(!args.contains("--headless"));
    }

    #[test]
    fn chromium_args_angle_includes_gl_flags() {
        let config = default_config().with_use_angle(true);
        let args = ChromiumArgs::from_config(&config);
        assert!(args.contains("--use-gl=angle"));
        assert!(args.contains("--use-angle=default"));
    }

    #[test]
    fn chromium_args_no_angle_omits_gl_flags() {
        let config = default_config().with_use_angle(false);
        let args = ChromiumArgs::from_config(&config);
        assert!(!args.contains("--use-gl"));
    }

    #[test]
    fn chromium_args_sandbox_disabled_includes_no_sandbox() {
        let config = default_config().with_gpu_sandbox_disabled(true);
        let args = ChromiumArgs::from_config(&config);
        assert!(args.contains("--disable-gpu-sandbox"));
        assert!(args.contains("--no-sandbox"));
    }

    #[test]
    fn chromium_args_viewport_dimensions() {
        let config = default_config().with_viewport(1280, 720);
        let args = ChromiumArgs::from_config(&config);
        assert!(args.contains("--window-size=1280,720"));
    }

    #[test]
    fn chromium_args_device_scale_factor_non_default() {
        let config = default_config().with_force_device_scale_factor(2.0);
        let args = ChromiumArgs::from_config(&config);
        assert!(args.contains("--force-device-scale-factor=2"));
    }

    #[test]
    fn chromium_args_device_scale_factor_default_omitted() {
        let config = default_config().with_force_device_scale_factor(1.0);
        let args = ChromiumArgs::from_config(&config);
        assert!(!args.contains("--force-device-scale-factor"));
    }

    #[test]
    fn chromium_args_always_includes_mute_audio() {
        let config = default_config();
        let args = ChromiumArgs::from_config(&config);
        assert!(args.contains("--mute-audio"));
    }

    #[test]
    fn chromium_args_build_returns_vec_string() {
        let config = default_config();
        let args = ChromiumArgs::from_config(&config).build();
        assert!(!args.is_empty());
        assert!(args.iter().all(|a| a.starts_with("--")));
    }

    #[test]
    fn chromium_args_len_and_is_empty() {
        let empty = ChromiumArgs::default();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let args = ChromiumArgs::from_config(&default_config());
        assert!(!args.is_empty());
        assert!(args.len() > 5);
    }

    #[test]
    fn gpu_browser_launch_succeeds_with_valid_config() {
        let browser = GpuBrowser::launch(default_config());
        assert!(browser.is_ok());
        assert!(browser.unwrap().is_launched());
    }

    #[test]
    fn gpu_browser_launch_fails_empty_chromium_path() {
        let config = default_config().with_chromium_path("");
        let result = GpuBrowser::launch(config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("chromium_path"));
    }

    #[test]
    fn gpu_browser_launch_fails_zero_viewport() {
        let config = default_config().with_viewport(0, 1080);
        let result = GpuBrowser::launch(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("viewport"));
    }

    #[test]
    fn canvas_hash_deterministic_for_same_identity() {
        let browser = GpuBrowser::launch(default_config()).unwrap();
        let identity = chrome_desktop();
        let hash1 = browser.generate_canvas_hash(&identity);
        let hash2 = browser.generate_canvas_hash(&identity);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn webgl_hash_deterministic_for_same_identity() {
        let browser = GpuBrowser::launch(default_config()).unwrap();
        let identity = chrome_desktop();
        let hash1 = browser.generate_webgl_hash(&identity);
        let hash2 = browser.generate_webgl_hash(&identity);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn audio_hash_deterministic_for_same_identity() {
        let browser = GpuBrowser::launch(default_config()).unwrap();
        let identity = chrome_desktop();
        let hash1 = browser.generate_audio_hash(&identity);
        let hash2 = browser.generate_audio_hash(&identity);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn different_identities_produce_different_canvas_hashes() {
        let browser = GpuBrowser::launch(default_config()).unwrap();
        let chrome_hash = browser.generate_canvas_hash(&chrome_desktop());
        let firefox_hash = browser.generate_canvas_hash(&firefox_desktop());
        let safari_hash = browser.generate_canvas_hash(&safari_desktop());
        assert_ne!(chrome_hash, firefox_hash);
        assert_ne!(chrome_hash, safari_hash);
        assert_ne!(firefox_hash, safari_hash);
    }

    #[test]
    fn different_identities_produce_different_webgl_hashes() {
        let browser = GpuBrowser::launch(default_config()).unwrap();
        let chrome_hash = browser.generate_webgl_hash(&chrome_desktop());
        let firefox_hash = browser.generate_webgl_hash(&firefox_desktop());
        assert_ne!(chrome_hash, firefox_hash);
    }

    #[test]
    fn different_identities_produce_different_audio_hashes() {
        let browser = GpuBrowser::launch(default_config()).unwrap();
        let chrome_hash = browser.generate_audio_hash(&chrome_desktop());
        let firefox_hash = browser.generate_audio_hash(&firefox_desktop());
        assert_ne!(chrome_hash, firefox_hash);
    }

    #[test]
    fn fingerprint_consistent_flag_is_true_for_deterministic_hashes() {
        let browser = GpuBrowser::launch(default_config()).unwrap();
        let identity = chrome_desktop();
        let fp = browser.get_fingerprint(&identity);
        assert!(fp.consistent);
    }

    #[test]
    fn fingerprint_contains_all_three_hashes() {
        let browser = GpuBrowser::launch(default_config()).unwrap();
        let identity = firefox_desktop();
        let fp = browser.get_fingerprint(&identity);
        assert!(!fp.canvas_hash.is_empty());
        assert!(!fp.webgl_hash.is_empty());
        assert!(!fp.audio_hash.is_empty());
    }

    #[test]
    fn fingerprint_hashes_are_hex_encoded_sha256() {
        let browser = GpuBrowser::launch(default_config()).unwrap();
        let fp = browser.get_fingerprint(&chrome_desktop());
        assert_eq!(fp.canvas_hash.len(), 64);
        assert_eq!(fp.webgl_hash.len(), 64);
        assert_eq!(fp.audio_hash.len(), 64);
        assert!(fp.canvas_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_viewport_produces_different_canvas_hash() {
        let config_a = default_config().with_viewport(1920, 1080);
        let config_b = default_config().with_viewport(1280, 720);
        let browser_a = GpuBrowser::launch(config_a).unwrap();
        let browser_b = GpuBrowser::launch(config_b).unwrap();
        let identity = chrome_desktop();
        let hash_a = browser_a.generate_canvas_hash(&identity);
        let hash_b = browser_b.generate_canvas_hash(&identity);
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn angle_vs_native_produces_different_webgl_hash() {
        let config_angle = default_config().with_use_angle(true);
        let config_native = default_config().with_use_angle(false);
        let browser_angle = GpuBrowser::launch(config_angle).unwrap();
        let browser_native = GpuBrowser::launch(config_native).unwrap();
        let identity = chrome_desktop();
        let hash_angle = browser_angle.generate_webgl_hash(&identity);
        let hash_native = browser_native.generate_webgl_hash(&identity);
        assert_ne!(hash_angle, hash_native);
    }

    #[test]
    fn pre_built_identities_are_distinct() {
        let chrome = chrome_desktop();
        let firefox = firefox_desktop();
        let safari = safari_desktop();
        assert_ne!(chrome.renderer_string, firefox.renderer_string);
        assert_ne!(chrome.renderer_string, safari.renderer_string);
        assert_ne!(chrome.vendor_string, safari.vendor_string);
    }

    #[test]
    fn all_gpu_identities_contains_three_entries() {
        let identities = all_gpu_identities();
        assert_eq!(identities.len(), 3);
        assert!(identities.contains_key("chrome_desktop"));
        assert!(identities.contains_key("firefox_desktop"));
        assert!(identities.contains_key("safari_desktop"));
    }

    #[test]
    fn gpu_identity_equality() {
        let a = chrome_desktop();
        let b = chrome_desktop();
        assert_eq!(a, b);
        assert_ne!(a, firefox_desktop());
    }

    #[test]
    fn cdp_command_display_runtime_evaluate() {
        let cmd = CdpCommand::RuntimeEvaluate {
            expression: "console.log('hello world from gpu test')".to_string(),
        };
        let display = cmd.to_string();
        assert!(display.contains("Runtime.evaluate"));
    }

    #[test]
    fn cdp_command_display_page_navigate() {
        let cmd = CdpCommand::PageNavigate {
            url: "http://localhost:8080/".to_string(),
        };
        assert!(cmd.to_string().contains("Page.navigate"));
    }

    #[test]
    fn cdp_command_display_set_device_metrics() {
        let cmd = CdpCommand::SetDeviceMetrics {
            width: 1920,
            height: 1080,
            device_scale_factor: 2.0,
        };
        let display = cmd.to_string();
        assert!(display.contains("1920x1080"));
        assert!(display.contains("2"));
    }

    #[test]
    fn build_injection_commands_produces_two_commands() {
        let browser = GpuBrowser::launch(default_config()).unwrap();
        let identity = chrome_desktop();
        let commands = browser.build_injection_commands(&identity);
        assert_eq!(commands.len(), 2);
        assert!(matches!(commands[0], CdpCommand::SetDeviceMetrics { .. }));
        assert!(matches!(commands[1], CdpCommand::RuntimeEvaluate { .. }));
    }

    #[test]
    fn build_injection_commands_contains_renderer_string() {
        let browser = GpuBrowser::launch(default_config()).unwrap();
        let identity = chrome_desktop();
        let commands = browser.build_injection_commands(&identity);
        if let CdpCommand::RuntimeEvaluate { expression } = &commands[1] {
            assert!(expression.contains(&identity.renderer_string));
            assert!(expression.contains(&identity.vendor_string));
        } else {
            panic!("expected RuntimeEvaluate");
        }
    }

    #[test]
    fn gpu_browser_config_builder_chain() {
        let config = GpuBrowserConfig::default()
            .with_chromium_path("/opt/chrome/chrome")
            .with_use_angle(false)
            .with_headless(false)
            .with_viewport(3840, 2160)
            .with_gpu_sandbox_disabled(false)
            .with_force_device_scale_factor(1.5);
        assert_eq!(config.chromium_path, "/opt/chrome/chrome");
        assert!(!config.use_angle);
        assert!(!config.headless);
        assert_eq!(config.viewport_width, 3840);
        assert_eq!(config.viewport_height, 2160);
        assert!(!config.gpu_sandbox_disabled);
        assert!((config.force_device_scale_factor - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn gpu_browser_error_display_launch_failed() {
        let err = GpuBrowserError::LaunchFailed("no binary".to_string());
        assert!(err.to_string().contains("launch failed"));
        assert!(err.to_string().contains("no binary"));
    }

    #[test]
    fn gpu_browser_error_display_render_failed() {
        let err = GpuBrowserError::RenderFailed("timeout".to_string());
        assert!(err.to_string().contains("render failed"));
    }

    #[test]
    fn gpu_browser_error_display_cdp_error() {
        let err = GpuBrowserError::CdpError("session closed".to_string());
        assert!(err.to_string().contains("CDP error"));
    }

    #[test]
    fn gpu_browser_config_default_values() {
        let config = GpuBrowserConfig::default();
        assert!(config.use_angle);
        assert!(config.headless);
        assert_eq!(config.viewport_width, 1920);
        assert_eq!(config.viewport_height, 1080);
        assert!(config.gpu_sandbox_disabled);
        assert!((config.force_device_scale_factor - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn chrome_desktop_identity_contains_nvidia() {
        let id = chrome_desktop();
        assert!(id.renderer_string.contains("NVIDIA"));
        assert!(id.vendor_string.contains("Google"));
    }

    #[test]
    fn firefox_desktop_identity_contains_amd() {
        let id = firefox_desktop();
        assert!(id.renderer_string.contains("AMD"));
        assert!(id.vendor_string.contains("ATI"));
    }

    #[test]
    fn safari_desktop_identity_contains_apple() {
        let id = safari_desktop();
        assert!(id.renderer_string.contains("Apple"));
        assert!(id.vendor_string.contains("Apple"));
    }
}
