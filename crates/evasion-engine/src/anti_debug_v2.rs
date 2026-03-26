use serde::{Deserialize, Serialize};

/// Anti-debugging detection and evasion module (v2).
///
/// Detects attached debuggers, tracers, and analysis tools via multiple
/// orthogonal techniques: ptrace self-attach, TracerPid parsing,
/// timing-based detection, and parent process chain analysis.

/// Anti-debug detection verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DebugVerdict {
    Clean,
    DebuggerAttached,
    TracerDetected,
    TimingAnomaly,
    SuspiciousParent,
    MultipleIndicators,
}

impl std::fmt::Display for DebugVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "clean"),
            Self::DebuggerAttached => write!(f, "debugger-attached"),
            Self::TracerDetected => write!(f, "tracer-detected"),
            Self::TimingAnomaly => write!(f, "timing-anomaly"),
            Self::SuspiciousParent => write!(f, "suspicious-parent"),
            Self::MultipleIndicators => write!(f, "multiple-indicators"),
        }
    }
}

/// Individual anti-debug check type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DebugCheckType {
    PtraceTest,
    TracerPidCheck,
    TimingDetection,
    ParentProcessAnalysis,
    BreakpointScan,
    IsDebuggerPresent,
    EnvironmentCheck,
}

/// Result of a single anti-debug check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugCheckResult {
    pub check_type: DebugCheckType,
    pub detected: bool,
    pub confidence: f64,
    pub details: String,
}

/// Aggregated anti-debug analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiDebugResult {
    pub verdict: DebugVerdict,
    pub overall_confidence: f64,
    pub checks: Vec<DebugCheckResult>,
    pub detected_count: u32,
    pub total_checks: u32,
}

/// Simulated process environment for anti-debug analysis.
#[derive(Debug, Clone, Default)]
pub struct DebugEnvironment {
    pub tracer_pid: Option<u32>,
    pub ptrace_self_result: Option<PtraceResult>,
    pub timing_delta_ns: Option<u64>,
    pub parent_process_name: Option<String>,
    pub parent_pid: Option<u32>,
    pub grandparent_process_name: Option<String>,
    pub environment_variables: Vec<(String, String)>,
    pub int3_trap_triggered: Option<bool>,
    pub is_debugger_present_api: Option<bool>,
    pub proc_status_lines: Vec<String>,
}

/// Result of a ptrace PTRACE_TRACEME self-test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtraceResult {
    Success,
    AlreadyTraced,
    PermissionDenied,
}

/// Configuration for the anti-debug detector.
#[derive(Debug, Clone)]
pub struct AntiDebugConfig {
    pub enable_ptrace_test: bool,
    pub enable_timing_check: bool,
    pub timing_threshold_ns: u64,
    pub enable_parent_analysis: bool,
    pub enable_env_check: bool,
}

impl Default for AntiDebugConfig {
    fn default() -> Self {
        Self {
            enable_ptrace_test: true,
            enable_timing_check: true,
            timing_threshold_ns: 500_000,
            enable_parent_analysis: true,
            enable_env_check: true,
        }
    }
}

/// Known debugger/tracer parent process names.
const DEBUGGER_PARENTS: &[&str] = &[
    "gdb",
    "lldb",
    "strace",
    "ltrace",
    "x64dbg",
    "x32dbg",
    "ollydbg",
    "windbg",
    "ida",
    "ida64",
    "idaq",
    "idaq64",
    "radare2",
    "r2",
    "ghidra",
    "edb",
    "valgrind",
    "rr",
    "dtrace",
    "dtruss",
    "frida",
    "frida-server",
];

/// Environment variables that indicate debugging sessions.
const DEBUG_ENV_VARS: &[&str] = &[
    "DEBUGGER",
    "UNDER_DEBUGGER",
    "GDB_INIT",
    "_JAVA_OPTIONS",
    "DYLD_INSERT_LIBRARIES",
    "LD_PRELOAD",
    "FRIDA_AGENT",
    "ELECTRON_RUN_AS_NODE",
];

/// Anti-debug detection engine (v2).
pub struct AntiDebugDetector {
    config: AntiDebugConfig,
}

impl AntiDebugDetector {
    pub fn new(config: AntiDebugConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(AntiDebugConfig::default())
    }

    /// Run all enabled anti-debug checks against the environment.
    pub fn analyze(&self, env: &DebugEnvironment) -> AntiDebugResult {
        let mut checks = Vec::new();
        let mut detected_count = 0u32;

        let tracer_check = self.check_tracer_pid(env);
        if tracer_check.detected {
            detected_count += 1;
        }
        checks.push(tracer_check);

        if self.config.enable_ptrace_test {
            let ptrace_check = self.check_ptrace(env);
            if ptrace_check.detected {
                detected_count += 1;
            }
            checks.push(ptrace_check);
        }

        if self.config.enable_timing_check {
            let timing_check = self.check_timing(env);
            if timing_check.detected {
                detected_count += 1;
            }
            checks.push(timing_check);
        }

        if self.config.enable_parent_analysis {
            let parent_check = self.check_parent_process(env);
            if parent_check.detected {
                detected_count += 1;
            }
            checks.push(parent_check);
        }

        if self.config.enable_env_check {
            let env_check = self.check_environment(env);
            if env_check.detected {
                detected_count += 1;
            }
            checks.push(env_check);
        }

        if let Some(true) = env.is_debugger_present_api {
            detected_count += 1;
            checks.push(DebugCheckResult {
                check_type: DebugCheckType::IsDebuggerPresent,
                detected: true,
                confidence: 0.95,
                details: "IsDebuggerPresent() API returned true".to_string(),
            });
        }

        if let Some(true) = env.int3_trap_triggered {
            detected_count += 1;
            checks.push(DebugCheckResult {
                check_type: DebugCheckType::BreakpointScan,
                detected: true,
                confidence: 0.9,
                details: "INT3 breakpoint trap was caught by debugger".to_string(),
            });
        }

        let total_checks = checks.len() as u32;
        let overall_confidence = if total_checks == 0 {
            0.0
        } else {
            let max_conf = checks
                .iter()
                .filter(|c| c.detected)
                .map(|c| c.confidence)
                .fold(0.0_f64, f64::max);
            max_conf
        };

        let verdict = match detected_count {
            0 => DebugVerdict::Clean,
            1 => {
                let detected = checks.iter().find(|c| c.detected).unwrap();
                match detected.check_type {
                    DebugCheckType::PtraceTest | DebugCheckType::IsDebuggerPresent => {
                        DebugVerdict::DebuggerAttached
                    }
                    DebugCheckType::TracerPidCheck => DebugVerdict::TracerDetected,
                    DebugCheckType::TimingDetection => DebugVerdict::TimingAnomaly,
                    DebugCheckType::ParentProcessAnalysis => DebugVerdict::SuspiciousParent,
                    _ => DebugVerdict::DebuggerAttached,
                }
            }
            _ => DebugVerdict::MultipleIndicators,
        };

        AntiDebugResult {
            verdict,
            overall_confidence,
            checks,
            detected_count,
            total_checks,
        }
    }

    fn check_tracer_pid(&self, env: &DebugEnvironment) -> DebugCheckResult {
        match env.tracer_pid {
            Some(0) => DebugCheckResult {
                check_type: DebugCheckType::TracerPidCheck,
                detected: false,
                confidence: 0.0,
                details: "TracerPid=0 (no tracer)".to_string(),
            },
            Some(pid) => DebugCheckResult {
                check_type: DebugCheckType::TracerPidCheck,
                detected: true,
                confidence: 0.95,
                details: format!("TracerPid={pid} (non-zero, tracer attached)"),
            },
            None => DebugCheckResult {
                check_type: DebugCheckType::TracerPidCheck,
                detected: false,
                confidence: 0.0,
                details: "TracerPid not available".to_string(),
            },
        }
    }

    fn check_ptrace(&self, env: &DebugEnvironment) -> DebugCheckResult {
        match env.ptrace_self_result {
            Some(PtraceResult::AlreadyTraced) => DebugCheckResult {
                check_type: DebugCheckType::PtraceTest,
                detected: true,
                confidence: 0.95,
                details: "PTRACE_TRACEME failed: already being traced".to_string(),
            },
            Some(PtraceResult::PermissionDenied) => DebugCheckResult {
                check_type: DebugCheckType::PtraceTest,
                detected: false,
                confidence: 0.2,
                details: "PTRACE_TRACEME permission denied (Yama ptrace_scope?)".to_string(),
            },
            Some(PtraceResult::Success) => DebugCheckResult {
                check_type: DebugCheckType::PtraceTest,
                detected: false,
                confidence: 0.0,
                details: "PTRACE_TRACEME succeeded (no tracer)".to_string(),
            },
            None => DebugCheckResult {
                check_type: DebugCheckType::PtraceTest,
                detected: false,
                confidence: 0.0,
                details: "ptrace test not performed".to_string(),
            },
        }
    }

    fn check_timing(&self, env: &DebugEnvironment) -> DebugCheckResult {
        match env.timing_delta_ns {
            Some(delta) if delta > self.config.timing_threshold_ns => DebugCheckResult {
                check_type: DebugCheckType::TimingDetection,
                detected: true,
                confidence: 0.7,
                details: format!(
                    "Timing delta {delta}ns exceeds threshold {}ns (single-step/breakpoint overhead)",
                    self.config.timing_threshold_ns
                ),
            },
            Some(delta) => DebugCheckResult {
                check_type: DebugCheckType::TimingDetection,
                detected: false,
                confidence: 0.0,
                details: format!("Timing delta {delta}ns within normal range"),
            },
            None => DebugCheckResult {
                check_type: DebugCheckType::TimingDetection,
                detected: false,
                confidence: 0.0,
                details: "Timing measurement not available".to_string(),
            },
        }
    }

    fn check_parent_process(&self, env: &DebugEnvironment) -> DebugCheckResult {
        if let Some(ref parent) = env.parent_process_name {
            let parent_lower = parent.to_lowercase();
            for dbg in DEBUGGER_PARENTS {
                if parent_lower == *dbg {
                    return DebugCheckResult {
                        check_type: DebugCheckType::ParentProcessAnalysis,
                        detected: true,
                        confidence: 0.9,
                        details: format!("Parent process is debugger: {parent}"),
                    };
                }
            }

            if let Some(ref grandparent) = env.grandparent_process_name {
                let gp_lower = grandparent.to_lowercase();
                for dbg in DEBUGGER_PARENTS {
                    if gp_lower == *dbg {
                        return DebugCheckResult {
                            check_type: DebugCheckType::ParentProcessAnalysis,
                            detected: true,
                            confidence: 0.75,
                            details: format!("Grandparent process is debugger: {grandparent}"),
                        };
                    }
                }
            }
        }

        DebugCheckResult {
            check_type: DebugCheckType::ParentProcessAnalysis,
            detected: false,
            confidence: 0.0,
            details: "Parent process chain is clean".to_string(),
        }
    }

    fn check_environment(&self, env: &DebugEnvironment) -> DebugCheckResult {
        for (key, _value) in &env.environment_variables {
            let key_upper = key.to_uppercase();
            for debug_var in DEBUG_ENV_VARS {
                if key_upper == *debug_var {
                    return DebugCheckResult {
                        check_type: DebugCheckType::EnvironmentCheck,
                        detected: true,
                        confidence: 0.6,
                        details: format!("Debug-related env var: {key}"),
                    };
                }
            }
        }

        DebugCheckResult {
            check_type: DebugCheckType::EnvironmentCheck,
            detected: false,
            confidence: 0.0,
            details: "No debug-related environment variables".to_string(),
        }
    }
}
