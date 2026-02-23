use std::time::Duration;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

struct TakeoverSignature {
    service_domain_pattern: &'static str,
    response_body_signature: &'static str,
    severity: f64,
}

const TAKEOVER_SIGNATURES: &[TakeoverSignature] = &[
    TakeoverSignature {
        service_domain_pattern: "s3.amazonaws.com",
        response_body_signature: "NoSuchBucket",
        severity: 8.0,
    },
    TakeoverSignature {
        service_domain_pattern: "herokuapp.com",
        response_body_signature: "No such app",
        severity: 7.0,
    },
    TakeoverSignature {
        service_domain_pattern: "github.io",
        response_body_signature: "There isn't a GitHub Pages site here",
        severity: 7.0,
    },
    TakeoverSignature {
        service_domain_pattern: "azurewebsites.net",
        response_body_signature: "404 Web Site not found",
        severity: 7.0,
    },
    TakeoverSignature {
        service_domain_pattern: "cloudfront.net",
        response_body_signature: "Bad request",
        severity: 6.0,
    },
    TakeoverSignature {
        service_domain_pattern: "pantheon.io",
        response_body_signature: "404 Unknown Site",
        severity: 7.0,
    },
    TakeoverSignature {
        service_domain_pattern: "shopify.com",
        response_body_signature: "Sorry, this shop is currently unavailable",
        severity: 7.0,
    },
    TakeoverSignature {
        service_domain_pattern: "tumblr.com",
        response_body_signature: "Whatever you were looking for doesn't currently exist",
        severity: 6.0,
    },
    TakeoverSignature {
        service_domain_pattern: "wordpress.com",
        response_body_signature: "Do you want to register",
        severity: 6.0,
    },
    TakeoverSignature {
        service_domain_pattern: "ghost.io",
        response_body_signature: "The thing you were looking for is no longer here",
        severity: 6.0,
    },
    TakeoverSignature {
        service_domain_pattern: "surge.sh",
        response_body_signature: "project not found",
        severity: 7.0,
    },
    TakeoverSignature {
        service_domain_pattern: "bitbucket.io",
        response_body_signature: "Repository not found",
        severity: 7.0,
    },
    TakeoverSignature {
        service_domain_pattern: "zendesk.com",
        response_body_signature: "Help Center Closed",
        severity: 6.0,
    },
    TakeoverSignature {
        service_domain_pattern: "fastly.net",
        response_body_signature: "Fastly error: unknown domain",
        severity: 7.0,
    },
];

#[derive(Debug, Clone)]
pub struct TakeoverFinding {
    pub subdomain: String,
    pub cname_target: Option<String>,
    pub service: String,
    pub signature: String,
    pub severity: f64,
}

pub struct SubdomainTakeoverDetector {
    client: reqwest::blocking::Client,
}

impl Default for SubdomainTakeoverDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SubdomainTakeoverDetector {
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .redirect(reqwest::redirect::Policy::limited(5))
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    pub fn with_client(client: reqwest::blocking::Client) -> Self {
        Self { client }
    }

    pub fn test_subdomain(&self, subdomain: &str) -> Option<TakeoverFinding> {
        let url = format!("http://{subdomain}");
        let body = self.client.get(&url).send().ok()?.text().ok()?;

        let (service, signature, severity) = is_potential_takeover_target(&body)?;

        Some(TakeoverFinding {
            subdomain: subdomain.to_string(),
            cname_target: None,
            service: service.to_string(),
            signature: signature.to_string(),
            severity,
        })
    }

    pub fn test_subdomains(&self, subdomains: &[String]) -> Vec<TakeoverFinding> {
        subdomains
            .iter()
            .filter_map(|s| self.test_subdomain(s))
            .collect()
    }
}

pub fn is_potential_takeover_target(response_body: &str) -> Option<(&str, &str, f64)> {
    TAKEOVER_SIGNATURES.iter().find_map(|sig| {
        if response_body.contains(sig.response_body_signature) {
            Some((
                sig.service_domain_pattern,
                sig.response_body_signature,
                sig.severity,
            ))
        } else {
            None
        }
    })
}

#[cfg(test)]
#[path = "subdomain_takeover_test.rs"]
mod subdomain_takeover_test;
