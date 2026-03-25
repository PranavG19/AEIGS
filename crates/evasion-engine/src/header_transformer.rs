use std::collections::HashMap;

use crate::persona::Persona;

/// Ordered HTTP headers after persona-based transformation.
///
/// Contains the final header list with persona headers merged, existing
/// headers preserved (without overwriting persona values), and all entries
/// ordered according to the persona's canonical browser header ordering.
#[derive(Debug, Clone)]
pub struct TransformedHeaders {
    pub headers: Vec<(String, String)>,
}

/// Transforms request headers to match a persona's browser fingerprint.
///
/// Merges persona-specific headers (User-Agent, Accept, Sec-Fetch-*) with
/// existing request headers, normalizes header names, and reorders them
/// to match the persona's canonical browser header ordering.
#[derive(Debug)]
pub struct HeaderTransformer;

impl Default for HeaderTransformer {
    fn default() -> Self {
        Self::new()
    }
}

impl HeaderTransformer {
    pub fn new() -> Self {
        Self
    }

    pub fn transform(
        &self,
        existing_headers: &[(String, String)],
        persona: &Persona,
    ) -> TransformedHeaders {
        self.build_headers(existing_headers, persona, None)
    }

    pub fn transform_with_referer(
        &self,
        existing_headers: &[(String, String)],
        persona: &Persona,
        referer: &str,
    ) -> TransformedHeaders {
        self.build_headers(existing_headers, persona, Some(referer))
    }

    fn build_headers(
        &self,
        existing_headers: &[(String, String)],
        persona: &Persona,
        referer: Option<&str>,
    ) -> TransformedHeaders {
        let mut merged = self.collect_persona_headers(persona);

        if let Some(url) = referer {
            merged.insert("Referer".to_string(), url.to_string());
        }

        for (key, value) in existing_headers {
            let normalized = normalize_header_name(key);
            merged.entry(normalized).or_insert_with(|| value.clone());
        }

        let headers = self.order_headers(&merged, &persona.header_order);
        TransformedHeaders { headers }
    }

    fn collect_persona_headers(&self, persona: &Persona) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("User-Agent".to_string(), persona.user_agent.clone());
        map.insert("Accept".to_string(), persona.accept_header.clone());
        map.insert(
            "Accept-Language".to_string(),
            persona.accept_language.clone(),
        );
        map.insert(
            "Accept-Encoding".to_string(),
            persona.accept_encoding.clone(),
        );

        for (key, value) in &persona.sec_fetch_headers {
            map.insert(key.clone(), value.clone());
        }

        map
    }

    fn order_headers(
        &self,
        merged: &HashMap<String, String>,
        header_order: &[String],
    ) -> Vec<(String, String)> {
        let mut ordered: Vec<(String, String)> = Vec::with_capacity(merged.len());
        let mut placed = HashMap::with_capacity(header_order.len());

        for canonical in header_order {
            let lower = canonical.to_lowercase();
            if let Some(value) = find_by_lowercase(merged, &lower) {
                ordered.push((canonical.clone(), value.clone()));
                placed.insert(lower, true);
            }
        }

        let mut remaining: Vec<(String, String)> = merged
            .iter()
            .filter(|(k, _)| !placed.contains_key(&k.to_lowercase()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        remaining.sort_by(|(a, _), (b, _)| a.cmp(b));

        ordered.extend(remaining);
        ordered
    }
}

fn normalize_header_name(name: &str) -> String {
    name.split('-')
        .map(|segment| {
            let mut chars = segment.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => {
                    let upper: String = first.to_uppercase().collect();
                    upper + &chars.as_str().to_lowercase()
                }
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

fn find_by_lowercase<'a>(map: &'a HashMap<String, String>, lower: &str) -> Option<&'a String> {
    map.iter()
        .find(|(k, _)| k.to_lowercase() == lower)
        .map(|(_, v)| v)
}

#[cfg(test)]
#[path = "header_transformer_test.rs"]
mod header_transformer_test;
