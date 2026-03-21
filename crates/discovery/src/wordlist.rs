use std::path::Path;

const DEFAULT_WORDLIST_RAW: &str = include_str!("default_wordlist.txt");

pub fn default_wordlist() -> Vec<String> {
    DEFAULT_WORDLIST_RAW
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect()
}

pub fn parse_wordlist(content: &str) -> Vec<String> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect()
}

pub fn load_wordlist_from_path(path: &Path) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(content) => parse_wordlist(&content),
        Err(_) => Vec::new(),
    }
}

pub fn seclists_directories(base: &Path) -> Vec<String> {
    let path = base
        .join("Discovery")
        .join("Web-Content")
        .join("raft-large-directories.txt");
    load_wordlist_from_path(&path)
}

pub fn seclists_params(base: &Path) -> Vec<String> {
    let path = base
        .join("Discovery")
        .join("Web-Content")
        .join("burp-parameter-names.txt");
    load_wordlist_from_path(&path)
}
