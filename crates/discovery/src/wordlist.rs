const DEFAULT_WORDLIST_RAW: &str = include_str!("default_wordlist.txt");

pub fn default_wordlist() -> Vec<String> {
    DEFAULT_WORDLIST_RAW
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
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
