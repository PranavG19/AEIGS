pub(crate) fn timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Extracts the path component from a full URL string.
pub(crate) fn extract_path_from_url(raw_url: &str) -> Option<String> {
    url::Url::parse(raw_url).ok().map(|u| u.path().to_string())
}
