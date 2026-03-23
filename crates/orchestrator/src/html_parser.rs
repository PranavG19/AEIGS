/// Iterates over HTML tags of a given name, yielding (original_tag, lowercased_tag) pairs.
pub(crate) struct TagIter<'a> {
    html: &'a str,
    lower: String,
    tag_pattern: String,
    pos: usize,
}

impl<'a> TagIter<'a> {
    pub fn new(html: &'a str, tag_name: &str) -> Self {
        Self {
            html,
            lower: html.to_ascii_lowercase(),
            tag_pattern: format!("<{tag_name}"),
            pos: 0,
        }
    }
}

pub(crate) struct TagSlice<'a> {
    pub original: &'a str,
    pub lower: String,
}

impl<'a> Iterator for TagIter<'a> {
    type Item = TagSlice<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.lower[self.pos..].find(&self.tag_pattern)?;
        let abs_start = self.pos + start;
        let end = self.lower[abs_start..].find('>')?;
        let original = &self.html[abs_start..abs_start + end + 1];
        let lower = self.lower[abs_start..abs_start + end + 1].to_string();
        self.pos = abs_start + end + 1;
        Some(TagSlice { original, lower })
    }
}

/// Extracts an attribute value from a tag string.
/// `tag` is the original-cased tag, `tag_lower` is the lowercased version.
/// Returns the value using original case from `tag`.
pub(crate) fn extract_attr(tag: &str, tag_lower: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{attr_name}=");
    let pos = tag_lower.find(&pattern)?;
    let rest = &tag[pos + pattern.len()..];
    let trimmed = rest.trim_start();
    if let Some(stripped) = trimmed.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else if let Some(stripped) = trimmed.strip_prefix('\'') {
        let end = stripped.find('\'')?;
        Some(stripped[..end].to_string())
    } else {
        let end = trimmed
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .unwrap_or(trimmed.len());
        Some(trimmed[..end].to_string())
    }
}

/// Extracts an attribute value from a single (already-cased) tag string.
pub(crate) fn extract_attr_lower(tag_lower: &str, attr_name: &str) -> Option<String> {
    extract_attr(tag_lower, tag_lower, attr_name)
}
