use crate::red_agent::RedRoundResult;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A lesson learned from a round of combat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lesson {
    pub technique: String,
    pub endpoint: String,
    pub description: String,
    pub source: LessonSource,
    pub weight: f64,
    pub round: usize,
    pub match_id: String,
}

/// Where the lesson came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LessonSource {
    RedSuccess,
    RedFailure,
    BluePatchWorked,
    BluePatchFailed,
}

/// Persistent lessons database that accumulates across matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LessonsDb {
    pub lessons: Vec<Lesson>,
    pub decay_factor: f64,
}

impl LessonsDb {
    pub fn new() -> Self {
        Self {
            lessons: Vec::new(),
            decay_factor: 0.8,
        }
    }

    /// Extract lessons from a completed round.
    pub fn extract_lessons(
        &mut self,
        round: usize,
        match_id: &str,
        red_result: &RedRoundResult,
        patches_that_blocked: &[String],
        patches_that_failed: &[String],
    ) {
        // Lesson from red success: which technique worked
        if red_result.flag_captured {
            for technique in &red_result.techniques_used {
                self.add_lesson(Lesson {
                    technique: technique.clone(),
                    endpoint: extract_endpoint_from_technique(technique),
                    description: format!(
                        "{} on {} captured the flag",
                        technique,
                        extract_endpoint_from_technique(technique)
                    ),
                    source: LessonSource::RedSuccess,
                    weight: 1.0,
                    round,
                    match_id: match_id.to_string(),
                });
            }
        }

        // Lesson from red failure: blocked attacks
        for technique in &red_result.techniques_used {
            if red_result.blocked_count > 0 && !red_result.flag_captured {
                self.add_lesson(Lesson {
                    technique: technique.clone(),
                    endpoint: extract_endpoint_from_technique(technique),
                    description: format!(
                        "{} was blocked — Blue has patched this vector",
                        technique
                    ),
                    source: LessonSource::RedFailure,
                    weight: 0.7,
                    round,
                    match_id: match_id.to_string(),
                });
            }
        }

        // Lesson from effective patches
        for patch_desc in patches_that_blocked {
            self.add_lesson(Lesson {
                technique: "defense".to_string(),
                endpoint: patch_desc.clone(),
                description: format!("Patch '{}' successfully blocked attacks", patch_desc),
                source: LessonSource::BluePatchWorked,
                weight: 1.0,
                round,
                match_id: match_id.to_string(),
            });
        }

        // Lesson from failed patches
        for patch_desc in patches_that_failed {
            self.add_lesson(Lesson {
                technique: "defense".to_string(),
                endpoint: patch_desc.clone(),
                description: format!("Patch '{}' was bypassed — need stronger rules", patch_desc),
                source: LessonSource::BluePatchFailed,
                weight: 0.8,
                round,
                match_id: match_id.to_string(),
            });
        }
    }

    /// Add a lesson, merging with existing if duplicate.
    fn add_lesson(&mut self, lesson: Lesson) {
        // Check for existing similar lesson
        if let Some(existing) = self.lessons.iter_mut().find(|l| {
            l.technique == lesson.technique
                && l.endpoint == lesson.endpoint
                && l.source == lesson.source
        }) {
            // Reinforce existing lesson
            existing.weight = (existing.weight + lesson.weight).min(2.0);
            existing.round = lesson.round;
            existing.description = lesson.description;
        } else {
            self.lessons.push(lesson);
        }
    }

    /// Apply EMA decay to all lessons (called between matches).
    pub fn apply_decay(&mut self) {
        for lesson in &mut self.lessons {
            lesson.weight *= self.decay_factor;
        }
        // Remove lessons that have decayed below threshold
        self.lessons.retain(|l| l.weight > 0.1);
    }

    /// Get the top-N most relevant lessons, sorted by weight.
    pub fn top_lessons(&self, n: usize) -> Vec<&Lesson> {
        let mut sorted: Vec<&Lesson> = self.lessons.iter().collect();
        sorted.sort_by(|a, b| b.weight.partial_cmp(&a.weight).unwrap_or(std::cmp::Ordering::Equal));
        sorted.truncate(n);
        sorted
    }

    /// Format top lessons for inclusion in an agent briefing.
    pub fn briefing_text(&self, n: usize) -> String {
        let top = self.top_lessons(n);
        if top.is_empty() {
            return String::new();
        }

        let mut text = String::from("## Lessons from Previous Matches\n\n");
        for (i, lesson) in top.iter().enumerate() {
            text.push_str(&format!(
                "{}. {} (weight: {:.1})\n",
                i + 1,
                lesson.description,
                lesson.weight
            ));
        }
        text.push('\n');
        text
    }

    /// Save lessons database to a JSON file.
    pub async fn save(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        tokio::fs::write(path, json).await
    }

    /// Load lessons database from a JSON file. Returns empty if file doesn't exist.
    pub async fn load(path: &Path) -> Self {
        match tokio::fs::read_to_string(path).await {
            Ok(content) => serde_json::from_str(&content).unwrap_or_else(|e| {
                tracing::warn!("Failed to parse lessons DB: {e}");
                Self::new()
            }),
            Err(_) => Self::new(),
        }
    }

    /// Total number of lessons stored.
    pub fn len(&self) -> usize {
        self.lessons.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.lessons.is_empty()
    }
}

impl Default for LessonsDb {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract a probable endpoint from a technique name (e.g., "sqli_search_0" → "/search").
fn extract_endpoint_from_technique(technique: &str) -> String {
    let lower = technique.to_lowercase();
    if lower.contains("search") || lower.contains("sqli_search") {
        "/search".to_string()
    } else if lower.contains("profile") || lower.contains("idor") {
        "/profile".to_string()
    } else if lower.contains("lfi") || lower.contains("lfi_file") {
        "/file".to_string()
    } else if lower.contains("template") || lower.contains("ssti") {
        "/template".to_string()
    } else if lower.contains("admin") || lower.contains("jwt") {
        "/admin".to_string()
    } else if lower.contains("login") {
        "/login".to_string()
    } else if lower.contains("flag") {
        "/flag".to_string()
    } else if lower.contains("file") {
        "/file".to_string()
    } else {
        "/unknown".to_string()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "lessons_db_test.rs"]
mod lessons_db_test;
