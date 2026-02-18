use std::cmp::Ordering;
use std::collections::BinaryHeap;

#[derive(Debug, Clone, PartialEq)]
pub struct FuzzTarget {
    pub endpoint: String,
    pub method: String,
    pub parameter: String,
    pub vulnerability_class: VulnerabilityClassTarget,
    pub priority_score: f64,
    pub attempts: u32,
    pub max_attempts: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VulnerabilityClassTarget {
    SqlInjection,
    CrossSiteScripting,
    CommandInjection,
    PathTraversal,
    ServerSideRequestForgery,
    ServerSideTemplateInjection,
    Deserialization,
    HeaderInjection,
    OpenRedirect,
    CrlfInjection,
}

impl std::fmt::Display for VulnerabilityClassTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::SqlInjection => "sqli",
            Self::CrossSiteScripting => "xss",
            Self::CommandInjection => "cmdi",
            Self::PathTraversal => "path-traversal",
            Self::ServerSideRequestForgery => "ssrf",
            Self::ServerSideTemplateInjection => "ssti",
            Self::Deserialization => "deserialization",
            Self::HeaderInjection => "header-injection",
            Self::OpenRedirect => "open-redirect",
            Self::CrlfInjection => "crlf",
        };
        write!(f, "{label}")
    }
}

struct PrioritizedTarget {
    target: FuzzTarget,
}

impl PartialEq for PrioritizedTarget {
    fn eq(&self, other: &Self) -> bool {
        self.target.priority_score == other.target.priority_score
    }
}

impl Eq for PrioritizedTarget {}

impl PartialOrd for PrioritizedTarget {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedTarget {
    fn cmp(&self, other: &Self) -> Ordering {
        self.target
            .priority_score
            .partial_cmp(&other.target.priority_score)
            .unwrap_or(Ordering::Equal)
    }
}

pub struct FuzzScheduler {
    queue: BinaryHeap<PrioritizedTarget>,
    completed_count: u64,
    skipped_count: u64,
}

impl FuzzScheduler {
    pub fn new() -> Self {
        Self {
            queue: BinaryHeap::new(),
            completed_count: 0,
            skipped_count: 0,
        }
    }

    pub fn enqueue(&mut self, target: FuzzTarget) {
        self.queue.push(PrioritizedTarget { target });
    }

    pub fn enqueue_batch(&mut self, targets: Vec<FuzzTarget>) {
        for target in targets {
            self.enqueue(target);
        }
    }

    pub fn next_target(&mut self) -> Option<FuzzTarget> {
        while let Some(prioritized) = self.queue.pop() {
            if prioritized.target.attempts >= prioritized.target.max_attempts {
                self.skipped_count += 1;
                continue;
            }
            return Some(prioritized.target);
        }
        None
    }

    pub fn mark_completed(&mut self, mut target: FuzzTarget) {
        self.completed_count += 1;
        target.attempts += 1;
        if target.attempts < target.max_attempts {
            target.priority_score *= 0.8;
            self.enqueue(target);
        }
    }

    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    pub fn completed_count(&self) -> u64 {
        self.completed_count
    }

    pub fn skipped_count(&self) -> u64 {
        self.skipped_count
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

impl Default for FuzzScheduler {
    fn default() -> Self {
        Self::new()
    }
}
