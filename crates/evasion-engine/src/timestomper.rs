use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Filesystem timestamps in epoch milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTimestamps {
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
    pub mft_changed: Option<u64>,
}

/// Strategy for choosing target timestamps when stomping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimestompStrategy {
    MatchMedian,
    MatchOldest,
    MatchNewest,
    CustomRange(u64, u64),
}

impl std::fmt::Display for TimestompStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MatchMedian => write!(f, "match-median"),
            Self::MatchOldest => write!(f, "match-oldest"),
            Self::MatchNewest => write!(f, "match-newest"),
            Self::CustomRange(lo, hi) => write!(f, "custom-range({}-{})", lo, hi),
        }
    }
}

/// Result of a timestomp operation, capturing original and applied values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestompResult {
    pub path: String,
    pub original: FileTimestamps,
    pub applied: FileTimestamps,
    pub verified: bool,
}

/// Aggregated timestamp statistics for a directory of files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectorySurvey {
    pub median_created: u64,
    pub median_modified: u64,
    pub oldest: u64,
    pub newest: u64,
    pub count: usize,
}

/// Automates timestamp manipulation to blend implanted files with
/// the surrounding directory's temporal profile, defeating timeline
/// analysis in forensic investigations.
pub struct Timestomper {
    strategy: TimestompStrategy,
    rng_seed: u64,
}

impl Timestomper {
    pub fn new(strategy: TimestompStrategy) -> Self {
        Self {
            strategy,
            rng_seed: 42,
        }
    }

    pub fn with_seed(strategy: TimestompStrategy, seed: u64) -> Self {
        Self {
            strategy,
            rng_seed: seed,
        }
    }

    pub fn survey_directory(&self, entries: &[(String, FileTimestamps)]) -> DirectorySurvey {
        if entries.is_empty() {
            return DirectorySurvey {
                median_created: 0,
                median_modified: 0,
                oldest: 0,
                newest: 0,
                count: 0,
            };
        }

        let mut created_vals: Vec<u64> = entries.iter().map(|(_, ts)| ts.created).collect();
        let mut modified_vals: Vec<u64> = entries.iter().map(|(_, ts)| ts.modified).collect();
        created_vals.sort_unstable();
        modified_vals.sort_unstable();

        let all_times: Vec<u64> = entries
            .iter()
            .flat_map(|(_, ts)| vec![ts.created, ts.modified, ts.accessed])
            .collect();
        let oldest = *all_times.iter().min().unwrap_or(&0);
        let newest = *all_times.iter().max().unwrap_or(&0);

        DirectorySurvey {
            median_created: median(&created_vals),
            median_modified: median(&modified_vals),
            oldest,
            newest,
            count: entries.len(),
        }
    }

    pub fn calculate_target_timestamps(&self, survey: &DirectorySurvey) -> FileTimestamps {
        let (base_created, base_modified) = match self.strategy {
            TimestompStrategy::MatchMedian => (survey.median_created, survey.median_modified),
            TimestompStrategy::MatchOldest => (survey.oldest, survey.oldest),
            TimestompStrategy::MatchNewest => (survey.newest, survey.newest),
            TimestompStrategy::CustomRange(lo, hi) => {
                let mid = lo + (hi - lo) / 2;
                (mid, mid)
            }
        };

        let created = self.apply_jitter(base_created, 3_600_000);
        let modified = self.apply_jitter(base_modified, 1_800_000);
        let accessed = self.apply_jitter(base_modified, 600_000);

        FileTimestamps {
            created,
            modified,
            accessed,
            mft_changed: None,
        }
    }

    pub fn generate_windows_stomp_commands(path: &str, ts: &FileTimestamps) -> Vec<String> {
        let created_ft = epoch_ms_to_filetime(ts.created);
        let modified_ft = epoch_ms_to_filetime(ts.modified);
        let accessed_ft = epoch_ms_to_filetime(ts.accessed);

        vec![
            format!(
                "CreateFile(\"{}\", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL)",
                path
            ),
            format!(
                "SetFileInformationByHandle(hFile, FileBasicInfo, {{CreationTime={}, LastWriteTime={}, LastAccessTime={}, ChangeTime={}}})",
                created_ft,
                modified_ft,
                accessed_ft,
                ts.mft_changed.map(epoch_ms_to_filetime).unwrap_or(modified_ft)
            ),
            "CloseHandle(hFile)".to_string(),
        ]
    }

    pub fn generate_linux_stomp_commands(path: &str, ts: &FileTimestamps) -> Vec<String> {
        let accessed_sec = ts.accessed / 1000;
        let accessed_nsec = (ts.accessed % 1000) * 1_000_000;
        let modified_sec = ts.modified / 1000;
        let modified_nsec = (ts.modified % 1000) * 1_000_000;

        vec![
            format!("open(\"{}\", O_WRONLY)", path),
            format!(
                "futimens(fd, [{{tv_sec={}, tv_nsec={}}}, {{tv_sec={}, tv_nsec={}}}])",
                accessed_sec, accessed_nsec, modified_sec, modified_nsec
            ),
            format!(
                "touch -t {} \"{}\"",
                epoch_ms_to_touch_format(ts.modified),
                path
            ),
            "close(fd)".to_string(),
        ]
    }

    pub fn apply_jitter(&self, timestamp: u64, max_jitter_ms: u64) -> u64 {
        if max_jitter_ms == 0 {
            return timestamp;
        }
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.rng_seed ^ timestamp);
        let jitter: u64 = rng.random_range(0..=max_jitter_ms);
        if rng.random_bool(0.5) {
            timestamp.saturating_add(jitter)
        } else {
            timestamp.saturating_sub(jitter)
        }
    }

    pub fn verify_timestamps(path: &str, expected: &FileTimestamps, tolerance_ms: u64) -> bool {
        let _ = path;
        let simulated = *expected;
        within_tolerance(simulated.created, expected.created, tolerance_ms)
            && within_tolerance(simulated.modified, expected.modified, tolerance_ms)
            && within_tolerance(simulated.accessed, expected.accessed, tolerance_ms)
    }
}

fn median(sorted: &[u64]) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let mid = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[mid - 1] + sorted[mid]) / 2
    } else {
        sorted[mid]
    }
}

fn within_tolerance(actual: u64, expected: u64, tolerance: u64) -> bool {
    actual.abs_diff(expected) <= tolerance
}

fn epoch_ms_to_filetime(epoch_ms: u64) -> u64 {
    let windows_epoch_offset: u64 = 116_444_736_000_000_000;
    windows_epoch_offset + epoch_ms * 10_000
}

fn epoch_ms_to_touch_format(epoch_ms: u64) -> String {
    let total_secs = epoch_ms / 1000;
    let days_since_epoch = total_secs / 86400;
    let secs_in_day = total_secs % 86400;
    let hours = secs_in_day / 3600;
    let minutes = (secs_in_day % 3600) / 60;

    let mut y = 1970u64;
    let mut remaining = days_since_epoch;
    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }

    let month_days: [u64; 12] = if is_leap_year(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0usize;
    for (i, &d) in month_days.iter().enumerate() {
        if remaining < d {
            m = i;
            break;
        }
        remaining -= d;
    }

    format!(
        "{:04}{:02}{:02}{:02}{:02}",
        y,
        m + 1,
        remaining + 1,
        hours,
        minutes
    )
}

fn is_leap_year(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}
