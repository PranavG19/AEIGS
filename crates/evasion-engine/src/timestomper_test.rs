use super::timestomper::*;

fn sample_entries() -> Vec<(String, FileTimestamps)> {
    vec![
        (
            "readme.txt".to_string(),
            FileTimestamps {
                created: 1_700_000_000_000,
                modified: 1_700_100_000_000,
                accessed: 1_700_200_000_000,
                mft_changed: None,
            },
        ),
        (
            "config.ini".to_string(),
            FileTimestamps {
                created: 1_700_050_000_000,
                modified: 1_700_150_000_000,
                accessed: 1_700_250_000_000,
                mft_changed: None,
            },
        ),
        (
            "data.bin".to_string(),
            FileTimestamps {
                created: 1_700_080_000_000,
                modified: 1_700_180_000_000,
                accessed: 1_700_280_000_000,
                mft_changed: None,
            },
        ),
    ]
}

#[test]
fn test_survey_directory() {
    let ts = Timestomper::new(TimestompStrategy::MatchMedian);
    let entries = sample_entries();
    let survey = ts.survey_directory(&entries);

    assert_eq!(survey.count, 3);
    assert_eq!(survey.median_created, 1_700_050_000_000);
    assert_eq!(survey.median_modified, 1_700_150_000_000);
    assert_eq!(survey.oldest, 1_700_000_000_000);
    assert_eq!(survey.newest, 1_700_280_000_000);
}

#[test]
fn test_match_median_strategy() {
    let ts = Timestomper::with_seed(TimestompStrategy::MatchMedian, 99);
    let entries = sample_entries();
    let survey = ts.survey_directory(&entries);
    let target = ts.calculate_target_timestamps(&survey);

    let jitter_bound = 3_600_000u64;
    let diff = if target.created > survey.median_created {
        target.created - survey.median_created
    } else {
        survey.median_created - target.created
    };
    assert!(diff <= jitter_bound);
}

#[test]
fn test_match_oldest_strategy() {
    let ts = Timestomper::with_seed(TimestompStrategy::MatchOldest, 99);
    let entries = sample_entries();
    let survey = ts.survey_directory(&entries);
    let target = ts.calculate_target_timestamps(&survey);

    let jitter_bound = 3_600_000u64;
    let diff = if target.created > survey.oldest {
        target.created - survey.oldest
    } else {
        survey.oldest - target.created
    };
    assert!(diff <= jitter_bound);
}

#[test]
fn test_custom_range_strategy() {
    let lo = 1_700_000_000_000u64;
    let hi = 1_700_100_000_000u64;
    let ts = Timestomper::with_seed(TimestompStrategy::CustomRange(lo, hi), 99);
    let survey = DirectorySurvey {
        median_created: 0,
        median_modified: 0,
        oldest: 0,
        newest: 0,
        count: 0,
    };
    let target = ts.calculate_target_timestamps(&survey);

    let mid = lo + (hi - lo) / 2;
    let jitter_bound = 3_600_000u64;
    let diff = if target.created > mid {
        target.created - mid
    } else {
        mid - target.created
    };
    assert!(diff <= jitter_bound);
}

#[test]
fn test_windows_commands_generated() {
    let ts = FileTimestamps {
        created: 1_700_000_000_000,
        modified: 1_700_100_000_000,
        accessed: 1_700_200_000_000,
        mft_changed: Some(1_700_100_000_000),
    };
    let cmds = Timestomper::generate_windows_stomp_commands("C:\\Windows\\Temp\\payload.exe", &ts);
    assert!(cmds.len() >= 3);
    assert!(cmds[0].contains("CreateFile"));
    assert!(cmds[1].contains("SetFileInformationByHandle"));
    assert!(cmds[1].contains("CreationTime"));
    assert!(cmds[1].contains("LastWriteTime"));
    assert!(cmds[2].contains("CloseHandle"));
}

#[test]
fn test_linux_commands_generated() {
    let ts = FileTimestamps {
        created: 1_700_000_000_000,
        modified: 1_700_100_000_000,
        accessed: 1_700_200_000_000,
        mft_changed: None,
    };
    let cmds = Timestomper::generate_linux_stomp_commands("/tmp/payload", &ts);
    assert!(cmds.len() >= 3);
    assert!(cmds[0].contains("open"));
    assert!(cmds[1].contains("futimens"));
    assert!(cmds.iter().any(|c| c.contains("touch")));
}

#[test]
fn test_jitter_within_bounds() {
    let ts = Timestomper::with_seed(TimestompStrategy::MatchMedian, 12345);
    let base = 1_700_000_000_000u64;
    let max_jitter = 5_000u64;

    for offset in 0..100u64 {
        let result = ts.apply_jitter(base + offset, max_jitter);
        let diff = if result > base + offset {
            result - (base + offset)
        } else {
            (base + offset) - result
        };
        assert!(diff <= max_jitter);
    }
}

#[test]
fn test_timestamp_verification() {
    let ts = FileTimestamps {
        created: 1_700_000_000_000,
        modified: 1_700_100_000_000,
        accessed: 1_700_200_000_000,
        mft_changed: None,
    };
    assert!(Timestomper::verify_timestamps("/tmp/test", &ts, 1000));
}
