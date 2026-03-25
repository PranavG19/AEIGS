#[cfg(test)]
mod tests {
    use crate::continuous_scheduler::{
        BandwidthLimits, ContinuousScheduler, CronSchedule, DayOfWeek, QuietHours, RiskLevel,
        ScanMode, ScheduledScan,
    };

    fn make_scan(id: &str, risk: RiskLevel) -> ScheduledScan {
        ScheduledScan {
            target_url: format!("http://localhost:8080/{id}"),
            scan_id: id.to_string(),
            schedule: CronSchedule {
                minutes: Some(vec![0]),
                hours: Some(vec![10]),
                days_of_week: None,
            },
            risk_level: risk,
            mode: ScanMode::Full,
            alert_on_new_findings: true,
            quiet_hours: None,
            bandwidth_limits: BandwidthLimits::default(),
            enabled: true,
            last_run_timestamp_ms: None,
        }
    }

    #[test]
    fn day_of_week_iso_roundtrip() {
        for d in [
            DayOfWeek::Monday,
            DayOfWeek::Tuesday,
            DayOfWeek::Wednesday,
            DayOfWeek::Thursday,
            DayOfWeek::Friday,
            DayOfWeek::Saturday,
            DayOfWeek::Sunday,
        ] {
            assert_eq!(DayOfWeek::from_iso(d.iso_number()), Some(d));
        }
        assert_eq!(DayOfWeek::from_iso(0), None);
        assert_eq!(DayOfWeek::from_iso(8), None);
    }

    #[test]
    fn risk_level_intervals_decrease_with_severity() {
        assert!(
            RiskLevel::Critical.default_interval_secs() < RiskLevel::High.default_interval_secs()
        );
        assert!(
            RiskLevel::High.default_interval_secs() < RiskLevel::Medium.default_interval_secs()
        );
        assert!(RiskLevel::Medium.default_interval_secs() < RiskLevel::Low.default_interval_secs());
    }

    #[test]
    fn quiet_hours_simple_window() {
        let qh = QuietHours {
            start_hour: 22,
            end_hour: 6,
            days: vec![DayOfWeek::Monday, DayOfWeek::Tuesday],
        };
        assert!(qh.is_quiet(23, DayOfWeek::Monday));
        assert!(qh.is_quiet(0, DayOfWeek::Tuesday));
        assert!(qh.is_quiet(5, DayOfWeek::Monday));
        assert!(!qh.is_quiet(6, DayOfWeek::Monday));
        assert!(!qh.is_quiet(10, DayOfWeek::Monday));
        assert!(!qh.is_quiet(23, DayOfWeek::Wednesday));
    }

    #[test]
    fn quiet_hours_non_wrapping_window() {
        let qh = QuietHours {
            start_hour: 9,
            end_hour: 17,
            days: vec![DayOfWeek::Friday],
        };
        assert!(qh.is_quiet(9, DayOfWeek::Friday));
        assert!(qh.is_quiet(12, DayOfWeek::Friday));
        assert!(!qh.is_quiet(17, DayOfWeek::Friday));
        assert!(!qh.is_quiet(8, DayOfWeek::Friday));
    }

    #[test]
    fn cron_schedule_wildcard_matches_everything() {
        let sched = CronSchedule {
            minutes: None,
            hours: None,
            days_of_week: None,
        };
        assert!(sched.matches(0, 0, DayOfWeek::Monday));
        assert!(sched.matches(59, 23, DayOfWeek::Sunday));
    }

    #[test]
    fn cron_schedule_specific_values() {
        let sched = CronSchedule {
            minutes: Some(vec![0, 30]),
            hours: Some(vec![8, 20]),
            days_of_week: Some(vec![DayOfWeek::Monday, DayOfWeek::Friday]),
        };
        assert!(sched.matches(0, 8, DayOfWeek::Monday));
        assert!(sched.matches(30, 20, DayOfWeek::Friday));
        assert!(!sched.matches(15, 8, DayOfWeek::Monday));
        assert!(!sched.matches(0, 12, DayOfWeek::Monday));
        assert!(!sched.matches(0, 8, DayOfWeek::Wednesday));
    }

    #[test]
    fn scheduler_add_and_remove() {
        let mut scheduler = ContinuousScheduler::new();
        assert_eq!(scheduler.scan_count(), 0);
        scheduler.add_scan(make_scan("scan-1", RiskLevel::High));
        assert_eq!(scheduler.scan_count(), 1);
        assert!(scheduler.get_scan("scan-1").is_some());
        let removed = scheduler.remove_scan("scan-1");
        assert!(removed.is_some());
        assert_eq!(scheduler.scan_count(), 0);
    }

    #[test]
    fn scheduler_replace_existing_scan() {
        let mut scheduler = ContinuousScheduler::new();
        let mut s1 = make_scan("dup", RiskLevel::Low);
        s1.target_url = "http://old".to_string();
        scheduler.add_scan(s1);
        let mut s2 = make_scan("dup", RiskLevel::Critical);
        s2.target_url = "http://new".to_string();
        scheduler.add_scan(s2);
        assert_eq!(scheduler.scan_count(), 1);
        assert_eq!(
            scheduler.get_scan("dup").unwrap().risk_level,
            RiskLevel::Critical
        );
    }

    #[test]
    fn evaluate_due_scans() {
        let mut scheduler = ContinuousScheduler::new();
        scheduler.add_scan(make_scan("alpha", RiskLevel::Critical));
        scheduler.add_scan(make_scan("beta", RiskLevel::High));

        let result = scheduler.evaluate(0, 0, 10, DayOfWeek::Monday);
        assert_eq!(result.due_scans, vec!["alpha", "beta"]);
        assert!(result.skipped_quiet_hours.is_empty());
        assert!(result.skipped_bandwidth.is_empty());
    }

    #[test]
    fn evaluate_respects_quiet_hours() {
        let mut scheduler = ContinuousScheduler::new();
        let mut scan = make_scan("nightwatch", RiskLevel::Medium);
        scan.schedule = CronSchedule {
            minutes: None,
            hours: None,
            days_of_week: None,
        };
        scan.quiet_hours = Some(QuietHours {
            start_hour: 22,
            end_hour: 6,
            days: vec![DayOfWeek::Monday],
        });
        scheduler.add_scan(scan);

        let result = scheduler.evaluate(0, 30, 23, DayOfWeek::Monday);
        assert!(result.due_scans.is_empty());
        assert_eq!(result.skipped_quiet_hours, vec!["nightwatch"]);
        assert!(result.next_possible_window_secs.is_some());
    }

    #[test]
    fn evaluate_respects_bandwidth_limit() {
        let mut scheduler = ContinuousScheduler::new();
        let mut scan = make_scan("bw-test", RiskLevel::Low);
        scan.bandwidth_limits.max_concurrent_scans = 1;
        scan.schedule = CronSchedule {
            minutes: None,
            hours: None,
            days_of_week: None,
        };
        scheduler.add_scan(scan);

        scheduler.mark_scan_started("other", 100);

        let result = scheduler.evaluate(1_000_000, 0, 10, DayOfWeek::Monday);
        assert!(result.due_scans.is_empty());
        assert_eq!(result.skipped_bandwidth, vec!["bw-test"]);
    }

    #[test]
    fn evaluate_skips_recently_run_scan() {
        let mut scheduler = ContinuousScheduler::new();
        let mut scan = make_scan("recent", RiskLevel::Critical);
        scan.schedule = CronSchedule {
            minutes: None,
            hours: None,
            days_of_week: None,
        };
        scheduler.add_scan(scan);
        let now = 1_700_000_000_000u64;
        scheduler.mark_scan_started("recent", now);

        let shortly_after = now + 1000;
        let result = scheduler.evaluate(shortly_after, 0, 10, DayOfWeek::Monday);
        assert!(result.due_scans.is_empty());
    }

    #[test]
    fn evaluate_disabled_scans_ignored() {
        let mut scheduler = ContinuousScheduler::new();
        let mut scan = make_scan("disabled", RiskLevel::Critical);
        scan.enabled = false;
        scan.schedule = CronSchedule {
            minutes: None,
            hours: None,
            days_of_week: None,
        };
        scheduler.add_scan(scan);

        let result = scheduler.evaluate(0, 0, 10, DayOfWeek::Monday);
        assert!(result.due_scans.is_empty());
    }

    #[test]
    fn scans_by_priority_ordering() {
        let mut scheduler = ContinuousScheduler::new();
        scheduler.add_scan(make_scan("low-1", RiskLevel::Low));
        scheduler.add_scan(make_scan("crit-1", RiskLevel::Critical));
        scheduler.add_scan(make_scan("med-1", RiskLevel::Medium));
        scheduler.add_scan(make_scan("high-1", RiskLevel::High));

        let ordered = scheduler.scans_by_priority();
        assert_eq!(ordered, vec!["crit-1", "high-1", "med-1", "low-1"]);
    }

    #[test]
    fn overdue_scans_never_run_are_always_overdue() {
        let mut scheduler = ContinuousScheduler::new();
        scheduler.add_scan(make_scan("never-run", RiskLevel::Low));
        let overdue = scheduler.overdue_scans(1_700_000_000_000);
        assert_eq!(overdue, vec!["never-run"]);
    }

    #[test]
    fn overdue_scans_within_interval_not_overdue() {
        let mut scheduler = ContinuousScheduler::new();
        scheduler.add_scan(make_scan("fresh", RiskLevel::Critical));
        let now = 1_700_000_000_000u64;
        scheduler.mark_scan_started("fresh", now);
        let overdue = scheduler.overdue_scans(now + 1800_000);
        assert!(overdue.is_empty());
    }

    #[test]
    fn mark_scan_completed_decrements_active_count() {
        let mut scheduler = ContinuousScheduler::new();
        let mut scan = make_scan("counted", RiskLevel::High);
        scan.bandwidth_limits.max_concurrent_scans = 1;
        scan.schedule = CronSchedule {
            minutes: None,
            hours: None,
            days_of_week: None,
        };
        scheduler.add_scan(scan);

        scheduler.mark_scan_started("counted", 100);
        let eval = scheduler.evaluate(1_000_000_000, 0, 10, DayOfWeek::Monday);
        assert!(eval.due_scans.is_empty());

        scheduler.mark_scan_completed();
        let eval2 = scheduler.evaluate(1_000_000_000, 0, 10, DayOfWeek::Monday);
        assert_eq!(eval2.due_scans, vec!["counted"]);
    }

    #[test]
    fn diff_only_mode_stored_correctly() {
        let mut scan = make_scan("diff", RiskLevel::Medium);
        scan.mode = ScanMode::DiffOnly;
        let scheduler = {
            let mut s = ContinuousScheduler::new();
            s.add_scan(scan);
            s
        };
        assert_eq!(scheduler.get_scan("diff").unwrap().mode, ScanMode::DiffOnly);
    }

    #[test]
    fn bandwidth_limits_defaults_are_sane() {
        let bw = BandwidthLimits::default();
        assert!(bw.max_requests_per_second > 0);
        assert!(bw.max_concurrent_scans > 0);
        assert!(bw.max_bandwidth_bytes_per_sec > 0);
    }
}
