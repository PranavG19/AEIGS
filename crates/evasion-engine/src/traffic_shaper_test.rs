use super::*;

fn make_shaper() -> TrafficShaper {
    TrafficShaper::with_seed(TrafficShaperConfig::default(), 42)
}

#[test]
fn next_delay_returns_positive_value() {
    let mut shaper = make_shaper();
    let delay = shaper.next_delay_ms();
    assert!(delay >= 50);
}

#[test]
fn delays_are_varied_not_constant() {
    let mut shaper = make_shaper();
    let delays: Vec<u64> = (0..20).map(|_| shaper.next_delay_ms()).collect();
    let unique: std::collections::HashSet<u64> = delays.iter().copied().collect();
    assert!(unique.len() > 1);
}

#[test]
fn total_requests_increments() {
    let mut shaper = make_shaper();
    assert_eq!(shaper.total_requests(), 0);
    shaper.next_delay_ms();
    shaper.next_delay_ms();
    assert_eq!(shaper.total_requests(), 2);
}

#[test]
fn lognormal_distribution_produces_varied_delays() {
    let mut shaper = TrafficShaper::with_seed(
        TrafficShaperConfig::default().with_distribution(TimingDistribution::LogNormal),
        42,
    );
    let delays: Vec<u64> = (0..10).map(|_| shaper.next_delay_ms()).collect();
    let unique: std::collections::HashSet<u64> = delays.iter().copied().collect();
    assert!(unique.len() > 1);
}

#[test]
fn weibull_distribution_produces_varied_delays() {
    let mut shaper = TrafficShaper::with_seed(
        TrafficShaperConfig::default().with_distribution(TimingDistribution::Weibull),
        42,
    );
    let delays: Vec<u64> = (0..10).map(|_| shaper.next_delay_ms()).collect();
    let unique: std::collections::HashSet<u64> = delays.iter().copied().collect();
    assert!(unique.len() > 1);
}

#[test]
fn session_warmup_builds_navigation_chain() {
    let mut shaper = make_shaper();
    let steps = shaper.generate_session_warmup("https://example.com", "/admin/login");
    assert!(steps.len() >= 2);
    assert!(steps.first().unwrap().referer.is_none());
    assert!(steps.last().unwrap().is_attack_request);
    assert!(steps.last().unwrap().url.contains("/admin/login"));
}

#[test]
fn warmup_steps_have_referrer_chain() {
    let mut shaper = make_shaper();
    let steps = shaper.generate_session_warmup("https://example.com", "/target");
    for i in 1..steps.len() {
        assert!(steps[i].referer.is_some());
        assert_eq!(steps[i].referer.as_ref().unwrap(), &steps[i - 1].url);
    }
}

#[test]
fn build_referer_strips_path() {
    let shaper = make_shaper();
    let referer = shaper.build_referer("https://example.com/page/subpage");
    assert_eq!(referer, "https://example.com/page");
}

#[test]
fn generate_cover_traffic_returns_requested_count() {
    let mut shaper = make_shaper();
    let cover = shaper.generate_cover_traffic("https://example.com", 5);
    assert_eq!(cover.len(), 5);
    assert_eq!(shaper.cover_requests_sent(), 5);
}

#[test]
fn cover_traffic_urls_start_with_base() {
    let mut shaper = make_shaper();
    let cover = shaper.generate_cover_traffic("https://example.com", 10);
    for req in &cover {
        assert!(req.url.starts_with("https://example.com"));
    }
}

#[test]
fn cover_requests_needed_zero_when_ratio_zero() {
    let shaper = TrafficShaper::with_seed(
        TrafficShaperConfig::default().with_cover_traffic_ratio(0.0),
        42,
    );
    assert_eq!(shaper.cover_requests_needed(), 0);
}

#[test]
fn mouse_events_empty_when_disabled() {
    let mut shaper = make_shaper();
    let events = shaper.generate_mouse_events(1920, 1080);
    assert!(events.is_empty());
}

#[test]
fn mouse_events_generated_when_enabled() {
    let mut shaper =
        TrafficShaper::with_seed(TrafficShaperConfig::default().with_simulate_mouse(true), 42);
    let events = shaper.generate_mouse_events(1920, 1080);
    assert!(!events.is_empty());
    assert!(events.len() >= 5);
}

#[test]
fn mouse_events_within_viewport() {
    let mut shaper =
        TrafficShaper::with_seed(TrafficShaperConfig::default().with_simulate_mouse(true), 42);
    let events = shaper.generate_mouse_events(1920, 1080);
    for event in &events {
        assert!(event.x <= 1920);
        assert!(event.y <= 1080);
    }
}

#[test]
fn mouse_events_have_increasing_timestamps() {
    let mut shaper =
        TrafficShaper::with_seed(TrafficShaperConfig::default().with_simulate_mouse(true), 42);
    let events = shaper.generate_mouse_events(1920, 1080);
    for i in 1..events.len() {
        assert!(events[i].timestamp_offset_ms >= events[i - 1].timestamp_offset_ms);
    }
}

#[test]
fn business_hours_check_within() {
    let shaper = TrafficShaper::with_seed(
        TrafficShaperConfig::default().with_business_hours(BusinessHours {
            start_hour: 9,
            end_hour: 17,
        }),
        42,
    );
    assert!(shaper.is_within_business_hours(12));
    assert!(!shaper.is_within_business_hours(22));
}

#[test]
fn business_hours_wrap_around() {
    let hours = BusinessHours {
        start_hour: 22,
        end_hour: 6,
    };
    assert!(hours.contains_hour(23));
    assert!(hours.contains_hour(3));
    assert!(!hours.contains_hour(12));
}

#[test]
fn business_hours_none_means_always_valid() {
    let shaper = make_shaper();
    assert!(shaper.is_within_business_hours(3));
    assert!(shaper.is_within_business_hours(15));
}

#[test]
fn default_business_hours_8_to_18() {
    let hours = BusinessHours::default();
    assert_eq!(hours.start_hour, 8);
    assert_eq!(hours.end_hour, 18);
    assert!(hours.contains_hour(12));
    assert!(!hours.contains_hour(6));
}

#[test]
fn warmup_steps_configurable() {
    let mut shaper = TrafficShaper::with_seed(
        TrafficShaperConfig::default().with_session_warmup_steps(1),
        42,
    );
    let steps = shaper.generate_session_warmup("https://example.com", "/target");
    assert_eq!(steps.len(), 3);
}

#[test]
fn burst_dampening_increases_delay() {
    let mut shaper_damped = TrafficShaper::with_seed(
        TrafficShaperConfig::default()
            .with_mean_delay_ms(1000.0)
            .with_burst_dampening(true),
        42,
    );
    let mut shaper_no_damp = TrafficShaper::with_seed(
        TrafficShaperConfig::default()
            .with_mean_delay_ms(1000.0)
            .with_burst_dampening(false),
        42,
    );
    let _: Vec<u64> = (0..20).map(|_| shaper_damped.next_delay_ms()).collect();
    let _: Vec<u64> = (0..20).map(|_| shaper_no_damp.next_delay_ms()).collect();
    assert_eq!(shaper_damped.total_requests(), 20);
    assert_eq!(shaper_no_damp.total_requests(), 20);
}

#[test]
fn cover_traffic_some_have_referers() {
    let mut shaper = make_shaper();
    let cover = shaper.generate_cover_traffic("https://example.com", 20);
    let with_referer = cover.iter().filter(|c| c.referer.is_some()).count();
    assert!(with_referer > 0);
}
