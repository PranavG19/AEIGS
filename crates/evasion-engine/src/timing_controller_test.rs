#[cfg(test)]
mod tests {
    use crate::persona::{JitterDistribution, Persona, PersonaId};
    use crate::timing_controller::TimingController;

    fn make_controller(dist: JitterDistribution) -> TimingController {
        TimingController::new(100, 500, dist, 42)
    }

    #[test]
    fn first_delay_is_zero() {
        let mut ctrl = make_controller(JitterDistribution::Uniform);
        assert_eq!(ctrl.compute_delay_ms(), 0);
    }

    #[test]
    fn delay_after_record_is_nonzero() {
        let mut ctrl = make_controller(JitterDistribution::Uniform);
        ctrl.record_request();
        let delay = ctrl.compute_delay_ms();
        assert!(delay > 0);
    }

    #[test]
    fn uniform_values_in_range() {
        let mut ctrl = make_controller(JitterDistribution::Uniform);
        ctrl.record_request();
        for _ in 0..200 {
            let delay = ctrl.compute_delay_ms();
            assert!(delay >= 100, "delay {delay} below min 100");
            assert!(delay <= 500, "delay {delay} above max 500");
        }
    }

    #[test]
    fn exponential_values_at_least_min() {
        let mut ctrl = make_controller(JitterDistribution::Exponential);
        ctrl.record_request();
        for _ in 0..200 {
            let delay = ctrl.compute_delay_ms();
            assert!(delay >= 100, "delay {delay} below min 100");
            assert!(delay <= 500, "delay {delay} above max 500");
        }
    }

    #[test]
    fn normal_values_in_range() {
        let mut ctrl = make_controller(JitterDistribution::Normal);
        ctrl.record_request();
        for _ in 0..200 {
            let delay = ctrl.compute_delay_ms();
            assert!(delay >= 100, "delay {delay} below min 100");
            assert!(delay <= 500, "delay {delay} above max 500");
        }
    }

    #[test]
    fn reset_clears_state() {
        let mut ctrl = make_controller(JitterDistribution::Uniform);
        ctrl.record_request();
        let delay = ctrl.compute_delay_ms();
        assert!(delay > 0);
        ctrl.reset();
        assert_eq!(ctrl.compute_delay_ms(), 0);
    }

    #[test]
    fn from_persona_uses_persona_intervals() {
        let persona = Persona::custom(PersonaId::ChromeDesktop)
            .with_user_agent("test")
            .with_accept_header("text/html")
            .with_request_interval(200, 1000)
            .with_jitter_distribution(JitterDistribution::Uniform)
            .build();

        let mut ctrl = TimingController::from_persona(&persona, 99);
        ctrl.record_request();
        for _ in 0..100 {
            let delay = ctrl.compute_delay_ms();
            assert!(delay >= 200, "delay {delay} below persona min 200");
            assert!(delay <= 1000, "delay {delay} above persona max 1000");
        }
    }

    #[test]
    fn deterministic_with_same_seed() {
        let mut ctrl_a = make_controller(JitterDistribution::Uniform);
        let mut ctrl_b = make_controller(JitterDistribution::Uniform);
        ctrl_a.record_request();
        ctrl_b.record_request();
        let delays_a: Vec<u64> = (0..50).map(|_| ctrl_a.compute_delay_ms()).collect();
        let delays_b: Vec<u64> = (0..50).map(|_| ctrl_b.compute_delay_ms()).collect();
        assert_eq!(delays_a, delays_b);
    }

    #[test]
    fn different_seeds_produce_different_delays() {
        let mut ctrl_a = TimingController::new(100, 500, JitterDistribution::Uniform, 1);
        let mut ctrl_b = TimingController::new(100, 500, JitterDistribution::Uniform, 9999);
        ctrl_a.record_request();
        ctrl_b.record_request();
        let delays_a: Vec<u64> = (0..20).map(|_| ctrl_a.compute_delay_ms()).collect();
        let delays_b: Vec<u64> = (0..20).map(|_| ctrl_b.compute_delay_ms()).collect();
        assert_ne!(delays_a, delays_b);
    }

    #[test]
    fn exponential_distribution_skews_toward_min() {
        let mut ctrl = make_controller(JitterDistribution::Exponential);
        ctrl.record_request();
        let delays: Vec<u64> = (0..500).map(|_| ctrl.compute_delay_ms()).collect();
        let midpoint = (100 + 500) / 2;
        let below_mid = delays.iter().filter(|d| **d < midpoint).count();
        assert!(
            below_mid > delays.len() / 3,
            "exponential should skew toward min: {below_mid}/{} below midpoint",
            delays.len()
        );
    }

    #[test]
    fn normal_distribution_clusters_around_mean() {
        let mut ctrl = make_controller(JitterDistribution::Normal);
        ctrl.record_request();
        let delays: Vec<u64> = (0..500).map(|_| ctrl.compute_delay_ms()).collect();
        let mean = 300u64;
        let near_mean = delays.iter().filter(|d| d.abs_diff(mean) <= 100).count();
        assert!(
            near_mean > delays.len() / 3,
            "normal should cluster around mean: {near_mean}/{} within 100 of mean",
            delays.len()
        );
    }

    #[test]
    fn record_then_reset_then_record_resumes_delays() {
        let mut ctrl = make_controller(JitterDistribution::Uniform);
        ctrl.record_request();
        assert!(ctrl.compute_delay_ms() > 0);
        ctrl.reset();
        assert_eq!(ctrl.compute_delay_ms(), 0);
        ctrl.record_request();
        assert!(ctrl.compute_delay_ms() > 0);
    }

    #[test]
    fn equal_min_max_returns_that_value() {
        let mut ctrl = TimingController::new(300, 300, JitterDistribution::Uniform, 42);
        ctrl.record_request();
        for _ in 0..50 {
            assert_eq!(ctrl.compute_delay_ms(), 300);
        }
    }

    #[test]
    fn equal_min_max_exponential_returns_that_value() {
        let mut ctrl = TimingController::new(300, 300, JitterDistribution::Exponential, 42);
        ctrl.record_request();
        for _ in 0..50 {
            assert_eq!(ctrl.compute_delay_ms(), 300);
        }
    }

    #[test]
    fn equal_min_max_normal_returns_that_value() {
        let mut ctrl = TimingController::new(300, 300, JitterDistribution::Normal, 42);
        ctrl.record_request();
        for _ in 0..50 {
            assert_eq!(ctrl.compute_delay_ms(), 300);
        }
    }
}
