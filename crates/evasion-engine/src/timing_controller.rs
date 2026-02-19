use std::time::Instant;

use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::persona::{JitterDistribution, Persona};

pub struct TimingController {
    min_delay_ms: u64,
    max_delay_ms: u64,
    jitter_distribution: JitterDistribution,
    last_request_time: Option<Instant>,
    rng: StdRng,
}

impl TimingController {
    pub fn new(
        min_delay_ms: u64,
        max_delay_ms: u64,
        distribution: JitterDistribution,
        seed: u64,
    ) -> Self {
        Self {
            min_delay_ms,
            max_delay_ms,
            jitter_distribution: distribution,
            last_request_time: None,
            rng: StdRng::seed_from_u64(seed),
        }
    }

    pub fn from_persona(persona: &Persona, seed: u64) -> Self {
        Self::new(
            persona.min_request_interval_ms,
            persona.max_request_interval_ms,
            persona.jitter_distribution,
            seed,
        )
    }

    pub fn compute_delay_ms(&mut self) -> u64 {
        if self.last_request_time.is_none() {
            return 0;
        }
        match self.jitter_distribution {
            JitterDistribution::Uniform => self.compute_uniform(),
            JitterDistribution::Exponential => self.compute_exponential(),
            JitterDistribution::Normal => self.compute_normal(),
        }
    }

    pub fn record_request(&mut self) {
        self.last_request_time = Some(Instant::now());
    }

    pub fn reset(&mut self) {
        self.last_request_time = None;
    }

    fn compute_uniform(&mut self) -> u64 {
        self.rng.random_range(self.min_delay_ms..=self.max_delay_ms)
    }

    fn compute_exponential(&mut self) -> u64 {
        let range = self.max_delay_ms - self.min_delay_ms;
        if range == 0 {
            return self.min_delay_ms;
        }
        let lambda = 1.0 / range as f64;
        let u: f64 = self.rng.random_range(0.0001f64..1.0);
        let sample = -u.ln() / lambda;
        let delay = self.min_delay_ms as f64 + sample;
        delay.round().min(self.max_delay_ms as f64) as u64
    }

    fn compute_normal(&mut self) -> u64 {
        let mean = (self.min_delay_ms + self.max_delay_ms) as f64 / 2.0;
        let stddev = (self.max_delay_ms - self.min_delay_ms) as f64 / 4.0;
        if stddev == 0.0 {
            return self.min_delay_ms;
        }
        let normal_sample = self.box_muller(mean, stddev);
        let clamped = normal_sample
            .max(self.min_delay_ms as f64)
            .min(self.max_delay_ms as f64);
        clamped.round() as u64
    }

    fn box_muller(&mut self, mean: f64, stddev: f64) -> f64 {
        let u1: f64 = self.rng.random_range(0.0001f64..1.0);
        let u2: f64 = self.rng.random_range(0.0001f64..1.0);
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        mean + stddev * z
    }
}

#[cfg(test)]
#[path = "timing_controller_test.rs"]
mod timing_controller_test;
