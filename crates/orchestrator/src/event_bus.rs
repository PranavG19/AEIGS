use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aegis_protocol::operation::ModuleIdentifier;
use aegis_protocol::scan_event::{ScanEvent, ScanEventEnvelope};

/// Identifies which broad category of event a subscriber is interested in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventTopic {
    EndpointDiscovered,
    HypothesisGenerated,
    PayloadTested,
    AnomalyDetected,
    FindingConfirmed,
    PhaseCompleted,
    All,
}

impl EventTopic {
    /// Maps a concrete ScanEvent variant to its topic.
    pub fn from_event(event: &ScanEvent) -> Self {
        match event {
            ScanEvent::EndpointDiscovered { .. } => Self::EndpointDiscovered,
            ScanEvent::HypothesisGenerated { .. } => Self::HypothesisGenerated,
            ScanEvent::PayloadTested { .. } => Self::PayloadTested,
            ScanEvent::AnomalyDetected { .. } => Self::AnomalyDetected,
            ScanEvent::FindingConfirmed { .. } => Self::FindingConfirmed,
            ScanEvent::PhaseCompleted { .. } => Self::PhaseCompleted,
        }
    }
}

/// Type-erased callback that receives a scan event envelope.
pub type EventHandler = Arc<dyn Fn(&ScanEventEnvelope) + Send + Sync>;

/// A subscriber registration.
struct Subscription {
    id: u64,
    module: ModuleIdentifier,
    topic: EventTopic,
    handler: EventHandler,
}

/// Pub/sub event bus for inter-module communication during a scan.
///
/// Modules subscribe to event topics (EndpointDiscovered, VulnFound, etc.)
/// and receive callbacks when those events are published. Decouples modules
/// so that e.g. the fuzzer can react to newly discovered endpoints without
/// direct coupling to the crawler.
pub struct EventBus {
    subscriptions: Vec<Subscription>,
    next_sub_id: u64,
    next_event_id: u64,
    event_log: Vec<ScanEventEnvelope>,
    max_log_size: usize,
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            subscriptions: Vec::new(),
            next_sub_id: 0,
            next_event_id: 0,
            event_log: Vec::new(),
            max_log_size: 10_000,
        }
    }

    /// Creates a bus with a custom event log capacity.
    pub fn with_log_capacity(max_log_size: usize) -> Self {
        Self {
            max_log_size,
            ..Self::new()
        }
    }

    /// Subscribes a module to a specific event topic. Returns a subscription
    /// ID that can be used to unsubscribe later.
    pub fn subscribe(
        &mut self,
        module: ModuleIdentifier,
        topic: EventTopic,
        handler: EventHandler,
    ) -> u64 {
        let id = self.next_sub_id;
        self.next_sub_id += 1;
        self.subscriptions.push(Subscription {
            id,
            module,
            topic,
            handler,
        });
        id
    }

    /// Removes a subscription by its ID.
    pub fn unsubscribe(&mut self, sub_id: u64) -> bool {
        let before = self.subscriptions.len();
        self.subscriptions.retain(|s| s.id != sub_id);
        self.subscriptions.len() < before
    }

    /// Publishes an event from the given source module. All matching
    /// subscribers (by topic or All) are notified synchronously.
    pub fn publish(&mut self, source_module: ModuleIdentifier, event: ScanEvent) {
        let event_id = self.next_event_id;
        self.next_event_id += 1;

        let envelope = ScanEventEnvelope::new(event_id, source_module, event);
        let topic = EventTopic::from_event(&envelope.event);

        for sub in &self.subscriptions {
            if sub.topic == topic || sub.topic == EventTopic::All {
                (sub.handler)(&envelope);
            }
        }

        if self.event_log.len() < self.max_log_size {
            self.event_log.push(envelope);
        }
    }

    /// Returns the count of subscriptions for a given topic.
    pub fn subscriber_count(&self, topic: EventTopic) -> usize {
        self.subscriptions
            .iter()
            .filter(|s| s.topic == topic || s.topic == EventTopic::All)
            .count()
    }

    /// Returns all events logged so far.
    pub fn event_log(&self) -> &[ScanEventEnvelope] {
        &self.event_log
    }

    /// Returns events filtered by topic.
    pub fn events_by_topic(&self, topic: EventTopic) -> Vec<&ScanEventEnvelope> {
        self.event_log
            .iter()
            .filter(|e| EventTopic::from_event(&e.event) == topic)
            .collect()
    }

    /// Returns the total number of events published.
    pub fn total_events_published(&self) -> u64 {
        self.next_event_id
    }

    /// Clears the event log but keeps subscriptions.
    pub fn clear_log(&mut self) {
        self.event_log.clear();
    }

    /// Removes all subscriptions and clears the log.
    pub fn reset(&mut self) {
        self.subscriptions.clear();
        self.event_log.clear();
        self.next_sub_id = 0;
        self.next_event_id = 0;
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe wrapper around EventBus for shared access across modules.
#[derive(Clone)]
pub struct SharedEventBus {
    inner: Arc<Mutex<EventBus>>,
}

impl SharedEventBus {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(EventBus::new())),
        }
    }

    pub fn subscribe(
        &self,
        module: ModuleIdentifier,
        topic: EventTopic,
        handler: EventHandler,
    ) -> u64 {
        self.inner.lock().unwrap().subscribe(module, topic, handler)
    }

    pub fn unsubscribe(&self, sub_id: u64) -> bool {
        self.inner.lock().unwrap().unsubscribe(sub_id)
    }

    pub fn publish(&self, source_module: ModuleIdentifier, event: ScanEvent) {
        self.inner.lock().unwrap().publish(source_module, event);
    }

    pub fn subscriber_count(&self, topic: EventTopic) -> usize {
        self.inner.lock().unwrap().subscriber_count(topic)
    }

    pub fn total_events_published(&self) -> u64 {
        self.inner.lock().unwrap().total_events_published()
    }
}

impl Default for SharedEventBus {
    fn default() -> Self {
        Self::new()
    }
}
