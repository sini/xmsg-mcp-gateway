use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

pub struct AtEvent<F: Fn() + Send + Sync> {
    target: &'static str,
    action: F,
    _cache_participant: tracing::Dispatch,
}

impl<F: Fn() + Send + Sync> AtEvent<F> {
    pub fn new(target: &'static str, action: F) -> Self {
        // Avoid tracing-core 0.1.36's JustOne cache using the registering thread's default.
        Self {
            target,
            action,
            _cache_participant: tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()),
        }
    }
}

impl<F: Fn() + Send + Sync + 'static> Subscriber for AtEvent<F> {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == self.target
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        if event.metadata().target() == self.target {
            (self.action)();
        }
    }
}
