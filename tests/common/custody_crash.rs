use std::path::PathBuf;
use std::process::Child;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

pub struct Worker(pub Child);
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub struct Cut {
    pub target: &'static str,
    pub marker: PathBuf,
}
impl Subscriber for Cut {
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
            std::fs::write(&self.marker, b"at crash cut").unwrap();
            loop {
                std::thread::park();
            }
        }
    }
}
