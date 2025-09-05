use std::sync::Arc;
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub struct AbortTaskOnDrop(#[allow(unused)] Arc<AbortTaskOnDropInner>);

#[derive(Debug)]
struct AbortTaskOnDropInner(JoinHandle<()>);

impl From<JoinHandle<()>> for AbortTaskOnDrop {
    fn from(handle: JoinHandle<()>) -> Self {
        AbortTaskOnDrop(Arc::new(AbortTaskOnDropInner(handle)))
    }
}

impl Drop for AbortTaskOnDropInner {
    fn drop(&mut self) {
        tracing::debug!("Aborting task on drop: {}", self.0.id());
        self.0.abort();
    }
}
