pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type Result<T> = std::result::Result<T, Error>;

mod acceptor;
pub mod certificate;
mod config;
pub mod server;
mod stream;

pub use server::serve;