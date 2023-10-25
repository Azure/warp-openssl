#![doc(html_root_url = "https://docs.rs/warp-openssl")]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![cfg_attr(test, deny(warnings))]

//! # warp-openssl
//!
//! warp-openssl adds an openssl compatibility layer  to [warp](https://docs.rs/warp).
//!
//! By default warp ships with support for rustls as the TLS layer which makes warp 
//! unusable in some environments where only openssl is allowed.
//! 
//! In order to use the openssl compatibility layer just import serve from warp_openssl 
//! instead of warp.
//! 
//! So the following example:
//! ```
//!  use warp::serve;
//! 
//!  let server = serve(warp::Filter::map(warp::any(), || "Hello, World!"));
//! ```
//! 
//! would convert to:
//! 
//! ```
//!  use warp_openssl::serve;
//!  
//!  let cert = vec![]; // certificate to use
//!  let key = vec![]; // private key for the certificate
//!  let server = serve(warp::Filter::map(warp::any(), || "Hello, World!"))
//!     .key(key)
//!     .cert(cert);
//! ```
//! 
//! There is additional support for SSL key logging file to enable viewing network traffic in wireshark.
//! Just set the SSLKEYLOGFILE environment variable to the path of the file you want to use
//! and the key log gets generated to that file.

#[doc(hidden)]
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
#[doc(hidden)]
pub type Result<T> = std::result::Result<T, Error>;

mod acceptor;
#[doc(hidden)]
pub mod certificate;
mod config;
#[doc(hidden)]
pub mod server;
mod stream;

pub use server::serve;