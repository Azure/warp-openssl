use tokio::signal::ctrl_c;
use tracing::info;
use tracing_subscriber::EnvFilter;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::oneshot;
use warp_openssl::Result;
use warp_openssl::{CertificateVerifier, serve};

struct ValidCertVerifier {}

impl CertificateVerifier for ValidCertVerifier {
    fn verify_certificate(
        &self,
        _: &warp_openssl::Certificate,
    ) -> warp_openssl::Result<()> {
        Result::Ok(())
    }
}

use clap::Parser;


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Enable client authentication
    #[arg(short, long)]
    client_auth: bool,

    /// Default port to use
    #[arg(short, long, default_value_t = 18443)]
    port: u16,
}

/// For the example to work properly please generate the appropriate certificates and keys in the `certs` directory.
/// Requires openssl to be installed.
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();

    let args = Args::parse();
    
    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    let ca_cert = include_bytes!("../certs/ca.crt").to_vec();
    let mut host_cert = include_bytes!("../certs/localhost.crt").to_vec();
    host_cert.extend(ca_cert.clone());

    
    let intermediate_cert = include_bytes!("../certs/intermediate.crt").to_vec();
    
    let (tx, rx) = oneshot::channel::<()>();
    let server = serve(warp::Filter::map(warp::any(), || "Hello, World!"))
        .key(include_bytes!("../certs/localhost.key").to_vec())
        .cert(host_cert);

    let server = server.client_auth_required(intermediate_cert.clone(), Arc::new(ValidCertVerifier {}));

    let (addr, server) = server.bind_with_graceful_shutdown(addr, async move {
        rx.await.ok();
    })?;

    let server = tokio::spawn(async move {
        server.await;
    });

    info!("Server listening on {}. Press a key to exit", addr);
    ctrl_c().await?;

    tx.send(()).unwrap();
    server.await.unwrap();

    Ok(())
}
