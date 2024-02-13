use std::net::SocketAddr;

use std::sync::Arc;

use crate::acceptor::TlsAcceptor;
use crate::certificate::CertificateVerifier;
use crate::config::{LookupFileFn, LookupHashDirFn, TlsConfigBuilder};
use crate::Result;

use futures_util::{Future, FutureExt, TryFuture};

use hyper::server::conn::AddrIncoming;

use std::convert::Infallible;
use warp::{Filter, Reply};

use hyper::service::make_service_fn;
use hyper::Server as HyperServer;

macro_rules! addr_incoming {
    ($addr:expr) => {{
        let mut incoming = AddrIncoming::bind($addr)?;
        incoming.set_nodelay(true);
        let addr = incoming.local_addr();
        (addr, incoming)
    }};
}
macro_rules! bind {
    ($this:ident, $addr:expr) => {{
        let tls = $this.tls.build()?;
        let addr = $addr.into();
        let (addr, incoming) = addr_incoming!(&addr);
        let service = warp::service($this.filter);
        let make_svc = make_service_fn(move |_| {
            // let remote_addr = socket.remote_addr();
            let service = service.clone();
            async move { Ok::<_, Infallible>(service.clone()) }
        });

        let srv = HyperServer::builder(TlsAcceptor::new(tls, incoming)).serve(make_svc);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((addr, srv))
    }};
}

/// Create an `OpensslServer` with the provided `Filter`.
pub fn serve<F>(filter: F) -> OpensslServer<F> {
    OpensslServer {
        filter,
        tls: TlsConfigBuilder::new(),
    }
}


/// Create an openssl based TLS warp server with the provided filter.
/// 
#[derive(Debug)]
pub struct OpensslServer<F> {
    filter: F,
    tls: TlsConfigBuilder,
}

// // ===== impl TlsServer =====

impl<F> OpensslServer<F>
where
    F: Filter + Clone + Send + Sync + 'static,
    <F::Future as TryFuture>::Ok: Reply,
{
    /// Specify the in-memory contents of the private key.
    ///
    pub fn key(self, key: impl AsRef<[u8]>) -> Self {
        self.with_tls(|tls| tls.key(key.as_ref()))
    }

    /// Specify the in-memory contents of the certificate.
    ///
    pub fn cert(self, cert: impl AsRef<[u8]>) -> Self {
        self.with_tls(|tls| tls.cert(cert.as_ref()))
    }

    /// Add file loop callback
    ///
    pub fn add_file_lookup(self, lookup: LookupFileFn) -> Self {
        self.with_tls(|tls| tls.add_file_lookup(lookup))
    }

    /// Add hash dir lookup callback
    ///
    pub fn add_hash_dir_lookup(self, lookup: LookupHashDirFn) -> Self {
        self.with_tls(|tls| tls.add_hash_dir_lookup(lookup))
    }

    /// Specify the in-memory contents of the trust anchor for optional client authentication.
    ///
    /// Anonymous clients will be accepted by default
    /// Non anonymous clients passing CertificateVerifier and having a valid certificate chain will be accepted.
    ///
    pub fn client_auth_optional(
        self,
        trust_anchor: impl AsRef<[u8]>,
        certificate_verifier: Arc<dyn CertificateVerifier>,
    ) -> Self {
        self.with_tls(|tls| tls.client_auth_optional(trust_anchor.as_ref(), certificate_verifier))
    }

    /// Specify the in-memory contents of the trust anchor for required client authentication.
    /// Only clients passing CertificateVerifier and having a valid certificate chain will be accepted.
    ///
    pub fn client_auth_required(
        self,
        trust_anchor: impl AsRef<[u8]>,
        certificate_verifier: Arc<dyn CertificateVerifier>,
    ) -> Self {
        self.with_tls(|tls| tls.client_auth_required(trust_anchor.as_ref(), certificate_verifier))
    }

    /// **Not recommended** Disables partial certificate chain verification. 
    /// 
    /// For certificate pinning to work properly its enough to validate that
    /// the certificate chains to an anchor in the trust store. This is the default behavior.
    ///
    pub fn disable_partial_chain_verification(
        self,
    ) -> Self {
        self.with_tls(|tls| tls.disable_partial_chain_verification())
    }

    fn with_tls<Func>(self, func: Func) -> Self
    where
        Func: FnOnce(TlsConfigBuilder) -> TlsConfigBuilder,
    {
        let OpensslServer { filter, tls } = self;
        let tls = func(tls);
        OpensslServer { filter, tls }
    }

    /// Create a tls server bound to a sepecific port.
    ///
    pub fn bind(
        self,
        addr: impl Into<SocketAddr>,
    ) -> Result<(SocketAddr, impl Future<Output = ()> + 'static)> {
        let (addr, srv) = bind!(self, addr)?;

        let srv = srv.map(|result| {
            if let Err(err) = result {
                tracing::error!("server error: {}", err)
            }
        });

        Ok((addr, srv))
    }

    /// Create a tls server bound to a specific port with graceful shutdown signal.
    ///
    /// When the signal completes, the server will start the graceful shutdown
    /// process.
    ///
    pub fn bind_with_graceful_shutdown(
        self,
        addr: impl Into<SocketAddr>,
        signal: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(SocketAddr, impl Future<Output = ()> + 'static)> {
        let (addr, srv) = bind!(self, addr)?;
        let srv = srv.with_graceful_shutdown(signal).map(|result| {
            if let Err(err) = result {
                tracing::error!("server error: {}", err)
            }
        });

        Ok((addr, srv))
    }
}
