use std::net::SocketAddr;

use std::sync::Arc;

use crate::acceptor::TlsAcceptor;
use crate::certificate::{Certificate, CertificateVerifier};
use crate::config::{LookupFileFn, LookupHashDirFn, TlsConfigBuilder};
use crate::stream::CloneableStream;
use crate::Result;

use futures_util::FutureExt;
use futures_util::{Future, TryFuture};

use hyper::server::conn::AddrIncoming;
use openssl::ssl::{SslAcceptorBuilder, SslContext};

use std::convert::Infallible;
use warp::{Filter, Reply};

use hyper::service::{make_service_fn, Service};
use hyper::Server as HyperServer;
use hyper::{Body, Request};

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
        let make_svc = make_service_fn(move |stream| {
            let stream: CloneableStream = {
                let stream: &crate::stream::TlsStream = stream;
                stream.stream()
            };

            let mut service = service.clone();
            let svc = hyper::service::service_fn(move |mut req: Request<Body>| {
                let certificate: Option<Certificate> = stream
                    .lock()
                    .ok()
                    .and_then(|stream| stream.ssl().peer_certificate())
                    .and_then(|peer_certificate| peer_certificate.try_into().ok());

                if let Some(certificate) = certificate {
                    req.extensions_mut().insert(certificate);
                };

                service.call(req)
            });

            // let remote_addr = socket.remote_addr();
            let svc = svc.clone();
            async move { Ok::<_, Infallible>(svc.clone()) }
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

/// Settings corresponding to TLS level based on Mozilla's server side TLS recommendations.
/// See its [documentation][docs] for more details on specifics.
///
/// [docs]: https://wiki.mozilla.org/Security/Server_Side_TLS
#[derive(Debug, Clone)]
pub enum TlsLevel {
    /// Settings corresponding to modern configuration of version 4 of Mozilla's server side TLS
    /// recommendations
    MozillaModern,
    /// Settings corresponding to modern configuration of version 5 of Mozilla's server side TLS
    /// recommendations
    MozillaModernV5,
    /// Settings corresponding to the intermediate configuration of version 4 of Mozilla's server side TLS
    /// recommendations
    MozillaIntermediate,
    /// Settings corresponding to the intermediate configuration of version 5 of Mozilla's server side TLS
    /// recommendations
    MozillaIntermediateV5,
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

    /// Specify the tls level based on Mozilla's server side TLS recommendations.
    /// See its [documentation][docs] for more details on specifics.
    ///
    /// Defaults to `TlsLevel::MozillaIntermediateV5`.
    ///
    /// [docs]: https://wiki.mozilla.org/Security/Server_Side_TLS
    pub fn tls_level<T>(self, tls_level: TlsLevel) -> Self
    where
        T: FnMut(&mut SslContext) -> Result<SslAcceptorBuilder>,
    {
        self.with_tls(|tls| tls.tls_level(tls_level))
    }

    /// Specify the in-memory contents of the certificate.
    ///
    pub fn cert(self, cert: impl AsRef<[u8]>) -> Self {
        self.with_tls(|tls| tls.cert(cert.as_ref()))
    }

    /// Add file loop callback that loads all the certificates or CRLs present in a file into memory at the time the file is added as a lookup source.
    /// See [`openssl::x509::X509Lookup::file`] for more details.
    ///
    pub fn add_file_lookup(self, lookup: LookupFileFn) -> Self {
        self.with_tls(|tls| tls.add_file_lookup(lookup))
    }

    /// Add hash dir lookup callback that loads certificates and CRLs on demand and caches them in memory once they are loaded.
    /// See [`openssl::x509::X509Lookup::hash_dir`] for more details.
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
    pub fn disable_partial_chain_verification(self) -> Self {
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
