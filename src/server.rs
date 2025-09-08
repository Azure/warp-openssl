use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use crate::{
    certificate::{Certificate, CertificateVerifier},
    config::{LookupFileFn, LookupHashDirFn, TlsConfigBuilder},
    stream::TlsStream,
    tcp::AddrIncoming,
    Result,
};

use futures_util::{StreamExt, TryFuture};
use hyper_util::{rt::TokioExecutor, server::conn::auto::Builder as HyperServerBuilder};
use openssl::ssl::{SslAcceptorBuilder, SslContext};
use tokio_util::sync::CancellationToken;
use tower_service::Service;
use warp::{Filter, Reply};

fn bind<F>(
    server: OpensslServer<F>,
    addr: impl Into<SocketAddr>,
    cancellation_token: CancellationToken,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)>
where
    F: Filter + Clone + Send + Sync + 'static,
    <F::Future as TryFuture>::Ok: Reply,
{
    let ssl_config = server.tls.build()?;
    let addr = addr.into();
    let mut incoming = AddrIncoming::bind(&addr)?;
    incoming.set_nodelay(true);
    let local_addr = incoming.local_addr();
    let service = warp::service(server.filter.clone());

    let handle = tokio::spawn(async move {
        let server = HyperServerBuilder::new(TokioExecutor::new());
        loop {
            let stream = tokio::select! {
                _ = cancellation_token.cancelled() => {
                    tracing::info!("Shutting down warp-openssl server");
                    break;
                }
                maybe_incoming = incoming.next() => {
                    match maybe_incoming {
                        Some(stream) => {
                            stream
                        }
                        None => break,
                    }
                }
            };

            let tls_stream = match TlsStream::new(stream, &ssl_config) {
                Ok(stream) => stream,
                Err(err) => {
                    tracing::error!("Could not accept tls stream: {err:?}");
                    continue;
                }
            };

            let certificate: Option<Certificate> = tls_stream
                .stream()
                .lock()
                .ok()
                .and_then(|stream| stream.ssl().peer_certificate())
                .and_then(|peer_certificate| peer_certificate.try_into().ok());

            let service = service.clone();
            let svc = hyper::service::service_fn(move |mut request| {
                if let Some(certificate) = certificate.clone() {
                    request.extensions_mut().insert(certificate);
                };

                let mut service = service.clone();
                service.call(request)
            });

            let server = server.clone();
            let cancellation_token = cancellation_token.clone();
            tokio::spawn(async move {
                let connection = server.serve_connection(tls_stream, svc);

                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        tracing::info!("Shutting down warp-openssl connection");
                    }
                    res = connection => {
                        if let Err(err) = res {
                            tracing::error!("Error serving connection: {:?}", err);
                        }
                    }
                }
            });
        }
    });

    Ok((local_addr, handle))
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
    pub fn bind(self, addr: impl Into<SocketAddr>) -> Result<(SocketAddr, WarpOpensslServer)> {
        let (addr, handle) = bind(self, addr, CancellationToken::new())?;

        Ok((addr, handle.into()))
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
    ) -> Result<(SocketAddr, WarpOpensslServer)> {
        let cancellation_token = CancellationToken::new();

        {
            let cancellation_token = cancellation_token.clone();
            tokio::spawn(async move {
                signal.await;
                cancellation_token.cancel();
            });
        }

        let (addr, handle) = bind(self, addr, cancellation_token)?;

        Ok((addr, handle.into()))
    }
}

#[derive(Debug)]
pub struct WarpOpensslServer(tokio::task::JoinHandle<()>);

impl Future for WarpOpensslServer {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().0).poll(cx).map(|_| ())
    }
}

impl From<tokio::task::JoinHandle<()>> for WarpOpensslServer {
    fn from(handle: tokio::task::JoinHandle<()>) -> Self {
        WarpOpensslServer(handle)
    }
}
