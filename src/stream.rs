use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use hyper::server::conn::AddrStream;
use openssl::ssl::Ssl;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_openssl::SslStream;

use crate::{
    acceptor::SslConfig,
    certificate::{Certificate, CertificateVerifier},
};

enum AcceptState {
    Pending,
    Ready,
}

enum ConnectionState {
    Handshaking,
    Streaming,
}

/// Convenience wrapper around `tokio_openssl::SslStream` that handles the TLS handshake and
/// certificate validation.
pub(crate) struct TlsStream {
    state: ConnectionState,
    stream: SslStream<AddrStream>,
    certificate_verifier: Option<Arc<dyn CertificateVerifier>>,
}

impl TlsStream {
    pub(crate) fn new(
        stream: AddrStream,
        ssl_config: &SslConfig,
    ) -> std::result::Result<TlsStream, io::Error> {
        let ssl = Ssl::new(ssl_config.acceptor.context()).map_err(io::Error::from)?;
        let stream = SslStream::new(ssl, stream).map_err(io::Error::from)?;

        Ok(TlsStream {
            state: ConnectionState::Handshaking,
            stream,
            certificate_verifier: ssl_config.certificate_verifier.clone(),
        })
    }

    /// Performs the TLS handshake and sets the state to `Streaming` if successful.
    /// Returns `Ok(AcceptState::Ready)` if the handshake is complete, or `Ok(AcceptState::Pending)`
    /// if the handshake is still in progress.
    ///
    /// If the handshake fails, returns an `io::Error`.
    /// If the handshake succeeds but the certificate verification fails, returns an `io::Error`.
    ///
    fn do_poll_accept(self: &mut Pin<&mut Self>, cx: &mut Context<'_>) -> io::Result<AcceptState> {
        debug_assert!(matches!(self.state, ConnectionState::Handshaking));

        match Pin::new(&mut self.stream).poll_accept(cx) {
            Poll::Ready(Ok(_)) => {
                self.state = ConnectionState::Streaming;
                if let Some(certificate_verifier) = self.certificate_verifier.as_ref() {
                    if let Some(cert) = self.stream.ssl().peer_certificate() {
                        let mut common_names = vec![];
                        let mut organizational_units = vec![];

                        for entry in cert.subject_name().entries() {
                            let list = match entry.object().nid().short_name() {
                                Ok("CN") => &mut common_names,
                                Ok("OU") => &mut organizational_units,
                                _ => continue,
                            };

                            let value = entry.data().as_utf8()?.to_string();
                            list.push(value);
                        }

                        let cert = Certificate::new(common_names, organizational_units);
                        certificate_verifier
                            .verify_certificate(&cert)
                            .map_err(|err| {
                                tracing::error!(
                                    "Certificate validation failed for certificate: {:?}",
                                    cert
                                );
                                io::Error::new(io::ErrorKind::Other, err)
                            })?
                    }
                }
                Ok(AcceptState::Ready)
            }
            Poll::Ready(Err(e)) => {
                // Log the error in case of cert verification falilure otherwise warp silently ignores this
                tracing::error!("Error in poll_accept: {:?}", e);
                Err(e
                    .into_io_error()
                    .unwrap_or_else(|e| io::Error::new(io::ErrorKind::Other, e)))
            }
            Poll::Pending => Ok(AcceptState::Pending),
        }
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.state {
            ConnectionState::Handshaking => match self.do_poll_accept(cx)? {
                AcceptState::Pending => Poll::Pending,
                AcceptState::Ready => self.poll_read(cx, buf),
            },
            ConnectionState::Streaming => Pin::new(&mut self.stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, io::Error>> {
        match self.state {
            ConnectionState::Handshaking => match self.do_poll_accept(cx)? {
                AcceptState::Pending => Poll::Pending,
                AcceptState::Ready => self.poll_write(cx, buf),
            },
            ConnectionState::Streaming => Pin::new(&mut self.stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        match self.state {
            ConnectionState::Handshaking => Poll::Ready(Ok(())),
            ConnectionState::Streaming => Pin::new(&mut self.stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        match self.state {
            ConnectionState::Handshaking => Poll::Ready(Ok(())),
            ConnectionState::Streaming => Pin::new(&mut self.stream).poll_shutdown(cx),
        }
    }
}
