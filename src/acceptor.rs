use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::ready;
use hyper::server::{accept::Accept, conn::AddrIncoming};
use openssl::ssl::SslAcceptor;

use crate::{certificate::CertificateVerifier, stream::TlsStream};

pub(crate) struct SslConfig {
    pub(crate) acceptor: SslAcceptor,
    pub(crate) certificate_verifier: Option<Arc<dyn CertificateVerifier>>,
}

pub(crate) struct TlsAcceptor {
    ssl_config: SslConfig,
    incoming: AddrIncoming,
}

impl TlsAcceptor {
    pub(crate) fn new(ssl_config: SslConfig, incoming: AddrIncoming) -> TlsAcceptor {
        TlsAcceptor {
            ssl_config,
            incoming,
        }
    }
}

impl Accept for TlsAcceptor {
    type Conn = TlsStream;
    type Error = io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();
        match ready!(Pin::new(&mut pin.incoming).poll_accept(cx)) {
            Some(Ok(sock)) => Poll::Ready(Some(Ok(TlsStream::new(sock, &pin.ssl_config)?))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}
