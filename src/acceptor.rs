use std::sync::Arc;

use openssl::ssl::SslAcceptor;

use crate::certificate::CertificateVerifier;

pub(crate) struct SslConfig {
    pub(crate) acceptor: SslAcceptor,
    pub(crate) certificate_verifier: Option<Arc<dyn CertificateVerifier>>,
}
