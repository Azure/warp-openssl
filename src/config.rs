use std::{
    env,
    fmt,
    fs::File,
    io::{self, Cursor, Read, Write},
    sync::{Arc, Mutex},
};

use openssl::{
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod, SslVerifyMode},
    x509::{
        store::{X509Store, X509StoreBuilder},
        X509,
    },
};

use crate::{acceptor::SslConfig, certificate::CertificateVerifier};

/// Represents errors that can occur building the TlsConfig
#[derive(Debug)]
pub(crate) enum TlsConfigError {
    Io(io::Error),
    /// An error from an empty key
    EmptyKey,
    /// No public certificate was found
    EmptyCert,
    /// An error from openssl
    OpensslError(::openssl::error::ErrorStack),
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsConfigError::Io(err) => err.fmt(f),
            TlsConfigError::EmptyKey => write!(f, "key contains no private key"),
            TlsConfigError::EmptyCert => write!(f, "no public certificate found"),
            TlsConfigError::OpensslError(err) => write!(f, "Openssl failed, {}", err),
        }
    }
}

impl std::error::Error for TlsConfigError {}

/// Tls client authentication configuration.
#[derive(Debug)]
pub(crate) enum TlsClientAuth {
    /// No client auth.
    Off,
    /// Allow any anonymous or verification passing authenticated client with the given trust anchors.
    Optional((Vec<u8>, Arc<dyn CertificateVerifier>)),
    /// Allow any verification passing authenticated client with the given trust anchors.
    Required((Vec<u8>, Arc<dyn CertificateVerifier>)),
}

/// Builder to set the configuration for the Tls server.
pub(crate) struct TlsConfigBuilder {
    cert: Box<dyn Read + Send + Sync>,
    key: Box<dyn Read + Send + Sync>,
    client_auth: TlsClientAuth,
}

impl fmt::Debug for TlsConfigBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfigBuilder")
            .field("client_auth", &self.client_auth)
            .finish()
    }
}

impl TlsConfigBuilder {
    pub(crate) fn new() -> TlsConfigBuilder {
        TlsConfigBuilder {
            key: Box::new(io::empty()),
            cert: Box::new(io::empty()),
            client_auth: TlsClientAuth::Off,
        }
    }

    pub(crate) fn key(mut self, key: &[u8]) -> Self {
        self.key = Box::new(Cursor::new(Vec::from(key)));
        self
    }

    pub(crate) fn cert(mut self, cert: &[u8]) -> Self {
        self.cert = Box::new(Cursor::new(Vec::from(cert)));
        self
    }

    pub(crate) fn client_auth_optional(
        mut self,
        trust_anchor: &[u8],
        certificate_verifier: Arc<dyn CertificateVerifier>,
    ) -> Self {
        self.client_auth = TlsClientAuth::Optional((Vec::from(trust_anchor), certificate_verifier));
        self
    }

    pub(crate) fn client_auth_required(
        mut self,
        trust_anchor: &[u8],
        certificate_verifier: Arc<dyn CertificateVerifier>,
    ) -> Self {
        self.client_auth = TlsClientAuth::Required((Vec::from(trust_anchor), certificate_verifier));
        self
    }
}

impl TlsConfigBuilder {
    pub(crate) fn build(mut self) -> std::result::Result<SslConfig, TlsConfigError> {
        let mut key_vec = Vec::new();
        self.key
            .read_to_end(&mut key_vec)
            .map_err(TlsConfigError::Io)?;

        if key_vec.is_empty() {
            return Err(TlsConfigError::EmptyKey);
        }

        let private_key =
            PKey::private_key_from_pem(&key_vec).map_err(TlsConfigError::OpensslError)?;

        let mut cert_vec = Vec::new();
        self.cert
            .read_to_end(&mut cert_vec)
            .map_err(TlsConfigError::Io)?;

        let mut cert_chain = X509::stack_from_pem(&cert_vec)
            .map_err(TlsConfigError::OpensslError)?
            .into_iter();
        let cert = cert_chain.next().ok_or(TlsConfigError::EmptyCert)?;
        let chain: Vec<_> = cert_chain.collect();
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())
            .map_err(TlsConfigError::OpensslError)?;
        acceptor
            .set_private_key(&private_key)
            .map_err(TlsConfigError::OpensslError)?;
        acceptor
            .set_certificate(&cert)
            .map_err(TlsConfigError::OpensslError)?;

        for cert in chain.iter() {
            acceptor
                .add_extra_chain_cert(cert.to_owned())
                .map_err(TlsConfigError::OpensslError)?;
        }

        acceptor
            .set_alpn_protos(b"\x02h2\x08http/1.1")
            .map_err(TlsConfigError::OpensslError)?;

        fn read_trust_anchor(
            mut trust_anchor: &[u8],
        ) -> std::result::Result<X509Store, TlsConfigError> {
            let mut cert_vec = Vec::new();
            trust_anchor
                .read_to_end(&mut cert_vec)
                .map_err(TlsConfigError::Io)?;

            let certs = X509::stack_from_pem(&cert_vec).map_err(TlsConfigError::OpensslError)?;
            let mut store = X509StoreBuilder::new().map_err(TlsConfigError::OpensslError)?;

            for cert in certs.into_iter() {
                store.add_cert(cert).map_err(TlsConfigError::OpensslError)?;
            }

            Ok(store.build())
        }

        let certificate_validator = match self.client_auth {
            TlsClientAuth::Off => {
                acceptor.set_verify(SslVerifyMode::NONE);
                None
            }
            TlsClientAuth::Optional((trust_anchor, certificate_valiator)) => {
                let store = read_trust_anchor(&trust_anchor)?;
                acceptor.set_verify(SslVerifyMode::PEER);
                acceptor
                    .set_verify_cert_store(store)
                    .map_err(TlsConfigError::OpensslError)?;
                Some(certificate_valiator)
            }
            TlsClientAuth::Required((trust_anchor, certificate_validator)) => {
                let store = read_trust_anchor(&trust_anchor)?;
                acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
                acceptor
                    .set_verify_cert_store(store)
                    .map_err(TlsConfigError::OpensslError)?;
                Some(certificate_validator)
            }
        };

        if let Ok(filename) = env::var("SSLKEYLOGFILE") {
            let file = Mutex::new(File::create(filename).unwrap());

            acceptor.set_keylog_callback(move |_ssl, line| {
                let mut file = file.lock().unwrap();
                let _ = writeln!(&mut file, "{}", line);
            });
        };

        Ok(SslConfig {
            acceptor: acceptor.build(),
            certificate_verifier: certificate_validator,
        })
    }
}
