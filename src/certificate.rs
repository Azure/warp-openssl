use core::fmt;
use std::fmt::{Debug, Formatter};

use crate::Result;

/// Certificate information for a TLS connection.
#[derive(Debug)]
pub struct Certificate {
    subject_name: String,
}

impl Certificate {
    /// Creates a new certificate.
    pub(crate) fn new(subject_name: String) -> Certificate {
        Certificate { subject_name }
    }

    /// Returns the subject name of the certificate.
    pub fn subject_name(&self) -> &str {
        &self.subject_name
    }
}

/// A trait for verifying a certificate.
pub trait CertificateVerifier: Send + Sync {
    /// Verify the certificate. If the certificate is valid, return `Ok(())`.
    /// Otherwise, return an error.
    fn verify_certificate(&self, end_entity: &Certificate) -> Result<()>;
}

impl Debug for dyn CertificateVerifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateVerifier").finish()
    }
}