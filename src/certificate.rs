use core::fmt;
use std::fmt::{Debug, Formatter};

use crate::Result;

/// Certificate information for a TLS connection.
#[derive(Debug)]
pub struct Certificate {
    //TODO: Change to Option when `subject_name` is removed.
    common_name: String,
    organizational_unit: Option<String>,
}

impl Certificate {
    /// Creates a new certificate.
    pub(crate) fn new(common_name: String, organizational_unit: Option<String>) -> Certificate {
        Certificate {
            common_name,
            organizational_unit,
        }
    }

    /// Returns the common name of the certificate.
    #[deprecated(note = "please use `common_name` instead")]
    pub fn subject_name(&self) -> &str {
        &self.common_name
    }

    /// Returns the common name of the certificate.
    pub fn common_name(&self) -> Option<&str> {
        Some(&self.common_name)
    }

    /// Returns the organizational unit of the certificate.
    pub fn organizational_unit(&self) -> Option<&str> {
        self.organizational_unit.as_deref()
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
