use core::fmt;
use std::fmt::{Debug, Formatter};

use openssl::x509::X509;

use crate::Result;

/// Certificate information for a TLS connection.
#[derive(Debug, Clone)]
pub struct Certificate {
    common_names: Vec<String>,
    organizational_units: Vec<String>,
    localities: Vec<String>,
}

impl TryFrom<X509> for Certificate {
    type Error = std::io::Error;

    fn try_from(cert: X509) -> std::io::Result<Self> {
        let mut common_names = vec![];
        let mut organizational_units = vec![];
        let mut localities = vec![];

        for entry in cert.subject_name().entries() {
            let list = match entry.object().nid().short_name() {
                Ok("CN") => &mut common_names,
                Ok("OU") => &mut organizational_units,
                Ok("L") => &mut localities,
                _ => continue,
            };

            let value = entry.data().as_utf8()?.to_string();
            list.push(value);
        }

        Ok(Self::new(common_names, organizational_units, localities))
    }
}

impl Certificate {
    /// Creates a new certificate.
    pub(crate) fn new(
        common_names: Vec<String>,
        organizational_units: Vec<String>,
        localities: Vec<String>,
    ) -> Certificate {
        Certificate {
            common_names,
            organizational_units,
            localities,
        }
    }

    /// Returns the common name of the certificate.
    #[deprecated(note = "please use `common_names` instead")]
    pub fn common_name(&self) -> Option<&str> {
        self.common_names
            .first()
            .map(|common_name| common_name.as_str())
    }

    /// Returns the common names of the certificate.
    pub fn common_names(&self) -> &[String] {
        self.common_names.as_slice()
    }

    /// Returns the organizational unit of the certificate.
    #[deprecated(note = "please use `organizational_units` instead")]
    pub fn organizational_unit(&self) -> Option<&str> {
        self.organizational_units
            .first()
            .map(|organizational_unit| organizational_unit.as_str())
    }

    /// Returns the organizational units of the certificate.
    pub fn organizational_units(&self) -> &[String] {
        &self.organizational_units
    }

    /// Returns the localities of the certificate.
    pub fn localities(&self) -> &[String] {
        &self.localities
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
