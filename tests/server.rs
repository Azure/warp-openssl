use reqwest::{Certificate, ClientBuilder, Identity};
use rstest::*;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::oneshot;
use warp_openssl::Result;
use warp_openssl::{CertificateVerifier, serve};

struct ValidCertVerifier {}

impl CertificateVerifier for ValidCertVerifier {
    fn verify_certificate(
        &self,
        _: &warp_openssl::Certificate,
    ) -> warp_openssl::Result<()> {
        Result::Ok(())
    }
}

struct InValidCertVerifier {}

impl CertificateVerifier for InValidCertVerifier {
    fn verify_certificate(
        &self,
        _: &warp_openssl::Certificate,
    ) -> warp_openssl::Result<()> {
        Result::Err("Invalid certificate".into())
    }
}

enum AuthType {
    Off,
    Required,
    Optional,
}

enum VeriferType {
    Valid,
    Invalid,
}

#[rstest]
#[case::client_auth_off_invalid_success(AuthType::Off, VeriferType::Invalid, false, false)]
#[case::client_auth_off_valid_success(AuthType::Off, VeriferType::Valid, false, false)]
#[case::client_auth_optional_noclient_invalid_success(
    AuthType::Optional,
    VeriferType::Invalid,
    false,
    false
)]
#[case::client_auth_optional_client_invalid_failure(
    AuthType::Optional,
    VeriferType::Invalid,
    true,
    true
)]
#[case::client_auth_optional_client_valid_success(
    AuthType::Optional,
    VeriferType::Valid,
    true,
    false
)]
#[case::client_auth_required_noclient_valid_failure(
    AuthType::Required,
    VeriferType::Valid,
    false,
    true
)]
#[case::client_auth_required_client_valid_success(
    AuthType::Required,
    VeriferType::Valid,
    true,
    false
)]
#[case::client_auth_required_client_invalid_success(
    AuthType::Required,
    VeriferType::Invalid,
    true,
    true
)]
#[tokio::test]
async fn client_tests(
    #[case] auth_type: AuthType,
    #[case] verifier_type: VeriferType,
    #[case] use_client_auth: bool,
    #[case] expect_error: bool,
) -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ca_cert = include_bytes!("../certs/ca.crt").to_vec();

    let mut host_cert = include_bytes!("../certs/localhost.crt").to_vec();
    host_cert.extend(ca_cert.clone());

    let (tx, rx) = oneshot::channel();
    let server = serve(warp::Filter::map(warp::any(), || "Hello, World!"))
        .key(include_bytes!("../certs/localhost.key").to_vec())
        .cert(host_cert);

    let server = match auth_type {
        AuthType::Off => server,
        AuthType::Required => match verifier_type {
            VeriferType::Valid => {
                server.client_auth_required(ca_cert.clone(), Arc::new(ValidCertVerifier {}))
            }
            VeriferType::Invalid => {
                server.client_auth_required(ca_cert.clone(), Arc::new(InValidCertVerifier {}))
            }
        },
        AuthType::Optional => match verifier_type {
            VeriferType::Valid => {
                server.client_auth_optional(ca_cert.clone(), Arc::new(ValidCertVerifier {}))
            }
            VeriferType::Invalid => {
                server.client_auth_optional(ca_cert.clone(), Arc::new(InValidCertVerifier {}))
            }
        },
    };

    let (addr, server) = server.bind_with_graceful_shutdown(addr, async move {
        rx.await.ok();
    })?;

    let server = tokio::spawn(async move {
        server.await;
    });

    let identity = Identity::from_pkcs8_pem(
        include_bytes!("../certs/client.crt"),
        include_bytes!("../certs/client.key"),
    )?;

    let trust_root = Certificate::from_pem(&ca_cert).unwrap();
    let builder = ClientBuilder::new()
        .tls_built_in_root_certs(false)
        .add_root_certificate(trust_root);

    let builder = if use_client_auth {
        builder.identity(identity)
    } else {
        builder
    };

    let client = builder.build()?;
    let res = client
        .get(format!("https://localhost:{}", addr.port()))
        .send()
        .await;

    if expect_error {
        assert!(res.is_err());
    } else {
        let res = res.unwrap();
        assert_eq!(res.status(), 200);
    }

    tx.send(()).unwrap();
    server.await.unwrap();

    Ok(())
}
