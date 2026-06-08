//! Experimental pure-Rust XML signature verification backend.
//!
//! Implements the verification half of [`CryptoProvider`] using the pure-Rust
//! [`xml-sec`](https://crates.io/crates/xml-sec) crate for XML parsing,
//! canonicalization (exclusive C14N) and digest/reference processing, while the
//! actual RSA / ECDSA signature math is delegated to the RustCrypto backend
//! crates. No C dependency (no libxmlsec1, no OpenSSL).
//!
//! **Verify-only.** Signing (`sign_xml`) and encrypted-assertion decryption are
//! not supported here and return [`CryptoError::CryptoDisabled`]; use the
//! `xmlsec` feature for those.
//!
//! Anti-wrapping: [`reduce_xml_to_signed`](XmlDsig::reduce_xml_to_signed)
//! returns only the canonical bytes that were actually covered by a verified
//! signature reference (xml-sec's pre-digest payload), so content wrapped
//! outside the signed region cannot survive reduction.

use super::{CertificateDer, CryptoError, CryptoProvider, ReduceMode};
use crate::crypto::native::PrivateKey as NativePrivateKey;
use crate::schema::CipherValue;

use base64::{engine::general_purpose, Engine as _};
use rsa::pkcs1v15::{Signature as RsaSig, VerifyingKey as RsaVk};
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha1::Sha1;
use sha2::Sha256;
use x509_cert::der::{Decode, Encode};
use x509_cert::spki::DecodePublicKey;

use p256::ecdsa::{Signature as EcSig, VerifyingKey as EcVk};

use xml_sec::xmldsig::parse::SignatureAlgorithm as XmlSigAlg;
use xml_sec::xmldsig::verify::{DsigError, DsigStatus, VerifyContext, VerifyingKey};

mod decrypt;
mod sign;

const XMLENC_RSA_OAEP: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
const XMLENC_RSA_1_5: &str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
const XMLENC_AES128_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
const XMLENC_AES128_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes128-gcm";

/// Pure-Rust [`CryptoProvider`] (sign + verify + decrypt), no C dependency.
pub struct XmlDsig;

/// A verification key extracted from an X.509 certificate, dispatching the
/// actual signature math to the RustCrypto crates per declared algorithm.
enum CertKey {
    Rsa(RsaPublicKey),
    Ecdsa(Box<EcVk>),
}

fn key_err<E: std::fmt::Display>(e: E) -> CryptoError {
    CryptoError::KeyError(e.to_string())
}

impl CertKey {
    fn from_cert_der(der: &[u8]) -> Result<Self, CryptoError> {
        let cert = x509_cert::Certificate::from_der(der).map_err(key_err)?;
        let spki_der = cert
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(key_err)?;
        if let Ok(rsa) = RsaPublicKey::from_public_key_der(&spki_der) {
            return Ok(CertKey::Rsa(rsa));
        }
        let ec = EcVk::from_public_key_der(&spki_der)
            .map_err(|_| CryptoError::KeyError("unsupported certificate public key".into()))?;
        Ok(CertKey::Ecdsa(Box::new(ec)))
    }
}

impl VerifyingKey for CertKey {
    fn verify(
        &self,
        algorithm: XmlSigAlg,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        Ok(match (self, algorithm) {
            (CertKey::Rsa(key), XmlSigAlg::RsaSha256) => {
                let Ok(sig) = RsaSig::try_from(signature_value) else {
                    return Ok(false);
                };
                RsaVk::<Sha256>::new(key.clone())
                    .verify(signed_data, &sig)
                    .is_ok()
            }
            (CertKey::Rsa(key), XmlSigAlg::RsaSha1) => {
                let Ok(sig) = RsaSig::try_from(signature_value) else {
                    return Ok(false);
                };
                RsaVk::<Sha1>::new(key.clone())
                    .verify(signed_data, &sig)
                    .is_ok()
            }
            (CertKey::Ecdsa(key), XmlSigAlg::EcdsaP256Sha256) => {
                // XML-DSig ECDSA signatures are IEEE P1363 (raw r||s), not DER.
                let sig = match EcSig::from_slice(signature_value) {
                    Ok(sig) => sig,
                    Err(_) => match EcSig::from_der(signature_value) {
                        Ok(sig) => sig,
                        Err(_) => return Ok(false),
                    },
                };
                key.verify(signed_data, &sig).is_ok()
            }
            // Other algorithms (RSA-SHA384/512, ECDSA-P384) are not supported by
            // this verify-only backend.
            _ => false,
        })
    }
}

impl CryptoProvider for XmlDsig {
    type PrivateKey = NativePrivateKey;

    fn verify_signed_xml<Bytes: AsRef<[u8]>>(
        xml: Bytes,
        x509_cert_der: &CertificateDer,
        _id_attribute: Option<&str>,
    ) -> Result<(), CryptoError> {
        let xml = std::str::from_utf8(xml.as_ref()).map_err(key_err)?;
        let key = CertKey::from_cert_der(x509_cert_der.der_data())?;
        let result = VerifyContext::new()
            .key(&key)
            .verify(xml)
            .map_err(|e| CryptoError::KeyError(format!("xml signature verification failed: {e}")))?;
        match result.status {
            DsigStatus::Valid => Ok(()),
            _ => Err(CryptoError::InvalidSignature),
        }
    }

    /// Verify the document against the given certs and return only the canonical
    /// bytes covered by a verified signature reference.
    ///
    /// All [`ReduceMode`] values behave the same here (equivalent to
    /// `PreDigest`): the output is xml-sec's verified pre-digest payload, which
    /// by construction excludes any content wrapped outside the signed region.
    fn reduce_xml_to_signed(
        xml_str: &str,
        certs_der: &[CertificateDer],
        _reduce_mode: ReduceMode,
    ) -> Result<String, CryptoError> {
        for cert in certs_der {
            let key = CertKey::from_cert_der(cert.der_data())?;
            let result = match VerifyContext::new()
                .key(&key)
                .store_pre_digest(true)
                .verify(xml_str)
            {
                Ok(result) => result,
                Err(_) => continue,
            };

            if !matches!(result.status, DsigStatus::Valid) {
                continue;
            }

            let mut signed = Vec::new();
            for reference in &result.signed_info_references {
                if matches!(reference.status, DsigStatus::Valid) {
                    if let Some(bytes) = &reference.pre_digest_data {
                        signed.extend_from_slice(bytes);
                    }
                }
            }

            if signed.is_empty() {
                continue;
            }
            return String::from_utf8(signed).map_err(key_err);
        }
        Err(CryptoError::InvalidSignature)
    }

    fn decrypt_assertion_key_info(
        cipher_value: &CipherValue,
        method: &str,
        decryption_key: &Self::PrivateKey,
    ) -> Result<Vec<u8>, CryptoError> {
        decrypt::decrypt_key(cipher_value, method, decryption_key)
    }

    fn decrypt_assertion_value_info(
        cipher_value: &CipherValue,
        method: &str,
        decryption_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        decrypt::decrypt_value(cipher_value, method, decryption_key)
    }

    fn sign_xml<Bytes: AsRef<[u8]>>(
        xml: Bytes,
        private_key_der: &[u8],
    ) -> Result<String, CryptoError> {
        let xml = std::str::from_utf8(xml.as_ref()).map_err(key_err)?;
        sign::sign_enveloped(xml, private_key_der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_der_from_xml(xml: &str) -> CertificateDer {
        use base64::{engine::general_purpose, Engine as _};
        let marker = "X509Certificate>";
        let start = xml.find(marker).expect("no X509Certificate") + marker.len();
        let end = xml[start..].find("</").unwrap() + start;
        let b64: String = xml[start..end].split_whitespace().collect();
        general_purpose::STANDARD.decode(b64).unwrap().into()
    }

    #[test]
    fn verifies_legitimately_signed_response() {
        // RSA-SHA1 signed SAML response (legacy algorithm).
        let xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_signed_by_idp_2.xml"
        ));
        let cert = cert_der_from_xml(xml);
        XmlDsig::verify_signed_xml(xml, &cert, Some("ID")).expect("should verify");

        let reduced = XmlDsig::reduce_xml_to_signed(xml, &[cert], ReduceMode::default())
            .expect("should reduce");
        assert!(!reduced.is_empty());
    }

    #[test]
    fn rejects_wrong_certificate() {
        let xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/response_signed_by_idp_2.xml"
        ));
        // A real, valid certificate (the SP's) whose key did NOT sign this IdP response.
        let wrong = CertificateDer::from(
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/test_vectors/sp_cert.der"))
                .to_vec(),
        );
        let err = XmlDsig::verify_signed_xml(xml, &wrong, Some("ID"))
            .expect_err("wrong cert must not verify");
        assert!(matches!(err, CryptoError::InvalidSignature));
    }

    #[test]
    fn ancestor_wrapping_attack_content_is_not_signed() {
        // The signature is cryptographically valid, but the attacker content is
        // wrapped outside the signed reference. The reduced (signed) output must
        // not contain it.
        let xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/ancestor_attack_signed.xml"
        ));
        let cert = cert_der_from_xml(xml);
        let reduced = XmlDsig::reduce_xml_to_signed(xml, &[cert], ReduceMode::default())
            .expect("should reduce to signed content");
        assert!(
            !reduced.contains("attacker.evil.com"),
            "attacker-controlled content leaked into signed output"
        );
    }

}
