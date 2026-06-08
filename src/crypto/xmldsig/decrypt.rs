//! Pure-Rust XML encryption (decryption) for encrypted SAML assertions.
//!
//! Mirrors the algorithms supported by the libxmlsec1 backend:
//! * key transport: RSA-OAEP-MGF1P (SHA-1) and RSA PKCS#1 v1.5
//! * data:          AES-128-CBC and AES-128-GCM

use super::{XMLENC_AES128_CBC, XMLENC_AES128_GCM, XMLENC_RSA_1_5, XMLENC_RSA_OAEP};
use crate::crypto::native::PrivateKey as NativePrivateKey;
use crate::crypto::CryptoError;
use crate::schema::CipherValue;
use base64::{engine::general_purpose, Engine as _};

fn decode_b64(value: &str) -> Result<Vec<u8>, CryptoError> {
    let stripped: String = value.split_whitespace().collect();
    general_purpose::STANDARD
        .decode(stripped)
        .map_err(|e| CryptoError::KeyError(e.to_string()))
}

fn crypto_err<E: std::fmt::Display>(e: E) -> CryptoError {
    CryptoError::KeyError(e.to_string())
}

/// Unwrap (decrypt) the AES content key using the SP's RSA private key.
pub(super) fn decrypt_key(
    cipher_value: &CipherValue,
    method: &str,
    decryption_key: &NativePrivateKey,
) -> Result<Vec<u8>, CryptoError> {
    let rsa = match decryption_key {
        NativePrivateKey::Rsa(rsa) => rsa,
        _ => {
            return Err(CryptoError::KeyError(
                "encrypted assertion key transport requires an RSA private key".into(),
            ))
        }
    };

    let ciphertext = decode_b64(&cipher_value.value)?;
    match method {
        // rsa-oaep-mgf1p uses SHA-1 for both the digest and MGF1.
        XMLENC_RSA_OAEP => rsa
            .decrypt(rsa::Oaep::<Sha1>::new(), &ciphertext)
            .map_err(crypto_err),
        XMLENC_RSA_1_5 => rsa
            .decrypt(rsa::Pkcs1v15Encrypt, &ciphertext)
            .map_err(crypto_err),
        _ => Err(CryptoError::EncryptedAssertionKeyMethodUnsupported {
            method: method.to_string(),
        }),
    }
}

use sha1::Sha1;

/// Decrypt the assertion ciphertext with the unwrapped AES content key.
pub(super) fn decrypt_value(
    cipher_value: &CipherValue,
    method: &str,
    key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let data = decode_b64(&cipher_value.value)?;
    match method {
        XMLENC_AES128_CBC => {
            use cbc::cipher::block_padding::NoPadding;
            use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
            const IV_LEN: usize = 16;
            if data.len() < IV_LEN || (data.len() - IV_LEN) % 16 != 0 {
                return Err(CryptoError::KeyError(
                    "aes-128-cbc ciphertext is not block aligned".into(),
                ));
            }
            let (iv, ciphertext) = data.split_at(IV_LEN);
            let mut buf = ciphertext.to_vec();
            // XML-Enc uses arbitrary padding where the final octet is the pad
            // length (RFC 2630 / W3C xmlenc §5.2), not PKCS#7. Decrypt without a
            // padding scheme and strip it manually.
            let plaintext = cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
                .map_err(crypto_err)?
                .decrypt_padded::<NoPadding>(&mut buf)
                .map_err(crypto_err)?;
            let pad_len = *plaintext.last().unwrap_or(&0) as usize;
            if pad_len == 0 || pad_len > plaintext.len() {
                return Err(CryptoError::KeyError("invalid xmlenc cbc padding".into()));
            }
            Ok(plaintext[..plaintext.len() - pad_len].to_vec())
        }
        XMLENC_AES128_GCM => {
            use aes_gcm::aead::{Aead, Nonce};
            use aes_gcm::{Aes128Gcm, KeyInit};
            const IV_LEN: usize = 12;
            const TAG_LEN: usize = 16;
            if data.len() < IV_LEN + TAG_LEN {
                return Err(CryptoError::KeyError("aes-128-gcm ciphertext too short".into()));
            }
            // XML-Enc GCM layout is IV(12) || ciphertext || tag(16); aes-gcm's
            // `decrypt` expects ciphertext||tag, which is exactly `data[12..]`.
            let (nonce, ciphertext_and_tag) = data.split_at(IV_LEN);
            let cipher = Aes128Gcm::new_from_slice(key).map_err(crypto_err)?;
            let nonce: Nonce<Aes128Gcm> = nonce.try_into().map_err(crypto_err)?;
            cipher
                .decrypt(&nonce, ciphertext_and_tag)
                .map_err(crypto_err)
        }
        _ => Err(CryptoError::EncryptedAssertionValueMethodUnsupported {
            method: method.to_string(),
        }),
    }
}
