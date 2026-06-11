//! Pure-Rust enveloped XML signature generation.
//!
//! The caller hands us a serialized document that already contains a
//! `<ds:Signature>` *template* (as produced by [`crate::signature::Signature`]):
//! a `<ds:SignedInfo>` with the right algorithms, a `<ds:Reference URI="#id">`
//! and empty `<ds:DigestValue>` / `<ds:SignatureValue>` placeholders. We:
//!
//! 1. canonicalize the referenced element with the enveloped-signature transform
//!    (the `<ds:Signature>` subtree removed) + exclusive C14N, digest it, and
//!    splice the digest into `<ds:DigestValue>`;
//! 2. canonicalize `<ds:SignedInfo>` (exclusive C14N), sign it with the private
//!    key per the declared `SignatureMethod`, and splice the signature into
//!    `<ds:SignatureValue>`.
//!
//! Canonicalization is delegated to the `xml-sec` crate; the signature math to
//! the RustCrypto crates. No C dependency.

use crate::crypto::CryptoError;
use base64::{engine::general_purpose, Engine as _};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use xml_sec::c14n::{canonicalize, C14nAlgorithm, C14nMode};

use roxmltree::{Document, Node};

const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

const DIGEST_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SIG_RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const SIG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

fn err<E: std::fmt::Display>(e: E) -> CryptoError {
    CryptoError::KeyError(e.to_string())
}

fn exclusive_c14n() -> C14nAlgorithm {
    C14nAlgorithm::new(C14nMode::Exclusive1_0, false)
}

/// Returns true if `node` is `root` or a descendant of `root`.
fn in_subtree(node: Node, root: Node) -> bool {
    node == root || node.ancestors().any(|a| a == root)
}

/// Locate the single `<ds:Signature>` element.
fn find_signature<'a, 'input>(doc: &'a Document<'input>) -> Result<Node<'a, 'input>, CryptoError> {
    let mut found = None;
    for node in doc.descendants() {
        if node.is_element()
            && node.tag_name().name() == "Signature"
            && node.tag_name().namespace() == Some(DSIG_NS)
        {
            if found.is_some() {
                return Err(CryptoError::KeyError(
                    "document contains more than one Signature element".into(),
                ));
            }
            found = Some(node);
        }
    }
    found.ok_or_else(|| CryptoError::KeyError("no Signature template found in document".into()))
}

/// Find a direct dsig child element by local name.
fn dsig_child<'a, 'input>(parent: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    parent.children().find(|c| {
        c.is_element() && c.tag_name().name() == name && c.tag_name().namespace() == Some(DSIG_NS)
    })
}

/// Resolve the element referenced by a same-document URI (`#id` or `""`).
fn resolve_reference<'a, 'input>(
    doc: &'a Document<'input>,
    uri: &str,
) -> Result<Node<'a, 'input>, CryptoError> {
    if uri.is_empty() {
        return Ok(doc.root_element());
    }
    let id = uri.strip_prefix('#').ok_or_else(|| {
        CryptoError::KeyError(format!("unsupported reference URI for signing: {uri}"))
    })?;
    doc.descendants()
        .find(|n| n.is_element() && n.attribute("ID") == Some(id))
        .ok_or_else(|| CryptoError::KeyError(format!("reference target not found: #{id}")))
}

/// Splice `text` as the text content of the element at `node`'s source range,
/// handling both the `<tag>...</tag>` (open/close) and `<tag/>` (self-closing)
/// forms.
fn splice_element_text(xml: &str, node: Node, text: &str) -> Result<String, CryptoError> {
    let malformed = || CryptoError::KeyError("malformed element while splicing".into());
    let range = node.range();
    let element_src = &xml[range.clone()];
    let open_end = element_src.find('>').ok_or_else(malformed)?;

    // Self-closing form `<name .../>`: rewrite to `<name ...>text</name>`.
    if element_src[..open_end].trim_end().ends_with('/') {
        let qname: String = element_src[1..]
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != '/' && *c != '>')
            .collect();
        if qname.is_empty() {
            return Err(malformed());
        }
        let start_tag = element_src[..open_end].trim_end().trim_end_matches('/');
        let replacement = format!("{start_tag}>{text}</{qname}>");
        let mut out = String::with_capacity(xml.len() + replacement.len());
        out.push_str(&xml[..range.start]);
        out.push_str(&replacement);
        out.push_str(&xml[range.end..]);
        return Ok(out);
    }

    // Open/close form `<name ...>...</name>`.
    let close_start = element_src.rfind('<').ok_or_else(malformed)?;
    if close_start <= open_end {
        return Err(malformed());
    }
    let abs_content_start = range.start + open_end + 1;
    let abs_content_end = range.start + close_start;
    let mut out = String::with_capacity(xml.len() + text.len());
    out.push_str(&xml[..abs_content_start]);
    out.push_str(text);
    out.push_str(&xml[abs_content_end..]);
    Ok(out)
}

fn digest(algorithm: &str, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match algorithm {
        DIGEST_SHA256 => Ok(Sha256::digest(data).to_vec()),
        DIGEST_SHA1 => Ok(Sha1::digest(data).to_vec()),
        other => Err(CryptoError::KeyError(format!(
            "unsupported digest algorithm: {other}"
        ))),
    }
}

fn load_rsa_private_key(der: &[u8]) -> Result<RsaPrivateKey, CryptoError> {
    RsaPrivateKey::from_pkcs8_der(der)
        .or_else(|_| RsaPrivateKey::from_pkcs1_der(der))
        .map_err(|_| CryptoError::KeyError("could not parse RSA private key for signing".into()))
}

fn sign_signed_info(
    algorithm: &str,
    private_key_der: &[u8],
    signed_info_c14n: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match algorithm {
        SIG_RSA_SHA256 => {
            let key = load_rsa_private_key(private_key_der)?;
            let signing_key = SigningKey::<Sha256>::new(key);
            Ok(signing_key
                .try_sign(signed_info_c14n)
                .map_err(err)?
                .to_vec())
        }
        SIG_RSA_SHA1 => {
            let key = load_rsa_private_key(private_key_der)?;
            let signing_key = SigningKey::<Sha1>::new(key);
            Ok(signing_key
                .try_sign(signed_info_c14n)
                .map_err(err)?
                .to_vec())
        }
        other => Err(CryptoError::KeyError(format!(
            "unsupported signature algorithm for signing: {other}"
        ))),
    }
}

pub(super) fn sign_enveloped(xml: &str, private_key_der: &[u8]) -> Result<String, CryptoError> {
    // ---- Pass 1: compute and splice the reference DigestValue. ----
    let with_digest = {
        let doc = Document::parse(xml).map_err(err)?;
        let signature = find_signature(&doc)?;
        let signed_info = dsig_child(signature, "SignedInfo")
            .ok_or_else(|| CryptoError::KeyError("Signature is missing SignedInfo".into()))?;
        let reference = dsig_child(signed_info, "Reference")
            .ok_or_else(|| CryptoError::KeyError("SignedInfo is missing Reference".into()))?;
        let digest_method = dsig_child(reference, "DigestMethod")
            .ok_or_else(|| CryptoError::KeyError("Reference is missing DigestMethod".into()))?;
        let digest_alg = digest_method
            .attribute("Algorithm")
            .ok_or_else(|| CryptoError::KeyError("DigestMethod is missing Algorithm".into()))?;
        let digest_value = dsig_child(reference, "DigestValue")
            .ok_or_else(|| CryptoError::KeyError("Reference is missing DigestValue".into()))?;

        let uri = reference.attribute("URI").unwrap_or("");
        let referenced = resolve_reference(&doc, uri)?;

        // Enveloped-signature transform + exclusive C14N: canonicalize the
        // referenced subtree with the Signature element excluded.
        let predicate = |node: Node| in_subtree(node, referenced) && !in_subtree(node, signature);
        let mut canon = Vec::new();
        canonicalize(&doc, Some(&predicate), &exclusive_c14n(), &mut canon).map_err(err)?;

        let digest_b64 = general_purpose::STANDARD.encode(digest(digest_alg, &canon)?);
        splice_element_text(xml, digest_value, &digest_b64)?
    };

    // ---- Pass 2: compute and splice the SignatureValue over SignedInfo. ----
    let doc = Document::parse(&with_digest).map_err(err)?;
    let signature = find_signature(&doc)?;
    let signed_info = dsig_child(signature, "SignedInfo")
        .ok_or_else(|| CryptoError::KeyError("Signature is missing SignedInfo".into()))?;
    // We canonicalize SignedInfo with exclusive C14N below, so the template must
    // declare that same method; otherwise the verifier would canonicalize
    // differently and the signature would not validate.
    let c14n_alg = dsig_child(signed_info, "CanonicalizationMethod")
        .ok_or_else(|| {
            CryptoError::KeyError("SignedInfo is missing CanonicalizationMethod".into())
        })?
        .attribute("Algorithm")
        .ok_or_else(|| {
            CryptoError::KeyError("CanonicalizationMethod is missing Algorithm".into())
        })?;
    if c14n_alg != EXC_C14N {
        return Err(CryptoError::KeyError(format!(
            "unsupported canonicalization method (only exclusive C14N is supported): {c14n_alg}"
        )));
    }
    let signature_method = dsig_child(signed_info, "SignatureMethod")
        .ok_or_else(|| CryptoError::KeyError("SignedInfo is missing SignatureMethod".into()))?;
    let sig_alg = signature_method
        .attribute("Algorithm")
        .ok_or_else(|| CryptoError::KeyError("SignatureMethod is missing Algorithm".into()))?;
    let signature_value = dsig_child(signature, "SignatureValue")
        .ok_or_else(|| CryptoError::KeyError("Signature is missing SignatureValue".into()))?;

    // Canonicalize SignedInfo (the CanonicalizationMethod is exclusive C14N).
    let predicate = |node: Node| in_subtree(node, signed_info);
    let mut canon = Vec::new();
    canonicalize(&doc, Some(&predicate), &exclusive_c14n(), &mut canon).map_err(err)?;

    let signature_bytes = sign_signed_info(sig_alg, private_key_der, &canon)?;
    let signature_b64 = general_purpose::STANDARD.encode(signature_bytes);

    splice_element_text(&with_digest, signature_value, &signature_b64)
}
