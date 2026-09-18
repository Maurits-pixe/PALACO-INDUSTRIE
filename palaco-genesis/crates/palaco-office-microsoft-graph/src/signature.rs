#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Canonical cryptographic binding for Microsoft Graph requests.
//!
//! The signed bytes are produced by one canonical encoder and are the exact
//! bytes supplied to verification. The signature authenticates the request;
//! it does not grant authorization.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{GraphMethod, GraphRequest};

/// Cryptographic algorithm identifier for the request signature contract.
pub const SIGNATURE_ALGORITHM: &str = "Ed25519";

/// A cryptographic signature bound to one exact canonical request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphRequestSignature {
    /// Opaque reference to the public signing key.
    pub key_reference: String,
    /// Algorithm identifier.
    pub algorithm: String,
    /// SHA-256 digest of the exact signed canonical bytes.
    pub signed_sha256: String,
    /// Raw Ed25519 signature bytes.
    pub signature: Vec<u8>,
    /// Provenance reference bound into the signed request.
    pub provenance_reference: String,
}

/// Errors raised by canonical encoding or signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// A required reference is empty.
    MissingReference,
    /// A signed request failed its internal integrity check.
    IntegrityMismatch,
    /// The supplied public key is not a valid Ed25519 key.
    InvalidPublicKey,
    /// The supplied signature is not a valid Ed25519 signature.
    InvalidSignature,
    /// The signature algorithm is unsupported.
    UnsupportedAlgorithm,
}

/// Encodes a Graph request deterministically using explicit field order and
/// length framing. No debug formatting or map ordering is part of the contract.
pub fn canonical_request_bytes(request: &GraphRequest) -> Vec<u8> {
    let mut out = Vec::new();
    push_bytes(&mut out, match request.method {
        GraphMethod::Post => b"POST",
    });
    push_bytes(&mut out, request.path.as_bytes());
    push_bytes(&mut out, request.body.as_bytes());
    push_bytes(&mut out, request.event_id.as_bytes());
    push_bytes(&mut out, request.trace_id.as_bytes());
    push_bytes(&mut out, request.authorization_reference.as_bytes());
    push_bytes(&mut out, request.idempotency_key.as_bytes());
    push_bytes(&mut out, request.source_ref.as_bytes());
    push_bytes(&mut out, request.evidence_ref.as_bytes());
    push_bytes(&mut out, request.provenance_reference.as_bytes());
    out
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    let length = value.len() as u64;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
}

/// Computes the SHA-256 digest of the exact bytes covered by the signature.
pub fn canonical_request_sha256(request: &GraphRequest) -> String {
    Sha256::digest(canonical_request_bytes(request))
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Signs the exact canonical request bytes with an Ed25519 signing key.
pub fn sign_request(
    request: &GraphRequest,
    key_reference: &str,
    signing_key: &SigningKey,
) -> Result<GraphRequestSignature, SignatureError> {
    if key_reference.trim().is_empty() || request.provenance_reference.trim().is_empty() {
        return Err(SignatureError::MissingReference);
    }
    if !crate::verify_request_integrity(request) {
        return Err(SignatureError::IntegrityMismatch);
    }

    let bytes = canonical_request_bytes(request);
    let signature = signing_key.sign(&bytes);
    Ok(GraphRequestSignature {
        key_reference: key_reference.to_string(),
        algorithm: SIGNATURE_ALGORITHM.to_string(),
        signed_sha256: canonical_request_sha256(request),
        signature: signature.to_bytes().to_vec(),
        provenance_reference: request.provenance_reference.clone(),
    })
}

/// Verifies the signature against the same canonical bytes used for signing.
pub fn verify_request_signature(
    request: &GraphRequest,
    signed: &GraphRequestSignature,
    public_key: &[u8; 32],
) -> Result<(), SignatureError> {
    if signed.key_reference.trim().is_empty() || signed.provenance_reference.trim().is_empty() {
        return Err(SignatureError::MissingReference);
    }
    if signed.algorithm != SIGNATURE_ALGORITHM {
        return Err(SignatureError::UnsupportedAlgorithm);
    }
    if signed.provenance_reference != request.provenance_reference {
        return Err(SignatureError::IntegrityMismatch);
    }
    if signed.signed_sha256 != canonical_request_sha256(request) {
        return Err(SignatureError::IntegrityMismatch);
    }

    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| SignatureError::InvalidPublicKey)?;
    let signature =
        Signature::from_slice(&signed.signature).map_err(|_| SignatureError::InvalidSignature)?;
    verifying_key
        .verify(&canonical_request_bytes(request), &signature)
        .map_err(|_| SignatureError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_request, GraphAdapterError};
    use palaco_office_event_contract::{
        Authorization, AuthorizationState, EventEnvelope, ExecutionState, ProposedAction,
    };

    fn event() -> EventEnvelope {
        EventEnvelope {
            event_id: "event-028".into(),
            authorization: Authorization {
                state: AuthorizationState::Granted,
                reference: Some("auth-028".into()),
            },
            execution: ExecutionState::Started,
            trace_id: "trace-028".into(),
            idempotency_key: "idem-028".into(),
            proposed_action: Some(ProposedAction {
                action_type: "create_task".into(),
                destination: "todo".into(),
            }),
            evidence_ref: "evidence-028".into(),
            source_ref: "graph:message-028".into(),
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7_u8; 32])
    }

    #[test]
    fn what_is_signed_is_exactly_what_is_verified() -> Result<(), GraphAdapterError> {
        let request = build_request(&event(), "auth-028")?;
        let signing_key = key();
        let signed = sign_request(&request, "key-028", &signing_key)
            .map_err(|error| GraphAdapterError::InvalidEvent(format!("{error:?}")))?;
        verify_request_signature(&request, &signed, signing_key.verifying_key().as_bytes())
            .map_err(|error| GraphAdapterError::InvalidEvent(format!("{error:?}")))?;
        Ok(())
    }

    #[test]
    fn tampering_breaks_signature_verification() -> Result<(), GraphAdapterError> {
        let request = build_request(&event(), "auth-028")?;
        let signing_key = key();
        let signed = sign_request(&request, "key-028", &signing_key)
            .map_err(|error| GraphAdapterError::InvalidEvent(format!("{error:?}")))?;
        let mut tampered = request.clone();
        tampered.body.push('x');
        assert!(verify_request_signature(
            &tampered,
            &signed,
            signing_key.verifying_key().as_bytes()
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn provenance_is_bound_but_authority_is_not_created() -> Result<(), GraphAdapterError> {
        let request = build_request(&event(), "auth-028")?;
        let signing_key = key();
        let signed = sign_request(&request, "key-028", &signing_key)
            .map_err(|error| GraphAdapterError::InvalidEvent(format!("{error:?}")))?;
        assert_eq!(signed.provenance_reference, request.provenance_reference);
        assert_eq!(signed.algorithm, "Ed25519");
        Ok(())
    }
}
