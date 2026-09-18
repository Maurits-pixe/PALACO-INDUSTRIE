#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// An opaque authenticated-session handle.
///
/// The token material itself is deliberately not stored in this contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSession {
    /// Stable reference to the credential/session provider.
    pub session_reference: String,
}

impl AuthenticatedSession {
    /// Creates a session handle from a non-empty provider reference.
    pub fn new(session_reference: &str) -> Result<Self, String> {
        if session_reference.trim().is_empty() {
            return Err("session_reference is empty".into());
        }
        Ok(Self { session_reference: session_reference.to_string() })
    }
}

/// Authentication boundary for a Graph transport.
///
/// Implementations own token acquisition and secure credential handling.
/// The contract never receives or persists raw bearer tokens.
pub trait GraphAuthenticator {
    /// Authenticates the transport for one bounded request.
    fn authenticate(&self, session: &AuthenticatedSession) -> Result<(), String>;
}
