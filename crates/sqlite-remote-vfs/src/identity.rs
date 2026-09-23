//! Client identity: a public key and a signer for it.
//!
//! This is all the VFS knows about identity. Where the private key comes from (a seed, a key file, a smartcard, a
//! browser key store) is up to the application. The same applies to the database encryption key. The VFS only
//! handles ciphertext and has no access to that key.
//!
//! The client cannot choose the subject that owns its databases. The server derives the subject from the public key
//! whose private key the client has proven to hold. A client that could choose its subject could choose any other
//! client's subject.
//!
//! This module builds the transcript that is signed at login and derives the subject from a public key.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// Domain separation for login signatures: a signature over a transcript with this label is not valid in any other
/// context.
const TRANSCRIPT_LABEL: &[u8] = b"sqlite-remote-auth-v1";
/// Domain separation for the subject derivation.
const SUBJECT_LABEL: &[u8] = b"sqlite-remote-subject-v1";

/// Bounds for values the VFS shares internally. Natively `Send + Sync`, because the VFS uses several threads. No bounds
/// in a browser, which has one thread and whose values may hold JavaScript objects that are neither `Send` nor `Sync`.
#[cfg(not(target_arch = "wasm32"))]
pub trait Shared: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> Shared for T {}
#[cfg(target_arch = "wasm32")]
pub trait Shared {}
#[cfg(target_arch = "wasm32")]
impl<T> Shared for T {}

/// Signature algorithm used for the login.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Algorithm {
    Ed25519,
}

/// Signs the login challenge with the client's private key.
///
/// This is the only identity interface the VFS uses. The VFS never receives the private key. Key material stays with
/// the application.
pub trait Signer: Shared {
    /// Signature algorithm of the key.
    fn algorithm(&self) -> Algorithm;

    /// Public key. The server derives the subject from it.
    fn public_key(&self) -> Vec<u8>;

    /// Signs a login transcript and returns the signature.
    fn sign(&self, message: &[u8]) -> Vec<u8>;
}

/// Returns the subject the server derives from the signer's public key. The server stores the databases under it.
///
/// The subject is not secret. It identifies the databases but does not grant access to them.
pub fn subject(signer: &dyn Signer) -> String {
    subject_of(signer.algorithm(), &signer.public_key())
}

impl fmt::Debug for dyn Signer {
    /// Prints only the algorithm and the public key. The trait gives no access to the private key, so it cannot
    /// appear in the output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field("algorithm", &self.algorithm())
            .field("public_key", &URL_SAFE_NO_PAD.encode(self.public_key()))
            .finish()
    }
}

/// Builds the bytes the client signs and the server rebuilds to verify the signature.
///
/// Every part is prefixed with its length, so two different logins never produce the same bytes. The nonce makes a
/// signature valid for one login only.
///
/// The signature is not bound to the connection: a browser cannot bind it to the TLS session, and this client does
/// not compare the server id with the URL it connected to. A server the client connects to can therefore relay
/// another server's challenge and log in there with the signature. Applications should use a separate key for each
/// server.
pub(crate) fn transcript(
    label: &[u8],
    server_id: &str,
    nonce: &[u8],
    instance_id: &[u8],
    algorithm: Algorithm,
    public_key: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    for part in [
        label,
        server_id.as_bytes(),
        nonce,
        instance_id,
        &(wire_algorithm(algorithm) as u32).to_be_bytes(),
        public_key,
    ] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// Protocol value of an algorithm. It is part of the signed transcript.
pub(crate) fn wire_algorithm(algorithm: Algorithm) -> i32 {
    match algorithm {
        Algorithm::Ed25519 => sqlite_remote_protocol::v1::SigAlg::Ed25519 as i32,
    }
}

/// Derives the subject: SHA-256 of the subject transcript, base64url-encoded. The hash gives every subject the same
/// length, whatever the algorithm.
fn subject_of(algorithm: Algorithm, public_key: &[u8]) -> String {
    let bytes = transcript(SUBJECT_LABEL, "", &[], &[], algorithm, public_key);
    URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
}

/// Builds the transcript the client signs for one challenge.
pub(crate) fn login_transcript(
    server_id: &str,
    nonce: &[u8],
    instance_id: &[u8],
    algorithm: Algorithm,
    public_key: &[u8],
) -> Vec<u8> {
    transcript(TRANSCRIPT_LABEL, server_id, nonce, instance_id, algorithm, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Signer with a fixed public key that cannot sign. The tests here only need the public key.
    struct Named(Vec<u8>);

    impl Signer for Named {
        fn algorithm(&self) -> Algorithm {
            Algorithm::Ed25519
        }

        fn public_key(&self) -> Vec<u8> {
            self.0.clone()
        }

        fn sign(&self, _message: &[u8]) -> Vec<u8> {
            unreachable!("nothing is signed in these tests")
        }
    }

    fn keyed(public_key: &[u8]) -> Box<dyn Signer> {
        Box::new(Named(public_key.to_vec()))
    }

    #[test]
    fn subject_is_stable_for_same_key() {
        assert_eq!(subject(&*keyed(&[0x2a; 32])), subject(&*keyed(&[0x2a; 32])));
    }

    #[test]
    fn different_keys_give_different_subjects() {
        assert_ne!(subject(&*keyed(&[0x2a; 32])), subject(&*keyed(&[0x2b; 32])));
    }

    #[test]
    fn signer_debug_shows_only_public_parts() {
        // The trait exposes only the algorithm and the public key, so the Debug output contains nothing else.
        let printed = format!("{:?}", keyed(&[0xab; 32]));
        assert!(printed.contains("public_key"), "{printed}");
        assert!(printed.contains("Ed25519"), "{printed}");
    }

    #[test]
    fn length_prefixes_separate_parts() {
        // Without length prefixes, shifting the boundary between two parts would produce the same bytes, and one
        // signature would be valid for two logins.
        let one = login_transcript("wss://a.test", b"bc", b"i", Algorithm::Ed25519, b"k");
        let other = login_transcript("wss://a.testb", b"c", b"i", Algorithm::Ed25519, b"k");
        assert_ne!(one, other);
    }

    #[test]
    fn transcript_covers_every_parameter() {
        let base = login_transcript("wss://a.test", b"n", b"i", Algorithm::Ed25519, b"k");
        for other in [
            login_transcript("wss://b.test", b"n", b"i", Algorithm::Ed25519, b"k"),
            login_transcript("wss://a.test", b"m", b"i", Algorithm::Ed25519, b"k"),
            login_transcript("wss://a.test", b"n", b"j", Algorithm::Ed25519, b"k"),
            login_transcript("wss://a.test", b"n", b"i", Algorithm::Ed25519, b"l"),
        ] {
            assert_ne!(base, other, "every parameter must change the transcript");
        }
    }

    #[test]
    fn login_and_subject_transcripts_differ() {
        // The labels differ, so a login transcript never equals a subject transcript.
        assert_ne!(
            login_transcript("", &[], &[], Algorithm::Ed25519, b"k"),
            transcript(SUBJECT_LABEL, "", &[], &[], Algorithm::Ed25519, b"k")
        );
    }
}
