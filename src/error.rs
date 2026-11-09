use core::fmt;
use std::io;

use coqui_peer::pair::PairingError;

/// Why a handshake, a session record or an identity failed.
///
/// `Display` is one lowercase clause and never quotes the input, a key or a path.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A handshake message is not one this protocol allows at this point: its length, a public key
    /// that is not in its one encoding or has small order, the peer presenting this side's own key,
    /// or its place in the exchange.
    Malformed,
    /// A handshake message does not decrypt: another key, another transcript or another outer
    /// binding.
    BadProof,
    /// The peer proved its key, and [`Trust`] does not admit it.
    ///
    /// [`Trust`]: crate::Trust
    Untrusted,
    /// This method has no [`Trust`](crate::Trust) configured for that role.
    Unsupported,
    /// The handshake is over, or a step came outside its place: [`finish`] before the end, a
    /// binding after the first message.
    ///
    /// [`finish`]: coqui_peer::Handshake::finish
    State,
    /// The random source failed.
    Random,
    /// A record does not open: altered, replayed, out of order, under other keys, of an unknown
    /// type, or after the peer's close. The session is over in both directions.
    Record,
    /// The transport ended before the peer's close record: records may have been cut off.
    Truncated,
    /// This side already sent its close record, so it sends no more.
    Closed,
    /// A key reached [`key_limit`](crate::NoiseSettings::key_limit). See
    /// [`Sealer::seal`](crate::Sealer::seal) and [`Opener::open`](crate::Opener::open).
    LimitReached,
    /// An export is longer than HKDF-SHA256 can give.
    TooLong,
    /// The text or bytes are not an X25519 private key in PKCS#8.
    Key,
    /// A pairing exchange was refused, by this side or the other, or did not follow its protocol.
    Pairing(PairingError),
    /// A setting is outside what it can hold: a first-message timeout of zero.
    Settings,
    /// Reading or writing an identity file, or a transport a pairing exchange runs on, failed.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "the message is not valid here",
            Self::BadProof => "a handshake message does not decrypt",
            Self::Untrusted => "the peer proved its key and is not trusted",
            Self::Unsupported => "this method is not configured for that role",
            Self::State => "this step is out of its place in the handshake",
            Self::Random => "the random source failed",
            Self::Record => "a session record does not open, or the session is over",
            Self::Truncated => "the stream ended before the peer closed it",
            Self::Closed => "this side already closed its direction",
            Self::LimitReached => "a key reached its limit",
            Self::TooLong => "the export is over what HKDF can give",
            Self::Key => "not an X25519 PKCS#8 private key",
            Self::Settings => "a setting is outside what it can hold",
            Self::Pairing(_) => "the pairing exchange failed",
            Self::Io(_) => "an identity file or a transport failed",
        })
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Pairing(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<PairingError> for Error {
    fn from(error: PairingError) -> Self {
        Self::Pairing(error)
    }
}
