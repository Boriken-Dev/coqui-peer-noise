//! The settings of the methods as plain values a file, a form or a peer fills.

use core::time::Duration;

use coqui_builder::Describe;

use crate::handshake::NoiseBuilder;
use crate::pairing::{DEFAULT_FIRST_MESSAGE_TIMEOUT, PairingMethodBuilder};
use crate::session::DEFAULT_KEY_LIMIT;

/// What a [`NoiseBuilder`](crate::NoiseBuilder) takes whole through `fill`.
///
/// Identities, trust and the random source are not settings: they hold keys and code, so the
/// builder takes them as inputs. Every key is optional (an absent one is its default) and an
/// unknown key is refused. The type is `Describe`, so a `Partial<NoiseSettings>` is filled from text
/// and built. It is `#[non_exhaustive]`: start from
/// [`Default`] and assign the fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Describe)]
#[builder(setters_on = NoiseBuilder)]
#[map(deny_unknown_fields)]
#[non_exhaustive]
pub struct NoiseSettings {
    /// What one key may carry in one direction, each Noise message counting its length and 32;
    /// [`DEFAULT_KEY_LIMIT`]. There is no floor: a limit below what a message costs refuses that
    /// message, and a limit of zero passes only a close. Above the default, AES-GCM's
    /// confidentiality margin shrinks. A peer is held to the larger of this and the default, so a
    /// lower limit changes only this side's own sending.
    #[map(default = NoiseSettings::default().key_limit)]
    pub key_limit: u64,
    /// Whether this side changes its sending key by itself at the key limit, which it does by
    /// default. Off, `seal` gives [`Error::LimitReached`](crate::Error::LimitReached) there and a
    /// new handshake carries on. Each side decides for itself: the change is announced in the
    /// record that makes it.
    #[map(default = NoiseSettings::default().rekey)]
    pub rekey: bool,
}

impl Default for NoiseSettings {
    fn default() -> Self {
        Self {
            key_limit: DEFAULT_KEY_LIMIT,
            rekey: true,
        }
    }
}

/// What a [`PairingMethodBuilder`](crate::PairingMethodBuilder) takes whole through `fill`: the
/// [`NoiseSettings`] keys and how long a responder waits for a joiner.
///
/// Read as [`NoiseSettings`] is. `first_message_timeout` is a duration (`30`, `0.25`, `30s`,
/// `250ms`) or `never`, which is `None`, no bound but the transport's; an absent key is
/// `Some(`[`DEFAULT_FIRST_MESSAGE_TIMEOUT`]`)`, as [`Default`] has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Describe)]
#[builder(setters_on = PairingMethodBuilder)]
#[map(deny_unknown_fields)]
#[non_exhaustive]
pub struct PairingSettings {
    /// As [`NoiseSettings::key_limit`].
    #[map(default = PairingSettings::default().key_limit)]
    pub key_limit: u64,
    /// As [`NoiseSettings::rekey`].
    #[map(default = PairingSettings::default().rekey)]
    pub rekey: bool,
    /// How long a responder waits for the joiner's first message; a timeout set on the transport
    /// still applies if it is shorter. `Some(Duration::ZERO)` is refused when the method is built.
    /// `None` leaves the transport's own timeout as the only bound, and over a transport with none
    /// a silent stranger holds it until it closes.
    #[map(default = Some(DEFAULT_FIRST_MESSAGE_TIMEOUT), none = "never")]
    pub first_message_timeout: Option<Duration>,
}

impl Default for PairingSettings {
    fn default() -> Self {
        Self {
            key_limit: DEFAULT_KEY_LIMIT,
            rekey: true,
            first_message_timeout: Some(DEFAULT_FIRST_MESSAGE_TIMEOUT),
        }
    }
}

impl PairingSettings {
    /// The keys it shares with [`NoiseSettings`].
    pub(crate) fn noise(&self) -> NoiseSettings {
        NoiseSettings {
            key_limit: self.key_limit,
            rekey: self.rekey,
        }
    }
}
