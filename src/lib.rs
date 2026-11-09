#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::alloc_instead_of_core
)]

extern crate alloc;

mod error;
mod framed;
mod handshake;
mod identity;
mod noise;
mod pairing;
mod session;
mod settings;
mod trust;

pub use coqui_peer::{
    Established, KeyMaterial, MessageTransport, Method, NonDefault, PeerId, Random, TrustStore,
    pair,
};
pub use error::Error;
pub use framed::{CurrentReadTimeout, FramedStream, MAX_HANDSHAKE_MESSAGE};
pub use handshake::{METHOD, Noise, NoiseBuilder, NoiseHandshake, PROFILE, random};
pub use identity::Identity;
pub use noise::PROTOCOL_NAME;
pub use pairing::{
    DEFAULT_FIRST_MESSAGE_TIMEOUT, MAX_PAIRING_RECORD, PAIR_EXPORT_LABEL, PairDial,
    PairingHandshake, PairingMethod, PairingMethodBuilder, PairingSession,
};
pub use session::{DEFAULT_KEY_LIMIT, Opener, Sealer, Session, record_length};
pub use settings::{NoiseSettings, PairingSettings};
pub use trust::Trust;
