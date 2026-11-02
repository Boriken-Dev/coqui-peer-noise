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
mod trust;

pub use coqui_peer::{
    Established, KeyMaterial, MessageTransport, Method, PeerId, Random, TrustStore, Weakening, pair,
};
pub use error::Error;
pub use framed::{CurrentReadTimeout, FramedStream, MAX_HANDSHAKE_MESSAGE};
pub use handshake::{METHOD, Noise, NoiseHandshake, PROFILE, random};
pub use identity::Identity;
pub use noise::PROTOCOL_NAME;
pub use pairing::{
    MAX_PAIRING_RECORD, PAIR_EXPORT_LABEL, PairDial, PairingHandshake, PairingMethod,
    PairingSession,
};
pub use session::{DEFAULT_KEY_LIMIT, Opener, Sealer, Session};
pub use trust::Trust;
