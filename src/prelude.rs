//! The settings setters, for a builder written in another crate.
//!
//! [`NoiseBuilder`](crate::NoiseBuilder) and [`PairingMethodBuilder`](crate::PairingMethodBuilder)
//! have these as methods already; the traits are for code that holds a builder of its own over the
//! same settings.

pub use crate::settings::{NoiseSettingsSetters, PairingSettingsSetters};
