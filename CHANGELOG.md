# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `Noise` and `NoiseHandshake`: the `coqui_peer::Method` named `noise`, as initiator and responder, running
  `Noise_XX_25519_AESGCM_SHA256` and ending in a `Session`.
- `Session`, `Sealer`, `Opener`: Noise's handshake hash as an id both ends agree on, records of any length, `close`
  and `verify_end` so a cut stream is reported as `Error::Truncated`, `with_key_limit` and `with_rekey` per key and
  direction, and exports bound to their length.
- `Identity`: an X25519 key in RFC 8410's PKCS#8, generated, read and written. The static key is the identity, and
  its id is the SHA-256 of its RFC 8410 public key.
- `Trust`: fixed pins, or a live `TrustStore` with rotation and waiting entries, bounded by the store.
- `FramedStream`: refuses a frame by its declared length before reading it, and one above its limit before sending it; a
  read timeout on it bounds a whole frame. `CurrentReadTimeout`: a transport saying what read timeout it has.
- `NoiseHandshake::with_binding`: an optional outer binding in the Noise prologue, for an endpoint that ends TLS
  itself, refused once the prologue is fixed.
- The JavaScript module in `bindings/js/coqui-peer-noise`, with the same wire in both roles, over `crypto.subtle`.
- `PROTOCOL.md`, the published vectors in `tests/vectors/published.json`, and the shared vectors in
  `tests/vectors/session.json`.
- `PairingMethod`, `PairingSession` and `PairDial`, with the `pin` feature: `coqui_peer::pair` sealed in a session of its own.
  A stranger's session can carry nothing else. `with_first_message_timeout` and `DEFAULT_FIRST_MESSAGE_TIMEOUT` bound how long
  a stranger may say nothing, and it is told `Expired` when that runs out.
- `createPairingInitiator`, `createPairingResponder` and `createPairingDesk` in the JavaScript module: a typed PIN in both
  roles, the same bytes as Rust, over `BigInt` arithmetic that is not constant-time.
- `tests/vectors/pairing.json` and `tests/vectors/spake2.json`.
- `tools/proxy-run`: a real nginx between a real browser and the Rust side, by hand and not in CI.
