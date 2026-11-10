# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **Breaking: the builders are coqui-builder's.** `Noise::builder()` and `PairingMethod::builder()` take no arguments: the identity is
  an input (`Noise::builder().identity(identity)`), as are `responders`, `initiators` and `random`. `build()` returns
  `Result<Noise, Missing>` and `Result<PairingMethod, BuildError<Error>>` (`Missing` names `identity`; `Failed` holds
  `Error::Settings` for a zero first-message timeout). `NoiseSettings` and `PairingSettings` derive `coqui_builder::Describe` in
  place of guatiao's traits; they are read through `Partial` from TOML, JSON or the environment, and their setters (`key_limit`, `rekey`,
  `first_message_timeout`) are methods of the builders, with the traits in the new `prelude` for other builders. `NoiseParts` and
  `PairingMethodParts` are what the builders collect. `NoiseBuilder` and `PairingMethodBuilder` are no longer `Clone`.
- **Breaking: `PairingSettings::first_message_timeout`** reads `never` for `None` and a duration text (`30`, `0.25`, `30s`, `250ms`, not
  `[secs, nanos]`); a document that leaves the key out now reads `Some(60 s)`, as `Default` has it, where it read `None`.
- **Breaking: `NonDefault` is coqui-builder's.** A `value` and a `default` print as `Type(text)` (`u64(1000)`, `bool(false)`,
  `Duration(30s)`, `Duration(never)`, `Random(caller's)`). In the JavaScript module `nonDefaults()` has the same text, and a duration is
  written as Rust writes one (`30s`, `250ms`, `1500us`, `700ns`).
- **Breaking: a weakened setting is a non-default setting.** `Noise::non_defaults` and `PairingMethod::non_defaults` return coqui-peer's `NonDefault { setting, value, default }`,
  one for every setting that differs from its default, named by key path (`key_limit`, `rekey`, `first_message_timeout`),
  and `random` when it is replaced. In the JavaScript module `nonDefaults()` has the same entries, named by the same Rust key paths (`key_limit`, `rekey`,
  `first_message_timeout`) with the same value text, and lists every difference, not only a looser one. The `weakened`
  names are gone; nothing keeps an alias before a release without a pre-release tag.

### Removed

- **Breaking:** `NoiseBuilder::settings`, `PairingMethodBuilder::settings` (use `fill(Partial::from(settings))`), the guatiao
  traits on `NoiseSettings` and `PairingSettings` (`ToValue`, `FromValue`, `Schema`), the writing of a settings value to text, and
  `Clone` on `NoiseBuilder` and `PairingMethodBuilder`.
- **Breaking:** the always-on `initiators` and `responders` = `any-with-key-proof` entries of a pairing method, in Rust
  and JavaScript: admitting any proved key is what a pairing method is, not a setting left off its default.

### Added

- **Builders and settings.** `Noise::builder(identity)` and `PairingMethod::builder(identity)` set a method up by the
  setting's name (`responders`, `initiators`, `key_limit`, `rekey`, `random`, `first_message_timeout`, `settings`), then
  `build()`; there is no `new`. `NoiseSettings { key_limit, rekey }` and `PairingSettings` (those and
  `first_message_timeout`, an `Option<Duration>`: `None` leaves only the transport's own bound, and `Some(Duration::ZERO)` is refused by
  `build()`, which returns `Result<PairingMethod, Error>` with the new `Error::Settings`) are guatiao values a
  file fills, and `settings(..)` takes one whole. `NoiseHandshake::bind` sets the outer-channel binding.
- `Noise` and `NoiseHandshake`: the `coqui_peer::Method` named `noise`, as initiator and responder, running
  `Noise_XX_25519_AESGCM_SHA256` and ending in a `Session`.
- `Session`, `Sealer`, `Opener`: Noise's handshake hash as an id both ends agree on, records of any length, `close`
  and `verify_end` so a cut stream is reported as `Error::Truncated`, `key_limit` and `rekey` per key and
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
  A stranger's session can carry nothing else. `first_message_timeout` and `DEFAULT_FIRST_MESSAGE_TIMEOUT` bound how long
  a stranger may say nothing, and it is told `Expired` when that runs out.
- `createPairingInitiator`, `createPairingResponder` and `createPairingDesk` in the JavaScript module: a typed PIN in both
  roles, the same bytes as Rust, over `BigInt` arithmetic that is not constant-time. `firstMessageTimeout` and
  `DEFAULT_FIRST_MESSAGE_TIMEOUT` bound how long a stranger may say nothing, and it is told `expired` when that runs out.
- `nonDefaults()` on what the JavaScript module's starters give and on its desk, and `MAX_PAIRING_RECORD`, as in Rust.
- `tests/vectors/pairing.json` and `tests/vectors/spake2.json`.
- `tools/proxy-run`: a real nginx between a real browser and the Rust side, by hand and not in CI.

- `record_length` and `recordLength`: the length of the record a message becomes. `supported()` in the JavaScript module: whether
  the runtime has what the method needs, for the downgrade rule in `PROTOCOL.md`.

### Changed

- A receiver refuses a peer only above the larger of its own key limit and the default, so a lower limit is a side's own
  sending only. A record whose last part is empty after a part is refused, in both languages.
- A pairing responder ends the exchange as expired after more than three reads in a row that time out with time left and no
  record between, instead of reading again at once.
- The JavaScript module copies a `Buffer` binding instead of viewing it.
- The wire: the prologue has a third field, `ordinary` or `pair`. Nothing is released, so the version stays.
- A JavaScript scalar multiplication adds `8L` to its scalar, which changes no result.
