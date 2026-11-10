# `coqui-peer-noise` — API header

Header-file-style reference for the `coqui-peer-noise` crate: every public item with its
signature, contract and gotchas, so the crate can be used without reading its source. It ships inside
the package and is self-contained. Development documentation lives with the source at
<https://github.com/Boriken-Dev/coqui-peer-noise>.

One Cargo feature, off by default: `pin`, which is `coqui-peer/pin` (SPAKE2, HKDF, HMAC), for `pair::Pairing::pin`.
MSRV Rust 1.89. A build depends on `coqui-peer` (by git revision, `984db3d`),
`coqui-builder` (by revision), `x25519-dalek`, `aes-gcm`, `hkdf`, `sha2`, `data-encoding`, `getrandom` and `zeroize`. This crate is
unreleased, with one independent review by another AI agent (neither third-party nor formal) and no formal model
of XX with SPAKE2 inside it: depend on a git revision, and name the same `coqui-peer`
revision if you use it directly; the wire and API may change at any commit. This is the method named `noise`
of `coqui-peer` (`PeerId`, `TrustStore`, the sans-IO `Handshake`); its API header ships in that crate.
`PROTOCOL.md` ships here and is the wire.

Imports: everything is at the crate root, including re-exports of `coqui-peer`'s `Established`,
`KeyMaterial`, `MessageTransport`, `Method`, `PeerId`, `Random`, `TrustStore`, `NonDefault` (coqui-builder's) and `pair`. `prelude` holds the settings setters traits (`NoiseSettingsSetters`, `PairingSettingsSetters`), for a builder written in another crate.

No `unsafe` code (`#![forbid(unsafe_code)]`), no process-wide state. Nothing reads a file or an
environment variable unless the caller names a path. Ephemeral and long-term keys, every chaining key, the export
secret and PEM text are held on the heap and zeroed when dropped; copies a move leaves on the stack, and the
stack state of `x25519-dalek`, `hkdf`, `sha2` and `aes-gcm`, are not.

## Identity (`coqui_peer_noise::Identity`)

```rust
pub struct Identity;                       // Clone (one shared copy); Debug shows only the id
impl Identity {
    pub fn generate() -> Result<Identity, Error>;                 // the OS generator
    pub fn generate_with(random: &Random) -> Result<Identity, Error>;
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Identity, Error>;  // RFC 8410's 48 bytes, exactly
    pub fn from_pkcs8_pem(text: &str) -> Result<Identity, Error>; // -----BEGIN PRIVATE KEY-----
    pub fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>, Error>;
    pub fn read(path: &Path) -> Result<Option<Identity>, Error>;  // None when absent
    pub fn write_new(&self, path: &Path) -> Result<(), Error>;    // never replaces; 0600 on Unix; creates parents
    pub fn open_or_create(path: &Path) -> Result<Identity, Error>;
    pub fn peer_id(&self) -> PeerId;                              // SHA-256 of spki_der
    pub fn spki_der(&self) -> &[u8; 44];
    pub fn public_key(&self) -> &[u8; 32];
    pub fn key_material(&self) -> KeyMaterial;                    // method "noise", label "PUBLIC KEY"
}
```

The Noise static key is the identity: there is no signing key. `openssl genpkey -algorithm x25519` writes a key this
reads, and `openssl pkey -pubout -outform DER | sha256sum` gives its id. On Windows a written file inherits its
directory's ACL. Errors: `Error::Key` for what is not such a key, `Error::Io` for the file, `Error::Random`.

## Trust (`coqui_peer_noise::Trust`)

```rust
#[non_exhaustive]
pub enum Trust { Pinned(BTreeSet<PeerId>), Store(TrustStore) }
impl Trust { pub fn pinned(ids: impl IntoIterator<Item = PeerId>) -> Trust; }
```

Decided after the peer proved its key, never before.

- `Pinned`: fixed at build; an empty set admits nobody; a pin of a digest other than SHA-256 matches
  nothing.
- `Store`: read at each handshake, so a key removed or retired is refused from the next handshake on.
  The stored key must be of this method. A responder records a proved stranger with
  `record_waiting`, under the `source` given to `respond`; an initiator
  records nobody. The proved pending successor of an accepted key gets `prove_successor`, then
  `promote_successor` unless `RotationOptions::require_approval`, in which case it is refused until the
  caller promotes it.
- There is no way to admit anyone here: a stranger's session is a `PairingSession`.

How strangers wait is the store's: a source at `WaitingLimits::per_source` refuses a newcomer and keeps
those waiting, and records one new peer per `TrustStoreBuilder::record_interval`. A flood can fill a source;
it cannot remove anyone. Behind a reverse proxy every peer shares the proxy's source, unless the caller
passes the client's address from a header it trusts.

## The method (`coqui_peer_noise::{Noise, NoiseHandshake, METHOD, PROFILE, PROTOCOL_NAME, random}`)

```rust
pub const METHOD: &str = "noise";
pub const PROFILE: &str = "dev.boriken.coqui.peer-noise/v1";
pub const PROTOCOL_NAME: &str = "Noise_XX_25519_AESGCM_SHA256";
pub fn random() -> Random;                    // the OS generator
pub struct Noise;                             // Clone (shared); Debug shows no secret
impl Noise {
    pub fn builder() -> NoiseBuilder;      // neither role until responders or initiators
    pub fn identity(&self) -> &Identity;
    pub fn settings(&self) -> NoiseSettings;
    pub fn non_defaults(&self) -> Vec<NonDefault>;  // every NoiseSettings key that differs, by key path (`key_limit`, `rekey`); `random` when replaced
}
// Not Clone. The last write of a key wins, whichever way it was written.
pub struct NoiseBuilder;
pub struct NoiseParts;                        // Debug; what the builder collects
impl NoiseBuilder {
    pub fn identity(self, identity: Identity) -> NoiseBuilder;      // required
    pub fn responders(self, trust: Trust) -> NoiseBuilder;  // whom initiate() admits
    pub fn initiators(self, trust: Trust) -> NoiseBuilder;  // whom respond() admits
    pub fn key_limit(self, bytes: u64) -> NoiseBuilder;     // per key, per direction; DEFAULT_KEY_LIMIT; no floor
    pub fn rekey(self, rekey: bool) -> NoiseBuilder;        // change key at the limit; on by default
    pub fn random(self, random: Random) -> NoiseBuilder;    // secure, or for test vectors only
    pub fn fill(self, settings: Partial<NoiseSettings>) -> NoiseBuilder;   // only the keys the partial sets
    pub fn fill_from(self, source: &mut impl Source) -> Result<NoiseBuilder, FillError>;
    pub fn non_defaults(&self) -> Vec<NonDefault>;   // the settings' keys, not `random`
    pub fn build(self) -> Result<Noise, Missing>;    // Missing names `identity`
}
// Describe: every key optional, unknown keys refused; a Partial<NoiseSettings> is read from text and built.
#[non_exhaustive] pub struct NoiseSettings { pub key_limit: u64, pub rekey: bool }   // Default: DEFAULT_KEY_LIMIT, true
impl coqui_peer::Method for Noise { /* name() = "noise"; initiate(); respond(source) */ }
pub struct NoiseHandshake;
impl NoiseHandshake {
    pub fn bind(self, binding: &[u8]) -> Result<NoiseHandshake, Error>;   // Error::State once the prologue is fixed
}
pub const MAX_HANDSHAKE_MESSAGE: usize = 96;
pub struct FramedStream<S>;                   // Debug
impl<S> FramedStream<S> {
    pub const fn new(stream: S, max_message: usize) -> FramedStream<S>;   // the limit in either direction
    pub const fn set_max_message(&mut self, max_message: usize);
    pub fn into_inner(self) -> S;
}
// MessageTransport for S: Read + Write + ReadTimeout; ReadTimeout, CurrentReadTimeout, WriteTimeout as S has them
pub trait CurrentReadTimeout: ReadTimeout {   // what ReadTimeout cannot say; PairingSession::respond needs it
    fn current_read_timeout(&self) -> Option<Duration>;
}
impl coqui_peer::Handshake for NoiseHandshake { /* Output = Session, Framing::Message */ }
```

Run it with `coqui_peer::drive_messages` over a reliable, ordered message transport, `drive_messages`
over a `FramedStream` for a byte stream (`coqui_peer::drive_stream` also works, and takes up to 1 MiB
before the message length applies; `FramedStream` refuses a frame by its declared length, with an
`InvalidData` I/O error), their `_until` forms for a deadline (**the caller bounds the handshake**), or a
`receive`/`transmit` loop. A read timeout set on a `FramedStream` bounds a whole `recv`, however many reads of the
stream it takes, so a peer sending a byte at a time cannot outlast it; zero is already spent, `TimedOut` with nothing
read; a `recv` that timed out keeps what it read of its frame for the next. A timeout set on the stream itself applies
per read. Three messages, of 32, 96 and 64 bytes, each binary. `initiate` draws the
ephemeral key and the first `transmit` gives the first message; `Error::Unsupported` without trust for that role.
`finish` gives `Established { peer, key: Some(key), session }`.

**An initiator finishes on sending the third message, and does not yet know it was accepted**: a responder that
refuses it ends the connection. Records it sends meanwhile go only to the responder it proved.

`bind` is for an endpoint that really ends a TLS connection itself: pass that connection's
exporter at both ends, and a relay ending TLS on both sides fails with `Error::BadProof`. Never set it
through a reverse proxy, where the two ends read different values. It is never sent. Set it before the first
`transmit` or `receive`.

## The session (`coqui_peer_noise::{Session, Sealer, Opener, DEFAULT_KEY_LIMIT}`)

```rust
pub const DEFAULT_KEY_LIMIT: u64 = 1 << 38;   // each Noise message counts its length and 32
pub const fn record_length(message_length: usize) -> usize;   // the record a message becomes; see below
pub struct Session;                           // Debug shows nothing
impl Session {
    pub fn id(&self) -> &[u8; 32];            // Noise's handshake hash; both ends agree; not secret
    pub fn seal(&mut self, message: &[u8]) -> Result<Vec<u8>, Error>;
    pub fn close(&mut self) -> Result<Vec<u8>, Error>;        // the last record of this direction
    pub fn open(&mut self, record: &[u8]) -> Result<Option<Vec<u8>>, Error>;  // None: the peer's close
    pub fn verify_end(&self) -> Result<(), Error>;            // call when the transport ended
    pub fn split(self) -> (Sealer, Opener);   // a reader and a writer on two threads; export first
    pub fn export(&self, label: &str, out: &mut [u8]) -> Result<(), Error>;   // at most 8160 bytes
}
impl Sealer { pub fn seal(&mut self, message: &[u8]) -> Result<Vec<u8>, Error>;
              pub fn close(&mut self) -> Result<Vec<u8>, Error>; }
impl Opener { pub fn open(&mut self, record: &[u8]) -> Result<Option<Vec<u8>>, Error>;
              pub fn verify_end(&self) -> Result<(), Error>; }
```

Each message is one record, sent whole and in order on a reliable transport, in binary frames. A message may be of
any length: a record is as many Noise messages as it takes (each at most 65535 bytes), and a message of up to 65518
bytes is one Noise message and 19 bytes more than itself. **`record_length(n)` is the length of the record a message
of `n` bytes becomes: `n + 19 * max(1, ceil(n / 65518))`, which is 19 bytes more up to 65,518 bytes, 38 at 65,519, 323 at
1 MiB and 4,883 at 16 MiB; a change of key, made only at the key limit, adds 19 to the record that holds it. Size a
`FramedStream` limit and any cap on a message from it, not from the message length.** What bounds it is the transport's frame limit: `FramedStream`'s
is `max_message`, in both directions, up to its length field's 2^32 - 1. A record a transport refuses has already used
its nonces, so the session cannot go on after that: end it.

**End every stream with `close`, and call `verify_end` when the transport ends.** A relay can cut the
connection at any record boundary; `verify_end` is `Error::Truncated` unless the peer's close record
opened. Each direction closes on its own: after `close`, `seal` is `Error::Closed`, and receiving goes on.

Any failure to open ends the session in both directions, split or not: `Error::Record` on every later
`open`, `seal` and `close`, and the caller closes the connection.

**At `key_limit`, with rekey on**, the sender changes its key in the record that crosses the limit, and the
stream goes on; nothing is asked of the caller, and the peer follows. A receiver refuses a sender above the larger of
its own limit and `DEFAULT_KEY_LIMIT`: a lower limit is only this side's own sending, and a limit above the default is raised
at both ends or not at all. A single Noise
message costing more than the limit is `Error::LimitReached`, with nothing sent and the session intact: a limit
of zero passes only a close. **With rekey off**, a record that would pass the limit is `Error::LimitReached`, with
nothing sent, the session intact and a close still passing; a new handshake carries on. An `open` past the limit
(a peer above the larger of this side's limit and the default) is `Error::LimitReached` and ends the session. Running out of nonces, at 2^64 - 1,
is `Error::LimitReached` from `seal` and ends the session.

`export` gives unrelated bytes for another label or another length. Keep every application message
inside the session: **a plain message on the same transport comes from whoever carries it**, even after
a successful handshake.

## Pairing (`coqui_peer_noise::{PairingMethod, PairingSession, PairDial}`, `pair`)

```rust
pub const PAIR_EXPORT_LABEL: &str = "EXPORTER-coqui-pair";
pub const MAX_PAIRING_RECORD: usize = 350;    // the longest record of an exchange; for FramedStream::set_max_message
pub const DEFAULT_FIRST_MESSAGE_TIMEOUT: Duration = Duration::from_secs(60);
pub struct PairingMethod;                     // Clone; Debug
impl PairingMethod {
    pub fn builder() -> PairingMethodBuilder;   // admits any proved key, in both roles
    pub fn identity(&self) -> &Identity;
    pub fn settings(&self) -> PairingSettings;
    pub fn non_defaults(&self) -> Vec<NonDefault>;    // every PairingSettings key that differs, by key path; `random` when replaced (admitting any proved key is what pairing is, not listed)
}
pub struct PairingMethodBuilder;              // not Clone
pub struct PairingMethodParts;                // Debug; what the builder collects
impl PairingMethodBuilder {
    pub fn identity(self, identity: Identity) -> PairingMethodBuilder;   // required
    pub fn responders(self, trust: Trust) -> PairingMethodBuilder;   // a joiner verifies the responder
    pub fn first_message_timeout(self, timeout: impl Into<Option<Duration>>) -> PairingMethodBuilder;   // None leaves the transport's own bound; Some(ZERO) is refused by build()
    pub fn key_limit(self, bytes: u64) -> PairingMethodBuilder;
    pub fn rekey(self, rekey: bool) -> PairingMethodBuilder;
    pub fn random(self, random: Random) -> PairingMethodBuilder;
    pub fn fill(self, settings: Partial<PairingSettings>) -> PairingMethodBuilder;
    pub fn fill_from(self, source: &mut impl Source) -> Result<PairingMethodBuilder, FillError>;
    pub fn non_defaults(&self) -> Vec<NonDefault>;   // the settings' keys, not `random`
    pub fn build(self) -> Result<PairingMethod, BuildError<Error>>;   // Missing names `identity`; Failed(Error::Settings) for Some(Duration::ZERO) as the first-message timeout
}
// As NoiseSettings, with `first_message_timeout: Option<Duration>` (text: `30`, `0.25`, `30s`, `250ms`, or `never` for None; an absent key is Some(60 s)); Default: DEFAULT_KEY_LIMIT, true, Some(60 s)
#[non_exhaustive] pub struct PairingSettings { pub key_limit: u64, pub rekey: bool, pub first_message_timeout: Option<Duration> }
impl coqui_peer::Method for PairingMethod { /* name() = "noise"; initiate(); respond(source) */ }
pub struct PairingHandshake;  // impl Handshake { Output = PairingSession, Framing::Message }
pub struct PairingSession;    // no seal, no open: it runs one exchange
impl PairingSession {
    pub fn id(&self) -> &[u8; 32];
    pub fn peer(&self) -> &KeyMaterial;
    pub fn peer_id(&self) -> PeerId;
    pub fn pair_channel(&self) -> Result<pair::Channel, Error>;  // the proved key; no caller names it
    pub fn join<T: MessageTransport>(self, pairing: Pairing, transport: &mut T) -> Result<PairDial<'_, T>, Error>;
    pub fn respond<T: MessageTransport + CurrentReadTimeout>(self, store: &TrustStore, desk: &PairingDesk,
        source: Option<SocketAddr>, transport: &mut T) -> Result<Paired, Error>;
}
impl<T: MessageTransport> PairDial<'_, T> {
    pub fn shown(&self) -> Option<&Shown>;    // a PIN with its slot, or a device flow's user code
    pub fn finish(self) -> Result<Paired, Error>;
}
```

**A stranger's session is this type, and only this type.** `Noise` cannot admit an unknown key, and `PairingSession` cannot
carry an application message, so what serves the application cannot be reached by proving just any key. The two purposes
differ in the prologue, so a run of one against the other is `Error::BadProof` at the second message. Drive the handshake
as `Noise`'s, then `join` or `respond`, which seal every message and end with a close record. `respond` blocks in
`PairingDesk::wait` for the operator. On success the responder has `accept_key`ed the joiner and the joiner stores
`Paired::peer`. Then both reconnect under `Noise`, with `Trust::Store` or a pin, and the full key is what the handshake
proves.

**A stranger's time is bounded.** Before the joiner's first message `respond` waits for the smaller of the transport's
`current_read_timeout` and `first_message_timeout`, `DEFAULT_FIRST_MESSAGE_TIMEOUT` unless set, `None` leaving only
the transport's own and `Some(Duration::ZERO)` refused when the method is built. So ask a person for the PIN before connecting, or raise this. From
that message each read waits until the desk's deadline. Either running out tells the joiner and returns
`Error::Pairing(PairingError::Refused(PairRefusal::Expired))`. Over a `FramedStream` the bound holds however slowly the bytes
come; another transport must make a whole `recv` obey its timeout. `drive_messages_until` clears the timeout it used, so
set your own after the handshake. `respond` sets the transport's read timeout, and leaves it at what it last needed.

A record longer than `MAX_PAIRING_RECORD` is `Error::Pairing(PairingError::Protocol)` without being opened, whatever the
transport lets through.

- **PIN** (feature `pin`): no pin needed: the PIN authenticates both keys and the session's binding. A wrong PIN is
  `Error::Pairing(PairingError::Refused(PairRefusal::WrongCode))` on both sides, and with the default one attempt burns the
  PIN at the desk, so `desk.show_pin()` again and start over on a new connection and session. **At the joiner a `WrongCode`
  spends the PIN: never join with it again, and get a new one.** A relay posing as the responder never reaches the real desk,
  so each run with the same PIN gives it a new guess. A host that retries by itself loses the PIN's guarantee.
- **Invitation**: `join` refuses (`Error::Pairing(PairingError::Unverified)`) unless the proved key is the inviter's, before
  anything is sent. Pin the inviter in `responders` too, to stop others at the handshake.
- **Device flow**: `join` refuses unless `responders` verified the responder, or `Pairing::allow_unverified(true)`, which
  lets a relay pair in place of both sides.

Over a `FramedStream`, the handshake's limit is `MAX_HANDSHAKE_MESSAGE`, and the exchange needs `set_max_message` with
`MAX_PAIRING_RECORD`. Behind a reverse proxy, pass the client's address as `source` from a header you trust, or every joiner
counts as the proxy for `DeskLimits`.

## Errors

`Error` (non-exhaustive): `Malformed` (not valid here: length, a key not in its one encoding or of small order, the
peer presenting this side's key, or place in the exchange), `BadProof` (a handshake message does not decrypt),
`Untrusted` (proved, and `Trust` does not admit it), `Unsupported` (no trust for that role), `State` (the handshake
is over, `finish` too early, a binding too late), `Random`, `Record`, `Truncated`, `Closed`, `LimitReached` (see the
session), `TooLong` (an export above 8160 bytes), `Key`, `Pairing(PairingError)`, `Io(io::Error)`. `Display` is one lowercase clause and never
quotes input, a key or a path. A handshake is over after an error: nothing queued leaves, and `transmit` is `State`.

## Gotchas

- The handshake alone authenticates nothing that follows it. Use the session, or a relay that forwarded
  the handshake owns the connection.
- A transport ending says nothing by itself: `verify_end` does. A peer that never calls `close` looks cut.
- A static key cannot sign, and it is the id: replacing it is a rotation through the store, and a key of another
  method is another id.
- One private key can prove 8 ids, through the points of order 8, as `PROTOCOL.md` says. Each is admitted only on its own pin or
  acceptance, so no trust decision turns on it, but a count of ids is not a count of private keys.
- A proxy that also serves the page can replace the module or use its key: `PROTOCOL.md`, "Where this method cannot protect".
- A responder's static key is sent to whoever starts a handshake; only an initiator's is kept from strangers.
- Each first message costs a responder two DH operations and an ephemeral key for free: bound connections and time
  in the host.
- A record's length is visible: there is no padding.
- A record whose last part is empty after a part is `Error::Record`: one message has one record.
- Removing a peer does not stop its running sessions: the host closes them, polling
  `TrustStore::is_accepted` if it must.
- `Error` and `Trust` are `#[non_exhaustive]`: a `match` needs a `_` arm.
