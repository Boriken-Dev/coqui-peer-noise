# `coqui-peer-noise` — API header

Header-file-style reference for the `coqui-peer-noise` crate: every public item with its
signature, contract and gotchas, so the crate can be used without reading its source. It ships inside
the package and is self-contained. Development documentation lives with the source at
<https://github.com/Boriken-Dev/coqui-peer-noise>.

No Cargo features. MSRV Rust 1.89. A build depends on `coqui-peer` (by git revision, `1f00bfe`),
`x25519-dalek`, `aes-gcm`, `hkdf`, `sha2`, `data-encoding`, `getrandom` and `zeroize`. This crate is
unreleased, with no independent security review: depend on a git revision, and name the same `coqui-peer`
revision if you use it directly; the wire and API may change at any commit. This is the method named `noise`
of `coqui-peer` (`PeerId`, `TrustStore`, the sans-IO `Handshake`); its API header ships in that crate.
`PROTOCOL.md` ships here and is the wire.

Imports: everything is at the crate root, including re-exports of `coqui-peer`'s `Established`,
`KeyMaterial`, `MessageTransport`, `Method`, `PeerId`, `Random`, `TrustStore` and `Weakening`.

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
- There is no way to admit anyone here.

How strangers wait is the store's: a source at `WaitingLimits::per_source` refuses a newcomer and keeps
those waiting, and records one new peer per `TrustStore::with_record_interval`. A flood can fill a source;
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
    pub fn new(identity: Identity) -> Noise;                 // neither role until a with_ below
    pub fn with_responders(self, trust: Trust) -> Noise;     // whom initiate() admits
    pub fn with_initiators(self, trust: Trust) -> Noise;     // whom respond() admits
    pub fn with_key_limit(self, bytes: u64) -> Noise;        // per key, per direction; DEFAULT_KEY_LIMIT; no floor
    pub fn with_rekey(self, rekey: bool) -> Noise;           // change key at the limit; on by default
    pub fn with_random(self, random: Random) -> Noise;       // secure, or for test vectors only
    pub fn identity(&self) -> &Identity;
    pub fn weakened(&self) -> Vec<Weakening>;  // a replaced random; a larger limit; rekey off
}
impl coqui_peer::Method for Noise { /* name() = "noise"; initiate(); respond(source) */ }
pub struct NoiseHandshake;
impl NoiseHandshake {
    pub fn with_binding(self, binding: &[u8]) -> Result<NoiseHandshake, Error>;   // Error::State once the prologue is fixed
}
pub const MAX_HANDSHAKE_MESSAGE: usize = 96;
pub struct FramedStream<S>;                   // Debug
impl<S> FramedStream<S> {
    pub const fn new(stream: S, max_message: usize) -> FramedStream<S>;
    pub const fn set_max_message(&mut self, max_message: usize);
    pub fn into_inner(self) -> S;
}
// MessageTransport for S: Read + Write; ReadTimeout and WriteTimeout as S has them
impl coqui_peer::Handshake for NoiseHandshake { /* Output = Session, Framing::Message */ }
```

Run it with `coqui_peer::drive_messages` over a reliable, ordered message transport, `drive_messages`
over a `FramedStream` for a byte stream (`coqui_peer::drive_stream` also works, and takes up to 1 MiB
before the message length applies; `FramedStream` refuses a frame by its declared length, with an
`InvalidData` I/O error), their `_until` forms for a deadline (**the caller bounds the handshake**), or a
`receive`/`transmit` loop. Three messages, of 32, 96 and 64 bytes, each binary. `initiate` draws the
ephemeral key and the first `transmit` gives the first message; `Error::Unsupported` without trust for that role.
`finish` gives `Established { peer, key: Some(key), session }`.

**An initiator finishes on sending the third message, and does not yet know it was accepted**: a responder that
refuses it ends the connection. Records it sends meanwhile go only to the responder it proved.

`with_binding` is for an endpoint that really ends a TLS connection itself: pass that connection's
exporter at both ends, and a relay ending TLS on both sides fails with `Error::BadProof`. Never set it
through a reverse proxy, where the two ends read different values. It is never sent. Set it before the first
`transmit` or `receive`.

## The session (`coqui_peer_noise::{Session, Sealer, Opener, DEFAULT_KEY_LIMIT}`)

```rust
pub const DEFAULT_KEY_LIMIT: u64 = 1 << 38;   // each Noise message counts its length and 32
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
bytes is one Noise message and 19 bytes more than itself. What bounds it is the transport's frame limit.

**End every stream with `close`, and call `verify_end` when the transport ends.** A relay can cut the
connection at any record boundary; `verify_end` is `Error::Truncated` unless the peer's close record
opened. Each direction closes on its own: after `close`, `seal` is `Error::Closed`, and receiving goes on.

Any failure to open ends the session in both directions, split or not: `Error::Record` on every later
`open`, `seal` and `close`, and the caller closes the connection.

**At `with_key_limit`, with rekey on**, the sender changes its key in the record that crosses the limit, and the
stream goes on; nothing is asked of the caller, and the peer follows. A receiver refuses a sender above its own
limit, so raise a limit at both ends or not at all. A single Noise
message costing more than the limit is `Error::LimitReached`, with nothing sent and the session intact: a limit
of zero passes only a close. **With rekey off**, a record that would pass the limit is `Error::LimitReached`, with
nothing sent, the session intact and a close still passing; a new handshake carries on. An `open` past the limit
(a peer above this side's limit) is `Error::LimitReached` and ends the session. Running out of nonces, at 2^64 - 1,
is `Error::LimitReached` from `seal` and ends the session.

`export` gives unrelated bytes for another label or another length. Keep every application message
inside the session: **a plain message on the same transport comes from whoever carries it**, even after
a successful handshake.

## Errors

`Error` (non-exhaustive): `Malformed` (not valid here: length, a key not in its one encoding or of small order, the
peer presenting this side's key, or place in the exchange), `BadProof` (a handshake message does not decrypt),
`Untrusted` (proved, and `Trust` does not admit it), `Unsupported` (no trust for that role), `State` (the handshake
is over, `finish` too early, a binding too late), `Random`, `Record`, `Truncated`, `Closed`, `LimitReached` (see the
session), `TooLong` (an export above 8160 bytes), `Key`, `Io(io::Error)`. `Display` is one lowercase clause and never
quotes input, a key or a path. A handshake is over after an error: nothing queued leaves, and `transmit` is `State`.

## Gotchas

- The handshake alone authenticates nothing that follows it. Use the session, or a relay that forwarded
  the handshake owns the connection.
- A transport ending says nothing by itself: `verify_end` does. A peer that never calls `close` looks cut.
- A static key cannot sign, and it is the id: replacing it is a rotation through the store, and a key of another
  method is another id.
- A responder's static key is sent to whoever starts a handshake; only an initiator's is kept from strangers.
- Each first message costs a responder two DH operations and an ephemeral key for free: bound connections and time
  in the host.
- A record's length is visible: there is no padding.
- Removing a peer does not stop its running sessions: the host closes them, polling
  `TrustStore::is_accepted` if it must.
- `Error` and `Trust` are `#[non_exhaustive]`: a `match` needs a `_` arm.
