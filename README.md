# coqui-peer-noise

[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-peer-noise/blob/main/LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-peer-noise/test.yml)](https://github.com/Boriken-Dev/coqui-peer-noise/actions/workflows/test.yml)

**Two peers run `Noise_XX_25519_AESGCM_SHA256`, prove their X25519 keys to each other and end up with an
encrypted session, in a browser or natively, through anything that carries their messages.** This is a
method of [`coqui-peer`](https://github.com/Boriken-Dev/coqui-peer), which holds the peer id, the trust
store and the sans-IO handshake trait. It depends on no TLS session beneath it, so it works behind a
TLS-terminating reverse proxy, and such a proxy cannot read or change a record or end a stream unseen, though it can forward the run, delay,
block or cut the connection, and see sizes and timing, and one that also serves the page can do more: `PROTOCOL.md`,
"Through a relay" and "Where this method cannot protect". See the
[documentation](https://boriken-dev.github.io/coqui-peer-noise/) and the
[wire protocol](https://github.com/Boriken-Dev/coqui-peer-noise/blob/main/PROTOCOL.md).

> **Status: unreleased, with one independent review, by another AI agent.** That review was neither
> third-party nor formal, and there is no formal model of Noise XX with a SPAKE2 exchange inside it. The wire and
> the API may change at any commit. There are no releases for now: depend on a git revision.

## Features

- **One analysed pattern, with nothing to negotiate**: Noise XX with X25519, AES-256-GCM and SHA-256, chosen per
  endpoint and never on the wire. Neither side's static key goes in the clear, the initiator's goes only to the
  responder it pinned, and no signature leaves evidence.
- **The static key is the identity**: its id is the SHA-256 of its RFC 8410 public key, which
  `openssl pkey -pubout -outform DER | sha256sum` reproduces. A key has one encoding, and so one id; but one private key can
  prove eight public keys and so eight ids (`PROTOCOL.md`), none of which a trust decision depends on. A key of small
  order is refused.
- **A session**: Noise's handshake hash as an id both ends agree on, records of any length, a sealed close that
  makes a cut stream visible, a limit on each key with an automatic change of key, and exports. A party carrying
  the connection cannot read or change what goes through it, or end it unseen.
- **No downgrade**: a client stores the method with the pin and never falls back to another method when a connection
  fails; only a failed `supported()` (JavaScript), decided before any connection, selects another
  (`PROTOCOL.md`, "The downgrade rule").
- **Trust from `coqui-peer`**: fixed pins, or a live `TrustStore` read at each handshake, with waiting entries for
  proved strangers and rotation to a proved successor.
- **Pairing on a session of its own**: two strangers prove keys and run a PIN exchange sealed in the session, bound to it and
  not to any TLS, and from then on the key is what the handshake proves. That session carries nothing else.
- **Both roles in both languages**: Rust here, and a dependency-free JavaScript module in
  [`bindings/js/coqui-peer-noise`](https://github.com/Boriken-Dev/coqui-peer-noise/tree/main/bindings/js/coqui-peer-noise)
  over `crypto.subtle` with a non-extractable key, tested against each other, in a real browser, against `snow`
  and against published Noise vectors.

## Installation

```bash
cargo add --git https://github.com/Boriken-Dev/coqui-peer-noise --rev <commit> coqui-peer-noise
```

This crate names `coqui-peer` by git revision too. A consumer that uses `coqui-peer` directly names the
same revision, as `Cargo.toml` here does, so both see one `PeerId` type.

| Feature | Enables | What | Default |
| --- | --- | --- | --- |
| `pin` | `coqui-peer/pin` (SPAKE2, HKDF, HMAC) | PIN pairing (`pair::Pairing::pin`) | off |

Rust 1.89 or later. A build depends on `coqui-peer`, `x25519-dalek`, `aes-gcm`, `hkdf`, `sha2`,
`data-encoding`, `getrandom` and `zeroize`.

## Quick start

Prove both keys over any message transport, then keep every message inside the session:

```rust
use std::sync::mpsc::{Receiver, Sender, channel};
use std::{io, thread};

use coqui_peer::{MessageTransport, Method, drive_messages};
use coqui_peer_noise::{Identity, Noise, Trust};

struct Pipe(Sender<Vec<u8>>, Receiver<Vec<u8>>);

impl MessageTransport for Pipe {
    fn send(&mut self, message: &[u8]) -> io::Result<()> {
        self.0.send(message.to_vec()).map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
    fn recv(&mut self) -> io::Result<Vec<u8>> {
        self.1.recv().map_err(|_| io::ErrorKind::UnexpectedEof.into())
    }
}

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let (client, server) = (Identity::generate()?, Identity::generate()?);
let dialing = Noise::builder().identity(client.clone()).responders(Trust::pinned([server.peer_id()])).build().unwrap();
let listening = Noise::builder().identity(server.clone()).initiators(Trust::pinned([client.peer_id()])).build().unwrap();

let ((to_server, at_server), (to_client, at_client)) = (channel(), channel());
let serving = thread::spawn(move || {
    drive_messages(listening.respond(None).unwrap(), &mut Pipe(to_client, at_server)).unwrap()
});
let near = drive_messages(dialing.initiate()?, &mut Pipe(to_server, at_client))?;
let far = serving.join().unwrap();
assert_eq!(near.peer, server.peer_id());
assert_eq!(far.peer, client.peer_id());

let (mut near, mut far) = (near.session, far.session);
assert_eq!(near.id(), far.id());
let record = near.seal(b"every later message goes through the session")?;
assert_eq!(far.open(&record)?.as_deref(), Some(&b"every later message goes through the session"[..]));

// The last record: the far end reports a stream cut before it.
assert_eq!(far.open(&near.close()?)?, None);
far.verify_end()?;
# Ok(())
# }
```

## API overview

Everything is at the crate root.

| Item | Purpose |
| --- | --- |
| `Identity` | an X25519 key: generated, or read from and written to PKCS#8 |
| `Noise`, `NoiseHandshake` | the `coqui_peer::Method`, in both roles, and its settings |
| `Trust` | whom a role admits: fixed pins, or a `TrustStore` |
| `Session`, `Sealer`, `Opener` | records, the close, the limit, exports |
| `FramedStream` | a byte stream as messages, refused by declared length before the body is read |
| `PairingMethod`, `PairingHandshake`, `PairingSession`, `PairDial` | a stranger's handshake, and the sealed pairing drivers it ends in |
| `pair` | `coqui_peer::pair`, which runs on a `PairingSession` |

## Wire protocol

[PROTOCOL.md](https://github.com/Boriken-Dev/coqui-peer-noise/blob/main/PROTOCOL.md) says what this is, which parts are
ours and unanalysed, how a key becomes an id, what a relay can and cannot do, and what is not covered.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --no-default-features -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cd bindings/js/coqui-peer-noise && npm test
```

`npm test` includes the Rust examples in both roles and a real browser, which skip with a message where cargo or a
browser is absent. `COQUI_PEER_NOISE_REQUIRE_PEERS=1` makes that a failure. A run through a real nginx is by hand:
[`tools/proxy-run`](https://github.com/Boriken-Dev/coqui-peer-noise/tree/main/tools/proxy-run).

### Releasing

There are no releases for now. Every `v*` tag needs the maintainer's explicit go-ahead.

## License

Mozilla Public License 2.0: [LICENSE](https://github.com/Boriken-Dev/coqui-peer-noise/blob/main/LICENSE).
