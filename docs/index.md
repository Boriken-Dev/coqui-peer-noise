# coqui-peer-noise

Two peers run `Noise_XX_25519_AESGCM_SHA256`, prove their X25519 keys to each other and end up with an encrypted
session, in a browser or natively, through anything that carries their messages. This is a method of
[coqui-peer](https://boriken-dev.github.io/coqui-peer/), which holds the peer id, the trust store and the sans-IO
handshake trait.

!!! warning "Unreleased, not independently reviewed"
    The wire and the API may change at any commit. There are no releases for now: depend on a git
    revision.

```bash
cargo add --git https://github.com/Boriken-Dev/coqui-peer-noise --rev <commit> coqui-peer-noise
```

## Why a session, and not only a proof

A proof alone says who was there when it was made. Anything carrying the connection, such as a reverse
proxy that ends TLS or a relay a user was lured to, can forward a proof unchanged, watch both ends
succeed, and then speak for either. This method therefore ends in keys only the two peers hold, and an
application keeps every later message inside that session. Nothing depends on the TLS beneath it.

A party carrying the connection can forward it, see ephemeral keys and record sizes, delay it and cut it,
and a cut is reported. It cannot read or change a record, replace a key, or stand in for a pinned peer. It can, if it
also serves a page's JavaScript, replace that JavaScript, so a browser application ships the module with itself.

## Choosing a method

An endpoint uses one method, chosen by its operator and never negotiated on the connection.

- **This one** where the browser has X25519 in WebCrypto: an analysed Noise pattern, no signature, and neither static
  key in the clear.
- [coqui-peer-webcrypto](https://boriken-dev.github.io/coqui-peer-webcrypto/) where it does not: signed P-256, which
  browsers have had for longer.

The two have different keys and so different ids.

## How a key becomes an id

The Noise static key is the identity, with no signing key beside it. Its id is the SHA-256 of its RFC 8410 public key,
so a standard tool computes the same value:

```bash
openssl genpkey -algorithm x25519 -out key.pem
openssl pkey -in key.pem -pubout -outform DER | sha256sum
```

The API reference is under
[Rust API](https://boriken-dev.github.io/coqui-peer-noise/rust/index.html) for `main`. The source, the
wire protocol (`PROTOCOL.md`), the API headers (`AGENTS.md`) and the changelog are in the
[repository](https://github.com/Boriken-Dev/coqui-peer-noise).
