# `@boriken/coqui-peer-noise` — API header

Every export of this dependency-free ES module (`src/index.mjs`) with its contract, so it can be used
without reading the source. One file, so it can be vendored by copying it. It needs `crypto.subtle` with X25519:
a browser needs a secure context, and by MDN's data Chrome 133, Firefox 130 or Safari 17 (this module has been run in
Chrome and Edge on Windows, and Node 22 and 24). The wire is `PROTOCOL.md` of
<https://github.com/Boriken-Dev/coqui-peer-noise>, which the Rust crate of that name also
implements. Not independently reviewed; it may change at any commit.

```js
export const PROFILE;              // 'dev.boriken.coqui.peer-noise/v1'
export const METHOD;               // 'noise'
export const PROTOCOL_NAME;        // 'Noise_XX_25519_AESGCM_SHA256'
export const DEFAULT_KEY_LIMIT;    // 2 ** 38
export const profile;              // {id, protocol, method}

export async function generateIdentity();              // -> identity
export async function importIdentity(pkcs8);           // RFC 8410 PKCS#8 DER X25519 bytes -> identity
export async function loadOrCreateIdentity(name);      // IndexedDB database `name`, required -> identity
// identity: frozen {method, peerId: 'sha256:<hex>', publicKey: base64url SPKI, privateKey: CryptoKey}

export async function createInitiator(identity, expectedPeerId, options);
// -> {async hello() -> Uint8Array, async answer(raw) -> {reply: Uint8Array, peerId, session}}
export async function createResponder(identity, {allowClient, ...options});
// -> {async challenge(raw) -> Uint8Array, async accept(raw) -> {peerId, session}}
// allowClient: async (peerId) -> exactly true to admit; runs after the peer proved its key

// session (frozen):
//   id                          Uint8Array(32), Noise's handshake hash; both ends agree; not secret
//   async seal(bytes | string)  -> Uint8Array record; any length; send whole, in the order of the calls
//   async close()               -> Uint8Array, the last record of this direction
//   async open(record)          -> Uint8Array message, or null for the peer's close
//   verifyEnd()                 throws when the peer's close never came; call when the transport ends
//   async export(label, length) -> Uint8Array, secret to the two peers; length is bound in; at most 8160
//   destroy()                   drops the session's keys; every later call fails

export const __testing;            // not API: the layer beneath, for the published Noise vectors
```

`raw` and `record` are bytes (a `TypedArray`, `DataView` or `ArrayBuffer`). A handshake message has a fixed length, 32,
96 or 64, and any other is refused. Options:

- `keyLimit`: what one key may carry in one direction, each Noise message counting its length and 32. Default
  `DEFAULT_KEY_LIMIT`, no floor. A receiver refuses a sender above its own limit, so raise it at both ends or not at
  all.
- `rekey`: whether this side changes its sending key by itself at the limit. Default `true`. With `true`, a record
  crossing the limit carries the change and the stream goes on. With `false`, a record that would pass the limit is
  refused with nothing sent, a close still passes, and a new handshake carries on. Either way a single Noise message
  costing more than the limit is refused, so a limit of zero passes only a close.
- `binding`: a `Uint8Array` or `Buffer` holding the bytes of an outer channel both ends really read (a TLS exporter
  where each end terminates that TLS itself; never through a reverse proxy or from a browser), and anything else
  throws.
- `ephemeral`: replacing the generator, **for test vectors only**.

The module reads `seal` and `open` input when called, so the caller may reuse its buffer. Calls made together take
their place in call order.

An identity's private key must be non-extractable and X25519, and `peerId` must be the hash of `publicKey`, or
`createInitiator` and `createResponder` throw. `openssl pkey -pubout -outform DER | sha256sum` gives a key's id. Each
application names its own `loadOrCreateIdentity` database: the name is its identity. Concurrent tabs end up with one
key.

The flow: the initiator sends `await hello()`; the responder answers `await challenge(raw)`; the initiator takes that in
`await answer(raw)`, having proved the responder and checked its pin, sends `reply` and already holds the session; the
responder ends with `await accept(raw)`, having proved the client and asked `allowClient`.

**An initiator finishes first, and does not yet know it was accepted**: a responder that refuses it ends the connection.

Then **every application message goes through the session**, as a binary message:

```js
socket.binaryType = 'arraybuffer';
socket.send(await session.seal(JSON.stringify(message)));
const text = new TextDecoder().decode(await session.open(new Uint8Array(event.data)));
```

End a stream with `socket.send(await session.close())`, and when the transport ends call
`session.verifyEnd()`: a relay can cut the connection at any record boundary, and that is how a cut shows.

A plain message on the same transport comes from whoever carries it, such as a TLS-terminating reverse
proxy, even after a successful handshake. A record that fails to open ends the session in both directions:
close the connection. When done, `session.destroy()`. The module drops the ephemeral key when the handshake
ends and wipes the key bytes it holds; a `CryptoKey`'s memory is cleared when the engine collects it. Noise's HKDF needs
each chaining key as bytes, so those exist in JavaScript memory during a handshake.

## Errors

Every failure is a thrown `Error` whose message quotes nothing the peer sent; a handshake object is
over after one, and a later call says `Unexpected ...`. What is refused is in `PROTOCOL.md`.

## Gotchas

- A non-extractable key cannot be copied out, but any script in the origin can use it.
- A proxy that serves the page can replace this module. Ship it with the application.
- The static key cannot sign, and it is the id: a new key is a new peer.
- A responder's static key is sent to whoever starts a handshake; only an initiator's is kept from strangers.
- Each first message costs a responder two DH operations and an ephemeral key for free: bound connections and time in
  the host.
- A record's length is visible: there is no padding.
