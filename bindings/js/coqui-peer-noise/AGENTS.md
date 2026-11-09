# `@boriken/coqui-peer-noise` — API header

Every export of this dependency-free ES module (`src/index.mjs`) with its contract, so it can be used
without reading the source. One file, so it can be vendored by copying it. It needs `crypto.subtle` with X25519:
a browser needs a secure context, and by MDN's data Chrome 133, Firefox 130 or Safari 17 (this module has been run in
Chrome and Edge on Windows, and Node 22 and 24). The wire is `PROTOCOL.md` of
<https://github.com/Boriken-Dev/coqui-peer-noise>, which the Rust crate of that name also
implements. One independent review, by another AI agent (neither third-party nor formal); it may change at any commit.

```js
export const PROFILE;              // 'dev.boriken.coqui.peer-noise/v1'
export const METHOD;               // 'noise'
export const PROTOCOL_NAME;        // 'Noise_XX_25519_AESGCM_SHA256'
export const DEFAULT_KEY_LIMIT;    // 2 ** 38
export const profile;              // {id, protocol, method}

export async function supported();      // -> boolean: X25519, AES-GCM, HKDF, HMAC and SHA-256 work here; never throws, no connection
export function recordLength(n);        // -> the record length of an n-byte message: n + 19 * max(1, ceil(n / 65518)); RangeError otherwise

export async function generateIdentity();              // -> identity
export async function importIdentity(pkcs8);           // RFC 8410 PKCS#8 DER X25519 bytes -> identity
export async function loadOrCreateIdentity(name);      // IndexedDB database `name`, required -> identity
// identity: frozen {method, peerId: 'sha256:<hex>', publicKey: base64url SPKI, privateKey: CryptoKey}

export async function createInitiator(identity, expectedPeerId, options);
// -> {async hello() -> Uint8Array, async answer(raw) -> {reply: Uint8Array, peerId, session}, nonDefaults()}
export async function createResponder(identity, {allowClient, ...options});
// -> {async challenge(raw) -> Uint8Array, async accept(raw) -> {peerId, session}, nonDefaults()}
// allowClient: async (peerId) -> exactly true to admit; runs after the peer proved its key

// A stranger's handshake, which only pairs; see "Pairing" below.
export async function createPairingInitiator(identity, {responder, random, ...options});
// -> {async hello(), async answer(raw) -> {reply, peerId, pairing}, nonDefaults()}
export async function createPairingResponder(identity, {firstMessageTimeout, ...options});
// -> {async challenge(raw), async accept(raw) -> {peerId, pairing}, nonDefaults()}
export function createPairingDesk({pinAlphabet, pinLength, pinTtl, pinAttempts, now, random});
// -> frozen {showPin() -> {pin, expires}, shownPin() -> {pin, expires} | null, clearPin(), nonDefaults()}
export const PAIR_EXPORT_LABEL;    // 'EXPORTER-coqui-pair'
export const DEFAULT_FIRST_MESSAGE_TIMEOUT;   // 60000 (ms)
export const MAX_PAIRING_RECORD;   // 350: a longer record of an exchange is refused without being opened

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
  `DEFAULT_KEY_LIMIT`, no floor. A receiver refuses a sender above the larger of its own limit and the default, so a lower
  limit is only this side's own sending, and a higher one is raised at both ends or not at all.
- `rekey`: whether this side changes its sending key by itself at the limit. Default `true`. With `true`, a record
  crossing the limit carries the change and the stream goes on. With `false`, a record that would pass the limit is
  refused with nothing sent, a close still passes, and a new handshake carries on. Either way a single Noise message
  costing more than the limit is refused, so a limit of zero passes only a close.
- `binding`: a `Uint8Array` or `Buffer` holding the bytes of an outer channel both ends really read (a TLS exporter
  where each end terminates that TLS itself; never through a reverse proxy or from a browser), and anything else
  throws.
- `ephemeral`: replacing the generator, **for test vectors only**.

The module reads `seal` and `open` input, and the options, when called, so the caller may reuse its buffer. Calls made together take
their place in call order.

A setting is never refused for differing from its default, so **`nonDefaults()` says which do**: `[{setting, value, default}]`, each one that differs from
its default, as text. On the objects `createInitiator` and its like give, named as Rust names them and with the text Rust gives:
`key_limit` (a number), `rekey` (`false` against `true`), `first_message_timeout` (`[secs,nanos]`, as a duration) and a replaced
`ephemeral` or `random`; admitting any proved key is what a pairing starter is, so it is not listed. On a desk: fewer `pinCombinations`, more `pinAttempts`, a longer `pinTtl`, a replaced `random` or `now`.

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

## Pairing

A stranger's handshake ends in a `pairing`, and never in a session: it has no `seal` or `open`, so what serves the application
cannot be reached by proving just any key. The two purposes differ in the prologue, so a run of one against the other fails at
the second message. Once paired, both reconnect with `createInitiator` and `createResponder`, and the
full key is what the handshake proves.

```js
// pairing (frozen): id, peer: {method, label, publicKey}, verified
//   async join(pin, transport)                 -> {peerId, peer, mode: 'pin'}; the joiner, with a PIN a person typed
//   async respond(desk, transport, {accept})   -> {peerId, peer, mode: 'pin'}; accept(peerId, peer) keeps the joiner's key
// transport: {async send(bytes), async recv() -> Uint8Array, or null when the connection ended}
```

```js
const near = await createPairingInitiator(identity);
socket.send(await near.hello());
const {reply, pairing} = await near.answer(await nextMessage());
socket.send(reply);
const {peerId} = await pairing.join(typedPin, {send: async bytes => socket.send(bytes), recv: nextMessage});
// A new connection, pinned from now on:
const initiator = await createInitiator(identity, peerId);
```

A session runs one exchange, sealed, and its keys go when it ends, however it ends. Close the connection then, or the other
side waits for its transport. A joiner has no deadline of its own: bound it by ending the transport, which `recv` reports as
`null`. **A failure with a `refusal` property is the protocol saying no**: `wrong-code`, `expired`,
`exhausted`, `throttled`, `denied` or `disabled`. With the default of one attempt, a wrong PIN burns it at the desk:
`desk.showPin()` again and start over on a new connection. **At the joiner a `wrong-code` spends the PIN: never join with it
again, and get a new one.** A relay posing as the responder never reaches the real desk, so each run with the same PIN gives it
a new guess, and a host that retries by itself loses the PIN's guarantee. `accept` runs only after the PIN confirmed, and the
joiner hears it worked only after `accept` returned.

- `firstMessageTimeout` (`createPairingResponder`): the milliseconds a joiner has, from the call to `respond`, to send its
  first message, under the desk's `pinTtl`. Default `DEFAULT_FIRST_MESSAGE_TIMEOUT`, no floor: `0` is expired with nothing read.
  So ask a person for the PIN before connecting, or raise this. Past it, or past `pinTtl` from that first message, the joiner
  is told `expired`, and `respond` rejects with that `refusal`.
- `responder` (`createPairingInitiator`): the id the handshake must prove; `verified` is then `true`. A PIN needs none: it
  authenticates both keys. Without it the initiator accepts any proved key, which is all a `pairing` can do.
- Desk options, each with a default and no floor: `pinAlphabet` `'0123456789'`, `pinLength` `6`, `pinTtl` `600000` (ms, also how
  long an exchange may run), `pinAttempts` `1`, `now` `Date.now`. Options with no meaning (an empty alphabet, zero attempts) throw.
  More attempts or fewer codes raise a guess's chance in proportion.
- `random` (`createPairingInitiator`, `createPairingDesk`): a function of a length, for test vectors only.

The responder offers a PIN typed at the joiner, and refuses every other mode as `disabled`; the invitation and device flow are
Rust's. The desk counts attempts and time. **Limiting pending exchanges, and exchanges per source, is the host's.**

**The arithmetic is `BigInt`, written here, and not constant-time**, because WebCrypto has no group operation.
`PROTOCOL.md`, "What the JavaScript side leaves open", says what that means.

## Errors

Every failure is a thrown `Error` whose message quotes nothing the peer sent; a handshake object is
over after one, and a later call says `Unexpected ...`. What is refused is in `PROTOCOL.md`.

## Gotchas

- A non-extractable key cannot be copied out by a script, but any script in the origin can use it, and anyone who can read the
  browser profile can take it: Chrome was seen keeping its plain PKCS#8 in the origin's IndexedDB directory.
- **Store the method with the pin and never fall back to another on a connection failure.** Only a false `supported()`,
  asked before any connection, selects another method (`PROTOCOL.md`, "The downgrade rule").
- `recordLength(n)` is what a message of `n` bytes becomes on the wire (19 bytes more up to 65,518, then 19 for each further
  65,518; 323 at 1 MiB, 4,883 at 16 MiB). Size a frame limit from it. A key change adds 19.
- A record whose last part is empty after a part is refused: one message has one record.
- A proxy that also serves the page can replace this module or use its non-extractable key, so a hosted page gets no protection
  from that proxy. An extension, a packaged app, or a page whose code and pinned id come from elsewhere does.
- One private key can prove 8 ids, as `PROTOCOL.md` says. Each is admitted only on its own, so no trust decision turns on it, but
  a count of ids is not a count of private keys.
- The static key cannot sign, and it is the id: a new key is a new peer.
- A responder's static key is sent to whoever starts a handshake; only an initiator's is kept from strangers.
- Each first message costs a responder two DH operations and an ephemeral key for free: bound connections and time in
  the host.
- A record's length is visible: there is no padding.
- A stranger can burn a shown PIN by trying it. Bound connections in the host.
