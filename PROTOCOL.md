# The Noise method: wire profile v1

**Status:** experimental. It has had one independent review, by another AI agent: neither a third-party
review nor a formal one, and there is no formal model of XX with a SPAKE2 exchange inside it. It is not an IETF or ACP
standard. Implementations: Rust (`src/`) and JavaScript (`bindings/js/coqui-peer-noise/`), checked
against each other, against `snow` (a third implementation of this Noise protocol, in the Rust tests),
against the published vectors in `tests/vectors/published.json` and against `tests/vectors/session.json`
and `tests/vectors/pairing.json`.

## What this is

Pattern XX of the [Noise Protocol Framework](https://noiseprotocol.org/noise.html), revision 34, in one
concrete protocol, `Noise_XX_25519_AESGCM_SHA256`, and nothing else. It runs over any reliable, ordered
message transport and depends on nothing beneath it: no TLS session, certificate, origin or host name.
Both peers end the handshake holding a session id and keys, and **only records made with those keys are
tied to the peers that were proved**.

```text
-> e
<- e, ee, s, es
-> s, se
```

What rests on published analysis is that pattern with those functions. The Noise specification's own
section 7.7 gives XX these properties: from the second message on, payloads have source 2, sender
authentication that resists key-compromise impersonation, and from the third message on, destination 5,
encryption to a known recipient with strong forward secrecy. Kobeissi, Nicolas and Bhargavan, "Noise
Explorer" (ePrint 2018/766), say in their abstract that they confirm the stated security goals of the 12
fundamental patterns, of which section 7.5 lists XX as one. Girol et al., "A Spectral Analysis of Noise"
(USENIX Security 2020), compute the strongest threat model per pattern. Only those abstracts and the
specification were read for this document.

### What is ours, and what nobody has analysed

**Only the first row rests on published analysis.** Everything below it is this profile's or `coqui-peer`'s, built by
reading the sources named here and argued in this document, with no proof and no third-party or formal review. The papers above do not cover it.

| Piece | Whose | State |
| --- | --- | --- |
| Pattern XX with X25519, AES-256-GCM and SHA-256 | Noise specification | Analysed, as far as the abstracts above say |
| [Prologue](#handshake): three length-prefixed fields | Ours; section 6 allows a prologue | Its form not analysed |
| Refusing a small-order key, a second encoding, a payload, another length | Ours; stricter than the specification | Argued under [Handshake](#handshake) and [Identity](#identity) |
| A key's id: SHA-256 of its RFC 8410 SPKI | Ours | Argued under [Identity](#identity) |
| [Records](#records): a type byte inside the AEAD, parts, one shape per message | Ours | Not analysed |
| [The close record](#the-sealed-close) | Ours; section 14 leaves truncation to the application | Not analysed |
| [The key change](#limits-and-key-changes): `REKEY` is section 4.2's; announcing it in-band, by limit, is ours | Ours around the specification's function | Not analysed |
| [Export secret](#session-id-and-exports): a third output of `Split`'s HKDF, `Split` asks for two | Ours | Not analysed; rests on HKDF's outputs being independent |
| [Exports](#session-id-and-exports) | Ours | Not analysed |
| [Trust](#identity): pins, the store, waiting, rotation | `coqui-peer` | Not analysed |
| [Pairing](#pairing): the exchange, its messages, its confirmation | `coqui-peer` | Not analysed |
| A PIN exchange **inside** an XX session whose peer may be anyone, bound by an export | Ours, as `coqui-peer-webcrypto` does it | **The composition is not analysed**: nothing shows XX and SPAKE2 together give what each gives alone |
| SPAKE2: the `spake2` crate's constants M and N, its hash of the password, its side bytes, its key | That crate, version 0.4 | Its source was read and [compared with RFC 9382](#against-rfc-9382), by reading. It is not that RFC's profile |
| [The JavaScript SPAKE2](#pairing): Edwards25519 over `BigInt`, written here to match that crate | Ours | **Written from that crate's source, not constant-time**, checked only by the answers listed there. The scalar's length is hidden; nothing else is shown about its time |

The method is chosen per endpoint and never negotiated on one, so nothing on the path can talk it down.
A peer running another method fails the handshake, and so does a run for another purpose: pairing and ordinary runs differ
in the prologue, so a relay cannot pick which one a peer gets. Section 14's "Rollback" names what that closes.

### Why these functions

AES-256-GCM and SHA-256 are in WebCrypto, so a browser needs no dependency. noise-libp2p chose ChaChaPoly
instead, for platforms with no hardware AES; that reason does not outweigh this one here, and section 14
of the specification names the cost: AES-GCM's security falls with the volume under one key. See
[limits](#limits-and-key-changes).

X25519 in WebCrypto is what a browser must have. By MDN's browser-compat-data for `SubtleCrypto`, read
2026-11-02: Chrome 133, Firefox 130, Safari 17. A browser without it cannot use this method.
`coqui-peer-webcrypto` is the method for those. This module's browser test has run in Chrome 156 and
Edge 156 on Windows ARM64, with a non-extractable key held in IndexedDB; Firefox and Safari have not been
run.

### The downgrade rule

**A client stores the method with the pin, and never falls back to another method because a connection failed.** A
refused connection, a timeout, a failed handshake and a peer that does not speak the method are all things a party
carrying the connection can cause, so a fallback on any of them lets that party choose the method. Only a failed
`supported()` selects another method, and it does so before any connection: it runs each primitive this method needs in
the local runtime, asks nothing of any peer, and nothing on the network can change its answer. A client falls
back that way only to a method it already holds a pin for with that peer.

### Why not `snow`

The Rust side implements section 5's objects itself, over RustCrypto's `sha2`, `hkdf` and `aes-gcm` and
`x25519-dalek`, and uses `snow` 0.10 only as the other end of its tests. `snow` keeps `ck` in a `Copy`
struct it never zeroes, and its default cipher and DH key are plain arrays with no `Drop`, so the
[erasure](#erasure) below could not hold; a custom resolver fixes the cipher and the DH key but cannot
reach `ck`. It exposes no way to derive an export from `ck`, only a feature named `risky-raw-split`
returning the two cipher keys. And its default resolver uses `sha2` and `aes-gcm` lines other than the
coqui-peer family's. The cost is a second implementation to check, which the published vectors and the
`snow` tests do.

## Identity

| Field | Value |
| --- | --- |
| Method name | `noise` |
| Profile | `dev.boriken.coqui.peer-noise/v1` |
| Static key | an X25519 key, RFC 7748's 32 bytes on the wire |
| Stored form | RFC 8410's SubjectPublicKeyInfo DER: always 44 bytes, the 12 bytes `302a300506032b656e032100` then the key |
| Peer id | `sha256:` and the lowercase hex SHA-256 of the 44 bytes: coqui-peer's `PeerId` |
| Key material | method `noise`, label `PUBLIC KEY`, the 44 bytes |
| Private key file | RFC 8410's PKCS#8 in PEM: 48 bytes of DER, no attributes, no public key |

**The Noise static key is the identity.** `openssl pkey -pubout -outform DER | sha256sum` gives the id.

### The two options

**A. The static key is the identity**, which this profile does. **B. A signing identity signs the static
key**, as noise-libp2p does (its spec, revision r5: the payload carries `identity_key` and `identity_sig`,
a signature over `noise-libp2p-static-key:` and the static key).

libp2p gives two reasons for B, in "Distinct Noise and Identity Keys", and neither applies here:

- Its identity keys already exist, of several types, none usable as a Noise static key. A coqui-peer key
  already belongs to one method: `KeyMaterial` names it, and a `coqui-peer-webcrypto` id is not a
  `coqui-peer-tls` id today.
- It cannot be sure identity keys stay out of other protocols, which section 14 of the Noise
  specification warns about. A key made for this method stays in it, which is the rule that section
  gives.

What A gains:

- **The proof is Noise's own.** Section 14 of the specification: a protocol with static keys "verifies that
  the corresponding private keys are possessed", and leaves it to the application to decide whether the key
  is acceptable, by pins or certificates or key continuity. That is a `TrustStore`. B adds a signature layer
  outside what section 7.7 describes.
- **No signature to show.** libp2p's signature covers the static key alone, is not tied to a run, and anyone
  holding it can show it. This method signs nothing, so a transcript holds no signature for a third party to
  verify, unlike `coqui-peer-webcrypto`'s. That is all that is claimed here: no formal deniability result was
  read.
- **One key to hold.** In a browser a non-extractable X25519 key, with no second key type whose own
  availability would also limit the method.

What A costs:

- **A static key is the identity for as long as it lives.** With B, a static key can be replaced without
  changing the id. Here that is a rotation: `TrustStore::announce_successor`, then proving the successor,
  which `Trust::Store` promotes.
- **Moving an endpoint from `coqui-peer-webcrypto` means a new id.** The rule of `docs/browser.md` in coqui-acp
  is that a key that changes is a new agent, whose grants do not carry over. The store's successor mechanism
  takes a `KeyMaterial` of any method, so a peer proved under `webcrypto` can announce its `noise` key, and
  `tests/handshake.rs` runs the second half of that. Whether a host offers it is the host's choice.
- **A key that cannot sign.** A use that needs a signature needs another key.

### Against what it must fit

- **`PeerId`.** `Digest` has `sha256`, `sha384`, `sha512` and `sha1`; `x25519:<hash>` is not a `PeerId`, and
  parsing it is `Error::UnknownDigest`. `KeyMaterial::id` is always the SHA-256 of the bytes, and the docs of
  `KeyMaterial` say a method with other ids "does not store its keys here". So an id is `sha256:`, and which
  method it belongs to is `KeyMaterial.method`, which is what a `.acp` client reads.
- **What is hashed.** RFC 8410's SPKI and not the bare 32 bytes, as `coqui-peer-webcrypto` hashes its SPKI:
  the store keeps a `PUBLIC KEY` block that standard tools read, WebCrypto's `exportKey('spki')` gives the
  same bytes, and a key of another type under the same 32 bytes has another id.
- **`TrustStore`.** It compares the whole `KeyMaterial`, so the same bytes stored under another method are
  not this key. A responder records a stranger as waiting only after the proof, per its pairing contract.
- **Pairing.** `coqui_peer::pair`'s `Channel` wants `local` and `remote` as `KeyMaterial` and a `binding`, and
  this gives them: the proved key and an export. See [Pairing](#pairing).
- **`.acp`.** `docs/browser.md` in coqui-acp has `AcpIdentity { peer, verified, method }`, with `method` as "any
  proof's name, not a fixed list": `peer` is the id above, `method` is `noise`. `verified` may be true, since
  "every message after the proof is protected by keys that came out of it".

Each encoding is the only one: a key whose top bit is set, or at or above p, is refused. RFC 7748 section 5
has X25519 mask that bit and reduce modulo p, so without this one value would have several encodings and so several ids.

**One private key still proves 8 public keys, and so 8 ids.** A public key plus a point of order 8 is canonical and of large
order, and X25519 clamps its scalars to multiples of 8, so the DH output, and with it the proof, is the same as for the
honest key. Only the holder of the private key can do this, and only for its own key; a relay changing an ephemeral this way
fails, since the two transcripts differ. **No trust decision depends on one key having one id.** Each id is admitted only if it
is itself pinned, or accepted in a store, and making eight keys costs the same. So a count of ids is not a count of private
keys. Section 14's "Channel binding" warns about equivalent public keys; the session id and exports differ per run anyway. A
torsion check would need a group operation in each language for no attack it stops, so there is none.

## Handshake

Each message is sent whole and binary. Their lengths are fixed, and any other length is refused before
anything else is done with it. Payloads are always empty, and a message is refused for carrying one.

| # | From | Tokens | Length |
| --- | --- | --- | --- |
| 1 | Initiator | `e` | 32 |
| 2 | Responder | `e, ee, s, es` | 96: 32, 32 + 16, 16 |
| 3 | Initiator | `s, se` | 64: 32 + 16, 16 |

**The prologue** is three fields, each four big-endian length bytes and then its bytes: the profile above, the purpose,
`ordinary` or `pair`, and the [outer binding](#the-outer-binding), empty unless both ends set one. Section 6: a difference
fails the handshake with a decryption error at the second message. It is never sent.

**Order of checks.** A public key read is refused first if it is not in its one encoding. A DH output of all
zeros is refused. Section 12.1 allows that and discourages it, as adding complexity and not improving security,
and for Noise's own claims that stands. This profile claims one more thing, which section 14's "misusing public
keys as secrets" warns about: that a peer holds the static key it presents, so a store may record it as proved.
A key of small order gives all zeros whatever the private key (RFC 7748 section 6.1), so a peer could make the tag
below for a "key" it holds no private key for. Then the tag of the empty payload after `es` or `se`, which is the
proof of the static key. Then a static key equal to this side's own is refused. Only then is trust asked: the
initiator before its third message, which holds its static key, and the responder before anything else.

Trust is never decided on an unproved key. A responder keeping a store records a proved, unknown peer as
waiting, per coqui-peer's key-proof contract. Nothing enrolls a peer automatically.

**What each end knows when it finishes.** The responder finishes last, having proved the initiator and
decided. The initiator finishes on sending the third message, having proved the responder, and does not
yet know whether it was accepted: a refused initiator finds out by the connection ending. A record it
sends meanwhile is encrypted to the responder it proved, and is destination 5 of section 7.7.

## Session id and exports

- **Session id**: section 11.2's handshake hash `h`. It is not secret: whoever carried the handshake and knows
  any binding can compute it.
- **Transport keys**: `Split()`'s two outputs, the first for initiator to responder.
- **Export secret**: the third output of the same HKDF call (`HKDF(ck, zerolen, 3)`), which `Split()` does not
  ask for. Noise's HKDF is RFC 5869's with `ck` as salt and no info, so the first two outputs are what the
  specification gives. `ck` is then erased.
- **Exports**: `HKDF-SHA256(salt = absent, ikm = export secret, info = field("<profile>/export") || field(h) ||
  field(label) || length as 4 big-endian bytes)`, at most 8160 bytes. `h` is there because section 14 says a
  higher layer should bind to it and not to `ck`; another label or length gives unrelated bytes.

This construction is this profile's, not the specification's.

## Records

After the handshake, each application message is one **record**: a sequence of Noise transport messages, each
with the two-byte big-endian length section 13 recommends, carried whole as one binary message.

```text
record  = 1*( length message )
message = AESGCM(k, n, ad = "", type || contents)     ; section 12.4's nonce; n never resets
```

`type` is the first plaintext byte:

| Type | Meaning | Contents | Where |
| --- | --- | --- | --- |
| `01` | data: an application message's last or only part | any, possibly empty | last in a record |
| `02` | close | nothing | alone in a record |
| `03` | key change: the next message of this direction is under `REKEY(k)` | nothing | before another message, never twice in a row |
| `04` | part: more of this application message follows | any non-empty | exactly 65535 bytes on the wire |

**A record has one shape for one message.** Each part holds 65518 bytes of the message, the most section 3's
65535-byte limit leaves after the tag and the type, and the last part holds the rest. So a message of any
length is one record, and what bounds it is the transport, not this protocol. The last part is empty only when the whole
message is, so one message has one record, and a record whose last part is empty after a part is refused. A record's parts are bound to
each other by the nonce, so a relay can neither drop one nor cut the record between two without being refused.

**The length of a record.** Each Noise message adds its 2-byte length field, its 16-byte tag and its 1-byte type: 19
bytes. So a message of `n` bytes is a record of `n + 19 * max(1, ceil(n / 65518))` bytes, and a key change adds 19 to the
record that holds it. That is 19 bytes of overhead up to 65,518 bytes, 38 at 65,519, 323 at 1 MiB and 4,883 at 16
MiB. `record_length` (Rust) and `recordLength` (JavaScript) give it, and a transport's frame limit is set from it, not
from the message length.

A record that fails to open, has any other type, breaks the shapes above, has a byte after its last message, or
carries contents in a close or a key change, ends the session in **both** directions: nothing later is
believed, and nothing more is sent. Nothing of a record is returned before all of it opened.

## The sealed close

Section 3 of the specification has no end marker, and section 14 makes truncation "an application
responsibility". This is that: **a stream that ends without a close record is reported as truncated**. The
transport ending does not say the stream is complete, the close record does. Each direction closes on its own,
so one side can go on receiving after it closed. After `seal`ing a close a side seals nothing more; a record
after the peer's close is refused.

## Limits and key changes

Each setting has a default, no floor and no ceiling beyond the specification's own rules, and is the host's
to choose. `rekey` and a lower limit are each side's own: a change of key is announced in the record that makes
it. **A receiver refuses a sender above the larger of its own limit and the default**, so a lower limit only makes
its own sender change keys sooner, and a peer at the default is still believed. A limit above the default is raised at
both ends or not at all.

| Setting | Default | Meaning |
| --- | --- | --- |
| `key limit` | 2^38 | what one key may carry, in one direction, each Noise message counting its length and 32 |
| `rekey` | on | whether a sender changes its key at the limit by itself |

**Why 2^38.** Each message counts its length plus 32, about the bytes of AES blocks it uses: the block for the
tag's counter and GHASH's length block. RFC 8446 section 5.5 gives AES-GCM 2^24.5 full-size records (2^38.5
bytes) for a margin of about 2^-57. Noise section 14 says no more than 2^56 bytes, and section 15.1 gives the
margin behind that as less than one in a million, against a random guess at a 2^56-byte plaintext. The stricter
number is the default, and a host above it gets it listed by `non_defaults()`.

**The key change.** With rekey on, when the next Noise message would pass the limit, the sender first sends a
key change under the current key, applies section 4.2's `REKEY(k)`, and carries on under the new key, in the same
record, with the count at zero. The change itself and a close are not counted: each is 17 bytes and neither can
be refused for the limit. The nonce carries on, as section 11.3 says it must. So a key never carries more than
the limit, and a long record may span keys. A smaller limit rekeys more often, which also gives older records
protection against a later compromise of the key.

**At the limit.**

- A single Noise message costing more than the limit is refused with a limit error, whatever `rekey` says: no
  key could carry it. A limit of zero passes only a close.
- With rekey off, a record that would pass the limit is refused with a limit error before anything of it is
  sealed. The session stays intact, a close still passes, and carrying on takes a new handshake.
- An opener that sees a peer pass the limit on one key ends the session: only a peer running above the larger of this
  side's limit and the default does this, and part of a record may already have been opened. The default is the
  bound the key's security rests on, so a receiver holds a peer to no stricter one: a stricter one would end a session
  with a well-behaved peer and protect nothing the peer's own limit does not.
- The nonces run out at 2^64 - 1, section 5.1's reserved value: a direction that cannot fit a record below it
  ends the session, as section 5 requires. This is the specification's and not a setting.

## Through a relay

Anything carrying the connection is a relay: a TLS-terminating reverse proxy such as nginx, or an attacker holding
a certificate, or one a user was lured to. The method needs no cooperation from it and no TLS beneath it.

| A relay **can** | A relay **cannot** |
| --- | --- |
| forward the run unchanged, which only connects the two real parties | read a record or a static key, or learn the session's keys or exports |
| see ephemeral keys, the session id if it knows any binding, and each message's size and time | inject, alter, reorder, replay or reflect a record, or cut one in the middle |
| block, delay or cut the connection, which a peer reports as truncated | end a stream so that it looks complete: it has no key to make a close record |
| learn the responder's static key by starting a run with it, since a responder sends it to an initiator it has not authenticated: section 7.8's property 1 | learn an initiator's static key without being a responder that initiator admits: section 7.8's property 8 |
| run a handshake of its own under its own key, against a peer that trusts that key | make a peer that pins another id accept its key, or complete a run for a key whose private key it lacks |

**The right-hand column holds only for what goes through the session.** A peer that speaks plain application
messages beside the records, trusting the handshake, hands the whole connection to the relay: it forwards the
three messages, both ends succeed, and it then reads and writes as it likes.

**Where this method cannot protect.** A proxy that also serves the page can replace the module, or call the page's
non-extractable key from a script of its own, so a hosted page gets no protection from that proxy. An extension, a packaged app,
or a page whose code and pinned id come from elsewhere does.

**Whoever can read the browser profile can take the key.** A non-extractable `CryptoKey` cannot be copied out by a
script, but the browser stores it: in Chrome, the key's plain PKCS#8 was found in `000003.log` in the origin's IndexedDB
directory. Malware running as the same user, or a backup of the profile, takes the key and with it the peer's identity,
and the method has no defence against it. The same holds for any key a page keeps.

### The outer binding

Where each end really terminates one TLS connection itself, both may pass that connection's exporter as the
binding. It goes in the prologue and is never sent, so a relay ending TLS on both sides gives the two ends
different values and the handshake fails at the second message: it refuses such a relay, rather than only
blinding it. It adds nothing to what the session already protects. **Through a reverse proxy, or from a browser,
no two ends can read one value, so it stays empty.** Setting it through a proxy fails every handshake, which is
why it is opt-in and never derived automatically. It is fixed once the first message has gone.

Section 6 of the specification notes the prologue does not go into the encryption keys, only `h`. This uses it
for what that section says it is for, confirming both sides saw the same thing.

### What was run through a proxy

`tools/proxy-run` runs this for real. **nginx 1.30.6** (Fedora 44's aarch64 package, in WSL2, built against OpenSSL 3.5.9
and running with 3.5.7) ended TLS 1.3 and passed WebSocket to a relay, with a configuration holding only what a WebSocket
proxy needs. Chrome 156 and Edge 156, headless on Windows ARM64, were one end, in a secure context on the proxy's origin.
The Rust examples were the other, their frames carried to the proxy by a small client in that tool, because the crate has
no WebSocket. All 16 scenarios passed in both browsers, on Node 24 with Chrome and Node 22 with Edge: both roles, a record of
700 KB, a record altered, repeated and injected, a cut at a record boundary, a swallowed close, nginx's own read timeout
ending an idle stream, and PIN pairing followed by the ordinary method. Each of the 30 connections the relay took was plain,
from nginx. What the run shows about a proxy:

- **nginx passes a record whole and unchanged**, and needs no setting for this method.
- **A clean WebSocket close says nothing.** With a close code and `wasClean` true, the module still reported truncation
  where no close record came, which is the case the [sealed close](#the-sealed-close) exists for.
- **A proxy's read timeout looks like a cut**, because it is one. A host whose streams idle keeps them moving itself, or
  expects to reconnect.

No other proxy, nginx version or operating system has been run, and neither has Firefox or Safari.

## Pairing

`coqui_peer::pair` runs on a session of its own, bound to the session and not to any TLS beneath it. A joiner is a
stranger, so the responder admits any proved key for this. Both languages enforce what follows from that by what they
offer: such a handshake, whose prologue says `pair`, ends in a pairing session (`PairingSession` in Rust, `pairing` in
JavaScript), which holds the proved key and runs one exchange, and has no way to carry an application message. A session
that can carry one exists only with a peer a pin or a trust store admitted, on a prologue that says `ordinary`. Each message is one record. Once paired, both sides close and reconnect
under the ordinary method, and the full key is what the handshake proves.

The `Channel` is `local` this side's key, `remote` the key the handshake proved, which no caller names, `binding` a 32-byte
[export](#session-id-and-exports) under `EXPORTER-coqui-pair`, and `verified` when the joiner admitted the responder by a
pin or a store.

- **PIN.** A proved key of anyone is enough: the PIN authenticates both keys and the binding. A relay forwarding everything
  pairs the real parties with each other and learns nothing but sizes. A relay forwarding between two sessions of its own
  fails at the first message, since the keys differ. A relay that runs the exchange itself with each side, under its own
  key, has one guess at the PIN per run. With the default of one attempt per PIN, a wrong guess at the responder burns it.
  **At the joiner nothing burns it**: a relay posing as the responder never reaches the real desk, so the joiner still holds
  the PIN, and each new run with it is a new guess, online and one at a time. So a joiner's `wrong-code` spends the PIN: never
  run another exchange with it, and get a new one. A person will not retry a million times; a host retrying by itself, on a
  reconnect loop, loses the PIN's guarantee.
- **Invitation** (Rust). The secret goes as is, so the proved key must be the inviter's: `Pairing::join` refuses otherwise
  before anything is sent, and the secret goes only inside a record.
- **Device flow** (Rust). The joiner must have verified the responder by a pin or a store, or `join` refuses unless told
  `allow_unverified`, which lets a relay pair in place of both sides.

**How long a stranger may hold a responder.** Until the joiner's first message, the smaller of the transport's own read
timeout and a setting (60 seconds by default, no floor; the module's is also under `pinTtl`). From that message, until the
desk's deadline (`pin_ttl`, 10 minutes by default, or `device_ttl`). Past either, the responder sends refused, `02` expired,
and ends; a time already spent is expired with nothing read. A slow peer does not stretch it: `FramedStream` and the module
count from the start of the wait, not from the last byte.

**What a person must take from this.** The PIN is the whole of the authentication between strangers, and it is short. Its
strength is one guess in the number of codes per PIN shown (10^6 by default) and it rests on the attempts being counted,
so a responder that raises `pin_attempts` raises that chance in proportion. A joiner that a person never gave the right PIN
gets only a refusal. Anyone who reaches the port can burn a shown PIN, so a flood can stop pairing while it lasts: bound
connections in the host.

### The PIN exchange on the wire

The Rust side runs this through `coqui-peer`, whose source is the definition. The JavaScript module implements the same
messages for a typed PIN, and it is byte-compared with Rust in `tests/vectors/pairing.json`. Every message starts with the
version byte `01` and its kind; a key is its method, its label and its bytes, the first two after one length byte and the
last after four.

| Kind | From | Fields |
| --- | --- | --- |
| `01` hello | joiner | mode (`01` typed PIN), the joiner's key |
| `02` ready | responder | the responder's key, slot (`ff`: none) |
| `03` PAKE | joiner | SPAKE2 message, after one length byte |
| `04` reply | responder | SPAKE2 message, after one length byte; 32-byte MAC |
| `05` confirm | joiner | 32-byte MAC |
| `07` done | responder | the responder's key |
| `08` refused | either | why: `01` wrong code, `02` expired, `03` exhausted, `04` throttled, `05` denied, `06` disabled |

A key in a message must be the one the session proved, to the byte, or the exchange is over.

- **SPAKE2.** The joiner is side A and the responder side B, and their ids (`sha256:<hex>`) are `idA` and `idB`. The
  password is the PIN's UTF-8 bytes. From the `spake2` crate 0.4: `w` is HKDF-SHA256 of the password with an empty salt and
  info `SPAKE2 pw`, 48 bytes read big-endian, modulo the group order. A message is a side byte (`41`, `42`) and
  `xB + wM` (or `wN`) compressed. The key is SHA-256 over SHA-256 of the password, of `idA` and of `idB`, then both
  elements and the compressed result.
- **Confirmation.** Two keys come from that key by HKDF-SHA256 with no salt, info `coqui-pair joiner confirmation` and
  `coqui-pair responder confirmation`. Each MAC is HMAC-SHA256 under its side's key of the transcript: `coqui-pair pin`, both
  keys, the slot, both SPAKE2 messages each after one length byte, the byte `01` and the binding after four length bytes.
- **Order.** The responder takes an attempt at the PIN when the PAKE message arrives, sends its reply and MAC, and on the
  right confirmation keeps the joiner's key and only then sends done. The joiner verifies the responder's MAC before it
  sends its own.

### Against RFC 9382

The exchange is the `spake2` crate's, and that is not RFC 9382's profile. This was read side by side, not proved.

| RFC 9382 | Here | What that comes to |
| --- | --- | --- |
| M and N from a public seed | Other constants, from the seeds `M` and `N` by python-spake2's procedure | Rebuilt from those seeds and equal, each of order L. Nobody has a shortcut to their logs beyond what the hash gives |
| `w = MHF(pw) mod p`, the function a SHOULD | HKDF-SHA256, 48 bytes, modulo L | Wide enough to remove bias. No memory-hard function, which guessing online only does not call for |
| `K = h·x·(pB − w·N)`, by the cofactor | No multiplication by h | A small part of a message needs the sender to subtract the right `wM` anyway, so one guess per run stands; reasoned |
| Check group membership | Decompression only; low-order points are taken | Within the RFC's "member of G". The module refuses a second encoding, and the crate takes one |
| The transcript, with lengths and `w` | SHA-256 over the hash of the password, of each id, both elements and K | Fixed lengths, so unambiguous. The ids are the proved keys' |
| Confirmation both ways | HMAC each way, over both keys, both messages and the export | The responder confirms first, which one guess per run needs |

### What the JavaScript side leaves open

WebCrypto has no group operation, so the module computes SPAKE2 over Edwards25519 with `BigInt`, written to match the crate.

- **It is not constant-time.** Each scalar runs one fixed sequence of complete additions, with no branch on its bits except
  an array index, but `BigInt` itself promises nothing about time, and the password's scalar goes through it. RFC 9382 section
  7 says an implementation that leaks the scalar's length must not be used, and gives no form for avoiding it. Here `8L` is
  added to each scalar, which changes no result, so that no register stays the identity while the top bits are zero. That
  removes this one signal, as a test on one machine shows, and nothing else. Someone who can measure this page's work closely
  enough to learn the password's scalar could then test PINs offline. No such attack was attempted, and how close it needs to
  be is not known. A PIN lives for one attempt by default.
- **Its checks.** The `spake2` crate's own known answer (`tests/vectors/spake2.json`, copied and never regenerated) in both
  roles; points times scalars against Node's Ed25519 public keys; Rust's records of a right and a wrong PIN to the byte; and
  real runs against Rust in Node and in Chrome and Edge. Nothing here is a proof that it is correct on every input.
- **Stricter than the crate on what it reads.** It refuses a second encoding of a point, which `curve25519-dalek` takes; a
  message that passes one and not the other can only come from a party that is not following the protocol, and ends in a
  refusal or a failed confirmation either way.
- **It cannot erase.** A `BigInt` scalar and the PIN as a string stay in memory until the engine collects them. The key
  bytes it holds in arrays are wiped.

The module's responder offers only a PIN typed at the joiner, and refuses every other mode as `disabled`. Its desk counts
attempts and time; pending exchanges and per-source limits, which `PairingDesk` has in Rust, are the host's there.

## Bounds and refusal

There is nothing to negotiate, so nothing to downgrade: no version field, no cipher list, no message type. A
message is refused by its length before anything else. Errors never quote what the peer sent. A failed handshake
drops what it had queued and stays failed.

The crate's `FramedStream` refuses a frame by its declared length before reading it, at `MAX_HANDSHAKE_MESSAGE`
for the handshake, where `coqui_peer::drive_stream` would take up to 1 MiB. Its limit holds in both directions, a setting
with nothing above it but the length field's 2^32 - 1. A read timeout set on it bounds a whole frame, so a peer sending one
byte per timeout cannot outlast it.

## Erasure

Forward secrecy holds only if the ephemeral keys, `ck` and the session keys are erased. What the implementations
actually do:

- **Rust.** Ephemeral and long-term keys, every `ck`, the HKDF output, the export secret and PEM text are held on
  the heap in place and zeroed when dropped, and `tests/erasure.rs` scans every freed block for them. Copies a move
  leaves on the stack, and the working state of `x25519-dalek`, `hkdf`, `sha2` and `aes-gcm` on the stack, are not
  erased. The `spake2` crate holds the PIN's bytes and both of its scalars in memory it does not zero.
- **JavaScript.** Key bytes are wiped where the module holds them (`ck`, HKDF's outputs, a DH output), and every key
  after that is a non-extractable `CryptoKey` it cannot wipe. Noise's HKDF needs each chaining key as bytes, so those
  exist in JavaScript memory for the handshake. It drops its reference to the ephemeral key when the handshake ends,
  and `session.destroy()` drops the session's keys; when the memory is cleared is up to the engine's garbage
  collector.

## Not in this protocol

- **Invitation, device flow or a shown PIN in JavaScript.** Rust has all three through `coqui-peer`; the module has a typed
  PIN, and only that.
- **Hiding sizes.** Section 13 recommends padding; there is none, and a relay sees each record's length.
- **Hiding the responder.** Section 7.8, property 1. A responder that must not be identified by probes needs
  something in front of it.
- **Limiting pre-authentication work.** Each first message costs a responder an ephemeral key and two DH
  operations, and costs the sender nothing; a third message costs one more. The protocol has no cookie or puzzle, so
  bounding this is the host's: admission by address, connections at once, a deadline on the handshake.
- **Revocation of a running session.** Trust is read at each handshake. A host that removes a peer closes that
  peer's open connections itself.
- **Key-compromise resistance after the fact.** Whoever later learns a static private key can impersonate that peer
  from then on, and cannot read recorded sessions, whose keys came through `ee` as well.
- **Keeping a page's key from its own origin, or from its profile.** A non-extractable key cannot be copied out by a
  script, but any script in the origin can use it, anyone who can read the browser profile can take it, and
  IndexedDB's contents can be cleared by the browser or the user.
