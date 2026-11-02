# @boriken/coqui-peer-noise

The Noise method of [coqui-peer](https://github.com/Boriken-Dev/coqui-peer), in JavaScript: two peers run
`Noise_XX_25519_AESGCM_SHA256`, prove their X25519 keys to each other and end up with an encrypted session, with no
dependency and a private key that cannot leave WebCrypto. It interoperates with the
[Rust crate](https://github.com/Boriken-Dev/coqui-peer-noise) in both roles, and works behind a TLS-terminating reverse
proxy, because it uses nothing of the connection beneath it. A proxy that also serves the page can replace this module or use
its key, so a hosted page gets no protection from that proxy; an extension, a packaged app, or a page whose code and pinned id
come from elsewhere does.

One independent review, by another AI agent (neither third-party nor formal). `AGENTS.md` here is the API, and
[PROTOCOL.md](https://github.com/Boriken-Dev/coqui-peer-noise/blob/main/PROTOCOL.md) the wire and what a relay can and
cannot do.

```js
import {createInitiator, loadOrCreateIdentity} from '@boriken/coqui-peer-noise';

const identity = await loadOrCreateIdentity('my.application.peer');
const initiator = await createInitiator(identity, expectedPeerId);
socket.send(await initiator.hello());
const {reply, session} = await initiator.answer(await nextMessage());
socket.send(reply);

socket.send(await session.seal('every later message goes through the session'));
socket.send(await session.close());  // the last record; a stream cut before it is reported
```

A stranger's key is paired by a PIN a person types, sealed in a session that carries nothing else:
`createPairingInitiator`, `createPairingResponder` and `createPairingDesk`, the same bytes as Rust. The arithmetic behind it
is `BigInt` and not constant-time; `AGENTS.md` and `PROTOCOL.md` say what that leaves open.

`npm test` runs the tests, including the Rust examples in both roles and a real browser, which skip with
a message where cargo or a browser is absent.

MPL-2.0.
