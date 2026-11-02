/**
 * The Noise method of coqui-peer: Noise_XX_25519_AESGCM_SHA256 over `crypto.subtle`, ending in an
 * encrypted session. Dependency-free; a browser needs a secure context and X25519 in WebCrypto.
 * The wire format is PROTOCOL.md, and only `session` records are tied to the proven peers.
 */
export const PROFILE = 'dev.boriken.coqui.peer-noise/v1';
export const METHOD = 'noise';
export const PROTOCOL_NAME = 'Noise_XX_25519_AESGCM_SHA256';
// What one key may carry by default, before it changes: 2^38, against the 2^38.5 bytes of RFC 8446
// section 5.5's 2^24.5 full-size AES-GCM records. Each Noise message counts its length and 32.
export const DEFAULT_KEY_LIMIT = 2 ** 38;

const DHLEN = 32;
const TAGLEN = 16;
const HASHLEN = 32;
const FIRST_LEN = DHLEN;
const SECOND_LEN = DHLEN + (DHLEN + TAGLEN) + TAGLEN;
const THIRD_LEN = (DHLEN + TAGLEN) + TAGLEN;
// Section 5.1 of the Noise specification reserves this nonce: no message uses it, and REKEY does.
const RESERVED_NONCE = 0xffffffffffffffffn;
const INNER_DATA = 1;
const INNER_CLOSE = 2;
const INNER_KEY_CHANGE = 3;
const INNER_PART = 4;
// Section 3 of the Noise specification: no message is longer.
const MAX_NOISE_MESSAGE = 65535;
const MAX_CONTENT = MAX_NOISE_MESSAGE - TAGLEN - 1;
// A Noise message with a type and no contents. It stays possible at the limit.
const BARE_MESSAGE = 1 + TAGLEN;
const MESSAGE_OVERHEAD = 32;
const LENGTH_FIELD = 2;
const MAX_EXPORT = 8160;
// RFC 8410's forms of an id-X25519 key are these prefixes and the 32 key bytes, so comparing them
// leaves no ASN.1 for two parsers to read differently.
const SPKI_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]);
const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);
const SPKI_LEN = SPKI_PREFIX.length + DHLEN;
const PKCS8_LEN = PKCS8_PREFIX.length + DHLEN;
const PEER_ID = /^sha256:[a-f0-9]{64}$/;
const X25519 = {name: 'X25519'};
const HMAC = {name: 'HMAC', hash: 'SHA-256'};
const encoder = new TextEncoder();
const INVALID = 'Invalid peer message';

function subtle() {
  if (!globalThis.crypto?.subtle || !globalThis.crypto.getRandomValues) {
    throw new Error('Secure-context WebCrypto is required');
  }
  return globalThis.crypto.subtle;
}

function b64(bytes) {
  let text = '';
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function un64(text) {
  return Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/')), char => char.charCodeAt(0));
}

function concat(...parts) {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function field(bytes) {
  const output = new Uint8Array(4 + bytes.length);
  new DataView(output.buffer).setUint32(0, bytes.length, false);
  output.set(bytes, 4);
  return output;
}

function spkiOf(publicKey) {
  return concat(SPKI_PREFIX, publicKey);
}

function hasPrefix(bytes, prefix, length) {
  return bytes.length === length && prefix.every((byte, index) => bytes[index] === byte);
}

async function sha256(bytes) {
  return new Uint8Array(await subtle().digest('SHA-256', bytes));
}

async function peerIdOf(publicKey) {
  const digest = await sha256(spkiOf(publicKey));
  return 'sha256:' + [...digest].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

/** A copy taken now: the caller may reuse its buffer before the record is made. */
function bytesOf(input) {
  if (typeof input === 'string') return encoder.encode(input);
  return binaryOf(input);
}

function binaryOf(input) {
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength).slice();
  }
  if (input instanceof ArrayBuffer) return new Uint8Array(input).slice();
  throw new TypeError('Expected bytes');
}

/**
 * Whether `key` is the one encoding of a value. RFC 7748 section 5 has X25519 mask the top bit and
 * reduce modulo p, so without this a peer could present one key under several encodings, and ids.
 */
function isCanonical(key) {
  const atOrAboveP = key[31] === 0x7f && key[0] >= 0xed && key.subarray(1, 31).every(byte => byte === 0xff);
  return key[31] < 0x80 && !atOrAboveP;
}

function publicKeyOf(bytes) {
  if (bytes.length !== DHLEN || !isCanonical(bytes)) throw new Error(INVALID);
  return bytes;
}

/**
 * X25519, refusing a small-order peer key, which section 12.1 of the Noise specification allows.
 * Without it a peer could prove a static key it holds no private key for.
 */
async function dh(privateKey, peer) {
  let shared;
  try {
    const key = await subtle().importKey('raw', peer, X25519, false, []);
    shared = new Uint8Array(await subtle().deriveBits({name: 'X25519', public: key}, privateKey, 256));
  } catch {
    throw new Error(INVALID);
  }
  if (shared.every(byte => byte === 0)) throw new Error(INVALID);
  return shared;
}

async function hmac(key, data) {
  const imported = await subtle().importKey('raw', key, HMAC, false, ['sign']);
  return new Uint8Array(await subtle().sign('HMAC', imported, data));
}

/** Section 4.3's HKDF. A third output is what the SymmetricState's Split leaves for exports. */
async function noiseHkdf(chainingKey, input, outputs) {
  const temp = await hmac(chainingKey, input);
  const results = [];
  let previous = new Uint8Array();
  for (let index = 1; index <= outputs; index += 1) {
    const data = concat(previous, Uint8Array.of(index));
    previous = await hmac(temp, data);
    data.fill(0);
    results.push(previous);
  }
  temp.fill(0);
  return results;
}

/** Section 12.4: 32 zero bits, then the nonce big-endian. */
function ivOf(n) {
  const iv = new Uint8Array(12);
  new DataView(iv.buffer).setBigUint64(4, n, false);
  return iv;
}

function aesKey(bytes) {
  return subtle().importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/** A CipherState holding a key. `n` is a test's way to start near the end of the nonces. */
async function newCipher(bytes, n = 0n) {
  let key = await aesKey(bytes);
  let nonce = n;
  const operate = (operation, iv, ad, input) => subtle()[operation](
    {name: 'AES-GCM', iv, additionalData: ad, tagLength: 128}, key, input,
  );
  return {
    get remaining() { return RESERVED_NONCE - nonce; },
    /** Refuses once the nonces are used up, which section 5 says ends the session. */
    async encrypt(ad, plaintext) {
      if (nonce === RESERVED_NONCE) throw new Error('This direction used up its nonces');
      const out = new Uint8Array(await operate('encrypt', ivOf(nonce), ad, plaintext));
      nonce += 1n;
      return out;
    },
    async decrypt(ad, ciphertext) {
      if (nonce === RESERVED_NONCE) throw new Error('This direction used up its nonces');
      const out = new Uint8Array(await operate('decrypt', ivOf(nonce), ad, ciphertext));
      nonce += 1n;
      return out;
    },
    /** Section 4.2's REKEY: the nonce carries on, as section 11.3 says. */
    async rekey() {
      const next = new Uint8Array(await operate('encrypt', ivOf(RESERVED_NONCE), new Uint8Array(), new Uint8Array(32)));
      key = await aesKey(next.subarray(0, 32));
      next.fill(0);
    },
    drop() { key = null; },
  };
}

/** The SymmetricState: InitializeSymmetric, then MixHash of the prologue. */
async function newSymmetric(prologue) {
  // The name is shorter than HASHLEN, so section 5.2 pads it rather than hashing it.
  const start = new Uint8Array(HASHLEN);
  start.set(encoder.encode(PROTOCOL_NAME));
  const state = {
    h: start.slice(),
    ck: start,
    cipher: null,
    async mixHash(data) {
      state.h = await sha256(concat(state.h, data));
    },
    async mixKey(input) {
      const [ck, key] = await noiseHkdf(state.ck, input, 2);
      state.ck.fill(0);
      state.ck = ck;
      state.cipher = await newCipher(key);
      key.fill(0);
    },
    async encryptAndHash(plaintext) {
      const out = state.cipher ? await state.cipher.encrypt(state.h, plaintext) : plaintext.slice();
      await state.mixHash(out);
      return out;
    },
    async decryptAndHash(ciphertext) {
      let out;
      if (state.cipher) {
        try {
          out = await state.cipher.decrypt(state.h, ciphertext);
        } catch {
          throw new Error('A handshake message does not decrypt');
        }
      } else {
        out = ciphertext.slice();
      }
      await state.mixHash(ciphertext);
      return out;
    },
    wipe() {
      state.ck.fill(0);
      state.cipher?.drop();
      state.cipher = null;
    },
  };
  await state.mixHash(prologue);
  return state;
}

/** The HandshakeState of pattern XX. `local` and `ephemeral` hold a private key and public bytes. */
async function newHandshake(initiator, prologue, local, ephemeral) {
  const symmetric = await newSymmetric(prologue);
  let next = 0;
  let remoteEphemeral = null;
  let remoteStatic = null;
  const mixDh = async (privateKey, peer) => {
    const shared = await dh(privateKey, peer);
    await symmetric.mixKey(shared);
    shared.fill(0);
  };
  const writeEphemeral = async parts => {
    parts.push(ephemeral.public);
    await symmetric.mixHash(ephemeral.public);
  };
  const readEphemeral = async message => {
    if (message.length < DHLEN) throw new Error(INVALID);
    remoteEphemeral = publicKeyOf(message.slice(0, DHLEN));
    await symmetric.mixHash(remoteEphemeral);
    return message.subarray(DHLEN);
  };
  const readStatic = async message => {
    if (message.length < DHLEN + TAGLEN) throw new Error(INVALID);
    remoteStatic = publicKeyOf(await symmetric.decryptAndHash(message.subarray(0, DHLEN + TAGLEN)));
    return message.subarray(DHLEN + TAGLEN);
  };
  return {
    get remoteStatic() { return remoteStatic; },
    /** WriteMessage. */
    async writeMessage(payload) {
      const parts = [];
      if (next === 0 && initiator) {
        await writeEphemeral(parts);
      } else if (next === 1 && !initiator) {
        await writeEphemeral(parts);
        await mixDh(ephemeral.privateKey, remoteEphemeral);
        parts.push(await symmetric.encryptAndHash(local.public));
        await mixDh(local.privateKey, remoteEphemeral);
      } else if (next === 2 && initiator) {
        parts.push(await symmetric.encryptAndHash(local.public));
        await mixDh(local.privateKey, remoteEphemeral);
      } else {
        throw new Error('Unexpected handshake step');
      }
      parts.push(await symmetric.encryptAndHash(payload));
      next += 1;
      return concat(...parts);
    },
    /** ReadMessage. A static key read on the way is proved once this returns: the tag depends on it. */
    async readMessage(message) {
      let rest;
      if (next === 0 && !initiator) {
        rest = await readEphemeral(message);
      } else if (next === 1 && initiator) {
        rest = await readEphemeral(message);
        await mixDh(ephemeral.privateKey, remoteEphemeral);
        rest = await readStatic(rest);
        await mixDh(ephemeral.privateKey, remoteStatic);
      } else if (next === 2 && !initiator) {
        rest = await readStatic(message);
        await mixDh(ephemeral.privateKey, remoteStatic);
      } else {
        throw new Error('Unexpected handshake step');
      }
      const payload = await symmetric.decryptAndHash(rest);
      next += 1;
      return payload;
    },
    /** Split, and the third output of its HKDF as the secret of exports. */
    async split() {
      if (next !== 3) throw new Error('Unexpected handshake step');
      const [k1, k2, exporter] = await noiseHkdf(symmetric.ck, new Uint8Array(), 3);
      const transport = {
        h: symmetric.h,
        initiatorToResponder: await newCipher(k1),
        responderToInitiator: await newCipher(k2),
        exporter,
      };
      k1.fill(0);
      k2.fill(0);
      symmetric.wipe();
      ephemeral = null;
      return transport;
    },
    wipe() {
      symmetric.wipe();
      ephemeral = null;
    },
  };
}

/** The session both ends hold after the handshake: an id, and keys only they can derive. */
async function createSession(transport, initiator, settings) {
  const {h: id, initiatorToResponder, responderToInitiator} = transport;
  const sendingCipher = initiator ? initiatorToResponder : responderToInitiator;
  const receivingCipher = initiator ? responderToInitiator : initiatorToResponder;
  let exporter = await subtle().importKey('raw', transport.exporter, 'HKDF', false, ['deriveBits']);
  transport.exporter.fill(0);
  const status = {failed: false, destroyed: false};
  let closed = false;
  let peerClosed = false;
  let sendCharged = 0;
  let receiveCharged = 0;
  // Calls take their nonce, and resolve, in call order.
  const queues = {send: Promise.resolve(), receive: Promise.resolve()};
  const inOrder = (name, work) => {
    const run = queues[name].then(() => {
      if (status.destroyed || status.failed) throw new Error('The session is over');
      return work();
    });
    queues[name] = run.catch(() => {});
    return run;
  };
  const fail = message => {
    status.failed = true;
    return new Error(message);
  };
  const limitError = () => new Error('This key reached its limit');
  const cost = length => length + MESSAGE_OVERHEAD;

  const frame = (kind, contents) => sendingCipher.encrypt(new Uint8Array(), concat(Uint8Array.of(kind), contents))
    .then(sealed => {
      const out = new Uint8Array(LENGTH_FIELD + sealed.length);
      new DataView(out.buffer).setUint16(0, sealed.length, false);
      out.set(sealed, LENGTH_FIELD);
      return out;
    })
    .catch(() => { throw fail('The session is over'); });

  const admit = length => {
    const parts = Math.max(Math.ceil(length / MAX_CONTENT), 1);
    const largest = cost(Math.min(length, MAX_CONTENT) + BARE_MESSAGE);
    const total = cost(length + BARE_MESSAGE) + cost(BARE_MESSAGE) * (parts - 1);
    if (largest > settings.keyLimit || (!settings.rekey && sendCharged + total > settings.keyLimit)) {
      throw limitError();
    }
    // A key change may come before each part.
    if (sendingCipher.remaining < BigInt(2 * parts)) {
      status.failed = true;
      throw limitError();
    }
    return parts;
  };

  return Object.freeze({
    id,
    /** One message (bytes or text) as one record, of any length; send records whole, in call order. */
    seal(message) {
      let bytes;
      try {
        bytes = bytesOf(message);
      } catch (error) {
        return Promise.reject(error);
      }
      if (closed) return Promise.reject(new Error('This side already closed its direction'));
      return inOrder('send', async () => {
        const parts = admit(bytes.length);
        const pieces = [];
        for (let part = 0; part < parts; part += 1) {
          const chunk = bytes.subarray(part * MAX_CONTENT, (part + 1) * MAX_CONTENT);
          const price = cost(chunk.length + BARE_MESSAGE);
          if (settings.rekey && sendCharged + price > settings.keyLimit) {
            pieces.push(await frame(INNER_KEY_CHANGE, new Uint8Array()));
            await sendingCipher.rekey();
            sendCharged = 0;
          }
          sendCharged += price;
          pieces.push(await frame(part + 1 === parts ? INNER_DATA : INNER_PART, chunk));
        }
        return concat(...pieces);
      });
    },
    /** The record ending this direction, to send last. A peer that never gets it reports truncation. */
    close() {
      if (closed) return Promise.reject(new Error('This side already closed its direction'));
      closed = true;
      return inOrder('send', () => frame(INNER_CLOSE, new Uint8Array()));
    },
    /** The message of the next record, or null for the peer's close. A bad record ends the session. */
    open(record) {
      let bytes;
      try {
        bytes = binaryOf(record);
      } catch (error) {
        return Promise.reject(error);
      }
      return inOrder('receive', async () => {
        if (peerClosed) throw fail('The session is over');
        const refused = () => fail('A session record does not open');
        const message = [];
        let rest = bytes;
        let first = true;
        let afterKeyChange = false;
        for (;;) {
          if (rest.length < LENGTH_FIELD) throw refused();
          const length = new DataView(rest.buffer, rest.byteOffset, LENGTH_FIELD).getUint16(0, false);
          if (length < BARE_MESSAGE || rest.length < LENGTH_FIELD + length) throw refused();
          const sealed = rest.subarray(LENGTH_FIELD, LENGTH_FIELD + length);
          rest = rest.subarray(LENGTH_FIELD + length);
          if (length > BARE_MESSAGE) {
            if (receiveCharged + cost(length) > settings.keyLimit) {
              status.failed = true;
              throw limitError();
            }
            receiveCharged += cost(length);
          }
          let inner;
          try {
            inner = await receivingCipher.decrypt(new Uint8Array(), sealed);
          } catch {
            throw refused();
          }
          if (inner.length < 1) throw refused();
          const kind = inner[0];
          if (kind === INNER_DATA && rest.length === 0) {
            message.push(inner.subarray(1));
            return concat(...message);
          }
          if (kind === INNER_CLOSE && first && inner.length === 1 && rest.length === 0) {
            peerClosed = true;
            return null;
          }
          if (kind === INNER_KEY_CHANGE && inner.length === 1 && rest.length > 0 && !afterKeyChange) {
            await receivingCipher.rekey();
            receiveCharged = 0;
            afterKeyChange = true;
          } else if (kind === INNER_PART && length === MAX_NOISE_MESSAGE && rest.length > 0) {
            message.push(inner.subarray(1));
            afterKeyChange = false;
          } else {
            throw refused();
          }
          first = false;
        }
      });
    },
    /** Call when the transport ended; throws when the peer's close record never came. */
    verifyEnd() {
      if (status.destroyed || status.failed) throw new Error('The session is over');
      if (!peerClosed) throw new Error('The stream was truncated: it ended before the peer closed it');
    },
    /** `length` bytes only this session's two peers can derive; another label or length is unrelated. */
    async export(label, length) {
      if (status.destroyed) throw new Error('The session is over');
      if (!Number.isInteger(length) || length < 0 || length > MAX_EXPORT) {
        throw new Error('An export is at most 8160 bytes');
      }
      if (length === 0) return new Uint8Array();
      const lengthField = new Uint8Array(4);
      new DataView(lengthField.buffer).setUint32(0, length, false);
      const info = concat(
        field(encoder.encode(`${PROFILE}/export`)), field(id), field(encoder.encode(label)), lengthField,
      );
      return new Uint8Array(await subtle().deriveBits(
        {name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info}, exporter, length * 8,
      ));
    },
    /** Drops every key this session holds; each later call fails. WebCrypto then frees them. */
    destroy() {
      status.destroyed = true;
      sendingCipher.drop();
      receivingCipher.drop();
      exporter = null;
    },
  });
}

function options({keyLimit = DEFAULT_KEY_LIMIT, rekey = true, binding = new Uint8Array(), ephemeral} = {}) {
  if (!Number.isSafeInteger(keyLimit) || keyLimit < 0) throw new Error('keyLimit must be a whole number');
  if (typeof rekey !== 'boolean') throw new TypeError('rekey must be true or false');
  // Anything else would turn into another value here, or none, and bind to nothing.
  if (!(binding instanceof Uint8Array)) throw new TypeError('binding must be a Uint8Array or Buffer');
  return {
    keyLimit,
    rekey,
    binding: binding.slice(),
    ephemeral: ephemeral ?? (() => subtle().generateKey(X25519, false, ['deriveBits'])),
  };
}

function prologueOf(settings) {
  return concat(field(encoder.encode(PROFILE)), field(settings.binding));
}

async function newEphemeral(settings) {
  const pair = await settings.ephemeral();
  return {
    privateKey: pair.privateKey,
    public: new Uint8Array(await subtle().exportKey('raw', pair.publicKey)),
  };
}

function isOwnKey(handshake, local) {
  return handshake.remoteStatic.every((byte, index) => byte === local.public[index]);
}

async function checkIdentity(identity) {
  const key = identity?.privateKey;
  if (typeof identity?.publicKey !== 'string' || key?.type !== 'private' || key.extractable !== false ||
      key.algorithm?.name !== 'X25519' || !key.usages?.includes('deriveBits') ||
      !PEER_ID.test(identity.peerId ?? '')) {
    throw new Error('A non-extractable X25519 identity is required');
  }
  let spki;
  try {
    spki = un64(identity.publicKey);
  } catch {
    throw new Error('A non-extractable X25519 identity is required');
  }
  if (!hasPrefix(spki, SPKI_PREFIX, SPKI_LEN) || !isCanonical(spki.subarray(SPKI_PREFIX.length)) ||
      await peerIdOf(spki.subarray(SPKI_PREFIX.length)) !== identity.peerId) {
    throw new Error('A non-extractable X25519 identity is required');
  }
  return {privateKey: key, public: spki.slice(SPKI_PREFIX.length)};
}

function identityOf(publicKey, privateKey, id) {
  return Object.freeze({method: METHOD, peerId: id, publicKey: b64(spkiOf(publicKey)), privateKey});
}

/** A new identity whose private key cannot leave WebCrypto. */
export async function generateIdentity() {
  const pair = await subtle().generateKey(X25519, false, ['deriveBits']);
  const publicKey = new Uint8Array(await subtle().exportKey('raw', pair.publicKey));
  return identityOf(publicKey, pair.privateKey, await peerIdOf(publicKey));
}

/** The identity of an RFC 8410 PKCS#8 DER X25519 key, for a server; its private key is non-extractable. */
export async function importIdentity(pkcs8) {
  const der = binaryOf(pkcs8);
  if (!hasPrefix(der, PKCS8_PREFIX, PKCS8_LEN)) throw new Error('Not an X25519 PKCS#8 private key');
  const usable = await subtle().importKey('pkcs8', der, X25519, true, ['deriveBits']);
  const {x} = await subtle().exportKey('jwk', usable);
  const publicKey = un64(x);
  const privateKey = await subtle().importKey('pkcs8', der, X25519, false, ['deriveBits']);
  der.fill(0);
  return identityOf(publicKey, privateKey, await peerIdOf(publicKey));
}

/**
 * Starts a handshake as the side that dials, trusting only `expectedPeerId`.
 * Options: `keyLimit`; `rekey`; `binding`, bytes of an outer channel both ends really read (a TLS
 * exporter where each ends that TLS itself, never through a reverse proxy); `ephemeral` replaces the
 * generator, for test vectors only.
 */
export async function createInitiator(identity, expectedPeerId, config) {
  const local = await checkIdentity(identity);
  if (!PEER_ID.test(expectedPeerId ?? '')) throw new Error('A pinned responder id is required');
  const settings = options(config);
  const handshake = await newHandshake(true, prologueOf(settings), local, await newEphemeral(settings));
  let state = 'start';
  return Object.freeze({
    /** The first message. */
    async hello() {
      if (state !== 'start') throw new Error('Unexpected hello');
      state = 'second';
      return handshake.writeMessage(new Uint8Array());
    },
    /** Takes the second message, and gives the third and the session. */
    async answer(raw) {
      if (state !== 'second') throw new Error('Unexpected challenge');
      state = 'failed';
      try {
        const message = binaryOf(raw);
        if (message.length !== SECOND_LEN) throw new Error(INVALID);
        await handshake.readMessage(message);
        if (isOwnKey(handshake, local)) throw new Error(INVALID);
        if (await peerIdOf(handshake.remoteStatic) !== expectedPeerId) {
          throw new Error('Responder is not pinned');
        }
        const reply = await handshake.writeMessage(new Uint8Array());
        const session = await createSession(await handshake.split(), true, settings);
        state = 'done';
        return {reply, peerId: expectedPeerId, session};
      } catch (error) {
        handshake.wipe();
        throw error;
      }
    },
  });
}

/**
 * Starts a handshake as the side that accepts. `allowClient(peerId)` runs after the peer proved its
 * key and must resolve to exactly `true` to admit it. Other options as for `createInitiator`.
 */
export async function createResponder(identity, {allowClient, ...config} = {}) {
  const local = await checkIdentity(identity);
  if (typeof allowClient !== 'function') throw new Error('An explicit trust decision is required');
  const settings = options(config);
  let state = 'first';
  let handshake;
  return Object.freeze({
    /** Takes the first message, and gives the second. */
    async challenge(raw) {
      if (state !== 'first') throw new Error('Unexpected hello');
      state = 'failed';
      const message = binaryOf(raw);
      if (message.length !== FIRST_LEN) throw new Error(INVALID);
      handshake = await newHandshake(false, prologueOf(settings), local, await newEphemeral(settings));
      try {
        await handshake.readMessage(message);
        const reply = await handshake.writeMessage(new Uint8Array());
        state = 'third';
        return reply;
      } catch (error) {
        handshake.wipe();
        throw error;
      }
    },
    /** Takes the third message, and gives the proved peer and the session. */
    async accept(raw) {
      if (state !== 'third') throw new Error('Unexpected client proof');
      state = 'failed';
      try {
        const message = binaryOf(raw);
        if (message.length !== THIRD_LEN) throw new Error(INVALID);
        await handshake.readMessage(message);
        if (isOwnKey(handshake, local)) throw new Error(INVALID);
        const id = await peerIdOf(handshake.remoteStatic);
        if (await allowClient(id) !== true) throw new Error('Client is not paired');
        const session = await createSession(await handshake.split(), false, settings);
        state = 'done';
        return {peerId: id, session};
      } catch (error) {
        handshake.wipe();
        throw error;
      }
    },
  });
}

function requestResult(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/**
 * The identity kept in the origin-local IndexedDB database `name`, created when absent. The private
 * key is stored as a non-extractable CryptoKey. Each application names its own database.
 */
export async function loadOrCreateIdentity(name) {
  if (typeof name !== 'string' || !name) throw new Error('An identity store name is required');
  if (!globalThis.indexedDB) throw new Error('IndexedDB storage is unavailable');
  const opening = indexedDB.open(name, 1);
  opening.onupgradeneeded = () => opening.result.createObjectStore('keys');
  const db = await requestResult(opening);
  const read = () => requestResult(db.transaction('keys').objectStore('keys').get('default'));
  try {
    let stored = await read();
    if (!stored) {
      const fresh = await generateIdentity();
      // Another tab may get there first: `add` then fails, and every tab uses the one stored.
      await requestResult(db.transaction('keys', 'readwrite').objectStore('keys').add(fresh, 'default')).catch(() => {});
      stored = await read();
    }
    await checkIdentity(stored);
    return stored;
  } finally {
    db.close();
  }
}

export const profile = Object.freeze({id: PROFILE, protocol: PROTOCOL_NAME, method: METHOD});

/**
 * Not API, and it may change at any commit: the layer beneath the method, whose handshake takes
 * payloads the method never sends, which is what the published Noise test vectors need.
 */
export const __testing = Object.freeze({newHandshake, newCipher, createSession, isCanonical});
