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

/**
 * Whether this runtime has what the method needs: X25519, AES-GCM, HKDF, HMAC and SHA-256 in
 * `crypto.subtle`. It runs each once and makes no connection; a failure of any is `false`.
 */
export async function supported() {
  try {
    const api = subtle();
    const pair = await api.generateKey(X25519, false, ['deriveBits']);
    const theirs = await api.generateKey(X25519, false, ['deriveBits']);
    const shared = await api.deriveBits({name: 'X25519', public: theirs.publicKey}, pair.privateKey, 256);
    const key = new Uint8Array(shared);
    const aes = await api.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt']);
    const iv = new Uint8Array(12);
    const sealed = await api.encrypt({name: 'AES-GCM', iv, additionalData: new Uint8Array(), tagLength: 128}, aes, key);
    const opened = new Uint8Array(await api.decrypt({name: 'AES-GCM', iv, additionalData: new Uint8Array(), tagLength: 128}, aes, sealed));
    const hkdf = await api.importKey('raw', key, 'HKDF', false, ['deriveBits']);
    const okm = await api.deriveBits({name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info: new Uint8Array()}, hkdf, 256);
    const mac = await api.importKey('raw', key, HMAC, false, ['sign']);
    const tag = await api.sign('HMAC', mac, key);
    const digest = await api.digest('SHA-256', key);
    return key.length === 32 && sealed.byteLength === 48 && opened.length === 32 &&
      okm.byteLength === 32 && tag.byteLength === 32 && digest.byteLength === 32;
  } catch {
    return false;
  }
}

/**
 * The length of the record that carries a message of `messageLength` bytes: 19 more up to 65518
 * bytes, and 19 more for each further 65518. A change of key, which a sender makes only at its key
 * limit, adds 19 to the record that holds it.
 */
export function recordLength(messageLength) {
  if (!Number.isSafeInteger(messageLength) || messageLength < 0) {
    throw new RangeError('A message length is a whole number, 0 or more');
  }
  const parts = Math.max(Math.ceil(messageLength / MAX_CONTENT), 1);
  return messageLength + parts * (LENGTH_FIELD + BARE_MESSAGE);
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
 * reduce modulo p, so without this one value would have several encodings, and so ids. It does not make
 * one private key one id: PROTOCOL.md says what a point of order 8 does.
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
  // A peer may run to the default on a key, whatever this side's own sending limit.
  const receiveLimit = Math.max(settings.keyLimit, DEFAULT_KEY_LIMIT);
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
            if (receiveCharged + cost(length) > receiveLimit) {
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
          // A last part is empty only when it is the whole message.
          if (kind === INNER_DATA && rest.length === 0 && (inner.length > 1 || message.length === 0)) {
            message.push(inner.subarray(1));
            return concat(...message);
          }
          if (kind === INNER_CLOSE && first && inner.length === 1 && rest.length === 0) {
            peerClosed = true;
            return null;
          }
          if (kind === INNER_KEY_CHANGE && inner.length === 1 && !afterKeyChange) {
            await receivingCipher.rekey();
            receiveCharged = 0;
            afterKeyChange = true;
          } else if (kind === INNER_PART && length === MAX_NOISE_MESSAGE) {
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

/** The settings, read now: each caller takes them before its first `await`, so it may reuse its buffers on return. */
function options({keyLimit = DEFAULT_KEY_LIMIT, rekey = true, binding = new Uint8Array(), ephemeral} = {}) {
  if (!Number.isSafeInteger(keyLimit) || keyLimit < 0) throw new Error('keyLimit must be a whole number');
  if (typeof rekey !== 'boolean') throw new TypeError('rekey must be true or false');
  // Anything else would turn into another value here, or none, and bind to nothing.
  if (!(binding instanceof Uint8Array)) throw new TypeError('binding must be a Uint8Array or Buffer');
  return {
    keyLimit,
    rekey,
    // `Buffer.slice` is a view of the host's memory, which it may wipe; this is a copy.
    binding: Uint8Array.from(binding),
    ephemeral: ephemeral ?? (() => subtle().generateKey(X25519, false, ['deriveBits'])),
    ephemeralReplaced: ephemeral !== undefined,
  };
}

/** One setting looser than its default, as Rust's `Weakening`: reported, never refused. */
function weakening(setting, value, strict) {
  return Object.freeze({setting, value: String(value), strict: String(strict)});
}

function weakenedSettings(settings) {
  const found = [];
  if (settings.keyLimit > DEFAULT_KEY_LIMIT) found.push(weakening('keyLimit', settings.keyLimit, DEFAULT_KEY_LIMIT));
  if (!settings.rekey) found.push(weakening('rekey', 'off', 'on'));
  if (settings.ephemeralReplaced) found.push(weakening('ephemeral', "caller's", "the engine's"));
  return found;
}

// What a run is for, second in the prologue, so a run for one fails against the other at its second
// message and a relay cannot pick which a peer gets.
const PURPOSE_ORDINARY = encoder.encode('ordinary');
const PURPOSE_PAIR = encoder.encode('pair');

function prologueOf(purpose, settings) {
  return concat(field(encoder.encode(PROFILE)), field(purpose), field(settings.binding));
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
 * The dialling side's state machine; `admit` decides on the proved id, and `finish` gives the result.
 * `looser` is what a caller adds to `weakened()`.
 */
async function dialling(local, purpose, settings, looser, admit, finish) {
  const handshake = await newHandshake(true, prologueOf(purpose, settings), local, await newEphemeral(settings));
  let state = 'start';
  return Object.freeze({
    /** The settings looser than their default: `[{setting, value, strict}]`. */
    weakened: () => [...weakenedSettings(settings), ...looser],
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
        const id = await peerIdOf(handshake.remoteStatic);
        await admit(id);
        const reply = await handshake.writeMessage(new Uint8Array());
        const remote = handshake.remoteStatic;
        const session = await createSession(await handshake.split(), true, settings);
        state = 'done';
        return {reply, peerId: id, ...await finish(session, remote)};
      } catch (error) {
        handshake.wipe();
        throw error;
      }
    },
  });
}

/** As `dialling`, for the accepting side. */
async function accepting(local, purpose, settings, looser, admit, finish) {
  let state = 'first';
  let handshake;
  return Object.freeze({
    /** The settings looser than their default: `[{setting, value, strict}]`. */
    weakened: () => [...weakenedSettings(settings), ...looser],
    /** Takes the first message, and gives the second. */
    async challenge(raw) {
      if (state !== 'first') throw new Error('Unexpected hello');
      state = 'failed';
      const message = binaryOf(raw);
      if (message.length !== FIRST_LEN) throw new Error(INVALID);
      handshake = await newHandshake(false, prologueOf(purpose, settings), local, await newEphemeral(settings));
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
        await admit(id);
        const remote = handshake.remoteStatic;
        const session = await createSession(await handshake.split(), false, settings);
        state = 'done';
        return {peerId: id, ...await finish(session, remote)};
      } catch (error) {
        handshake.wipe();
        throw error;
      }
    },
  });
}

/**
 * Starts a handshake as the side that dials, trusting only `expectedPeerId`.
 * Options: `keyLimit`; `rekey`; `binding`, bytes of an outer channel both ends really read (a TLS
 * exporter where each ends that TLS itself, never through a reverse proxy); `ephemeral` replaces the
 * generator, for test vectors only.
 */
export async function createInitiator(identity, expectedPeerId, config) {
  const settings = options(config);
  const local = await checkIdentity(identity);
  if (!PEER_ID.test(expectedPeerId ?? '')) throw new Error('A pinned responder id is required');
  return dialling(local, PURPOSE_ORDINARY, settings, [], async id => {
    if (id !== expectedPeerId) throw new Error('Responder is not pinned');
  }, async session => ({session}));
}

/**
 * Starts a handshake as the side that accepts. `allowClient(peerId)` runs after the peer proved its
 * key and must resolve to exactly `true` to admit it. Other options as for `createInitiator`.
 */
export async function createResponder(identity, {allowClient, ...config} = {}) {
  const settings = options(config);
  const local = await checkIdentity(identity);
  if (typeof allowClient !== 'function') throw new Error('An explicit trust decision is required');
  return accepting(local, PURPOSE_ORDINARY, settings, [], async id => {
    if (await allowClient(id) !== true) throw new Error('Client is not paired');
  }, async session => ({session}));
}

// Edwards25519, for the PIN exchange's SPAKE2. WebCrypto has no group operation, so this is BigInt
// arithmetic: it runs one fixed sequence of point operations per scalar, and BigInt itself promises
// nothing about time. PROTOCOL.md says what that leaves open.
const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const CURVE_D = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3n;
const SQRT_M1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0n;
const BASE_X = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51an;
const BASE_Y = 0x6666666666666666666666666666666666666666666666666666666666666658n;
// Any scalar of up to 256 bits, with LADDER_OFFSET added.
const SCALAR_BITS = 257;

const fe = value => {
  const reduced = value % P;
  return reduced < 0n ? reduced + P : reduced;
};

function powP(base, exponent) {
  let result = 1n;
  let square = fe(base);
  for (let rest = exponent; rest > 0n; rest >>= 1n) {
    if (rest & 1n) result = fe(result * square);
    square = fe(square * square);
  }
  return result;
}

// 8L is a multiple of the order of every element, so adding it changes no result, torsion included. A
// scalar below L then has one top bit, so no register stays the identity, whose zero coordinates make
// BigInt's work cheap, and the length RFC 9382 section 7 says must not show does not.
const LADDER_OFFSET = 8n * L;

const pointOf = (x, y) => ({x, y, z: 1n, t: fe(x * y)});
const IDENTITY = pointOf(0n, 1n);
const BASE = pointOf(BASE_X, BASE_Y);

/** RFC 8032's unified addition for a = -1, which is complete: it holds for every pair of points. */
function pointAdd(a, b) {
  const minus = fe((a.y - a.x) * (b.y - b.x));
  const plus = fe((a.y + a.x) * (b.y + b.x));
  const c = fe(2n * CURVE_D * a.t * b.t);
  const d = fe(2n * a.z * b.z);
  const e = plus - minus;
  const f = d - c;
  const g = d + c;
  const h = plus + minus;
  return {x: fe(e * f), y: fe(g * h), t: fe(e * h), z: fe(f * g)};
}

/** A Montgomery ladder: the same additions whatever the scalar's bits, which index the pair. */
function pointMul(point, scalar) {
  const offset = scalar + LADDER_OFFSET;
  const pair = [IDENTITY, point];
  for (let index = SCALAR_BITS - 1; index >= 0; index -= 1) {
    const bit = Number((offset >> BigInt(index)) & 1n);
    pair[1 - bit] = pointAdd(pair[0], pair[1]);
    pair[bit] = pointAdd(pair[bit], pair[bit]);
  }
  return pair[0];
}

function littleEndian(bytes) {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) value = (value << 8n) | BigInt(bytes[index]);
  return value;
}

function compress(point) {
  const inverse = powP(point.z, P - 2n);
  const x = fe(point.x * inverse);
  let y = fe(point.y * inverse);
  const out = new Uint8Array(DHLEN);
  for (let index = 0; index < DHLEN; index += 1) {
    out[index] = Number(y & 0xffn);
    y >>= 8n;
  }
  out[DHLEN - 1] |= Number(x & 1n) << 7;
  return out;
}

/** RFC 8032 section 5.1.3, with its one encoding per point: null for anything else. */
function decompress(bytes) {
  if (bytes.length !== DHLEN) return null;
  const sign = bytes[DHLEN - 1] >> 7;
  const copy = bytes.slice();
  copy[DHLEN - 1] &= 0x7f;
  const y = littleEndian(copy);
  if (y >= P) return null;
  const u = fe(y * y - 1n);
  const v = fe(CURVE_D * y * y + 1n);
  const v3 = fe(v * v * v);
  let x = fe(u * v3 * powP(u * v3 * v3 * v, (P - 5n) / 8n));
  const check = fe(v * x * x);
  if (check === fe(-u)) x = fe(x * SQRT_M1);
  else if (check !== u) return null;
  if (x === 0n && sign === 1) return null;
  if (Number(x & 1n) !== sign) x = fe(-x);
  return pointOf(x, y);
}

function hexBytes(text) {
  return Uint8Array.from(text.match(/../g), pair => parseInt(pair, 16));
}

// SPAKE2 as the `spake2` crate 0.4 has it, which coqui_peer::pair uses: its constants, its reduction of
// the password, its side bytes and its key. Each of these is that crate's and not a specification's.
const SPAKE_M = decompress(hexBytes('15cfd18e385952982b6a8f8c7854963b58e34388c8e6dae891db756481a02312'));
const SPAKE_N = decompress(hexBytes('f04f2e7eb734b2a8f8b472eaf9c3c632576ac64aea650b496a8a20ff00e583c3'));
const SIDE_A = 0x41;
const SIDE_B = 0x42;
const SPAKE_MESSAGE_LEN = 1 + DHLEN;
const OS_RANDOM = length => globalThis.crypto.getRandomValues(new Uint8Array(length));

async function hkdf(ikm, info, length) {
  const key = await subtle().importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle().deriveBits(
    {name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info}, key, length * 8,
  ));
}

async function passwordScalar(password) {
  const okm = await hkdf(password, encoder.encode('SPAKE2 pw'), 48);
  const value = littleEndian(okm.slice().reverse()) % L;
  okm.fill(0);
  return value;
}

/** `random` gives the 64 bytes of the blinding scalar. Returns the state and the message to send. */
async function spakeStart(joiner, password, idA, idB, random) {
  const draw = random(64);
  const scalar = littleEndian(draw) % L;
  draw.fill(0);
  return spakeStartWith(joiner, password, idA, idB, scalar);
}

async function spakeStartWith(joiner, password, idA, idB, scalar) {
  const pw = await passwordScalar(password);
  const element = compress(pointAdd(pointMul(BASE, scalar), pointMul(joiner ? SPAKE_M : SPAKE_N, pw)));
  return {
    state: {joiner, password, idA, idB, scalar, pw, element},
    message: concat(Uint8Array.of(joiner ? SIDE_A : SIDE_B), element),
  };
}

/** The shared key for the other side's message, or null when that message is not one. */
async function spakeFinish(state, other) {
  if (other.length !== SPAKE_MESSAGE_LEN || other[0] !== (state.joiner ? SIDE_B : SIDE_A)) return null;
  const received = other.subarray(1);
  const element = decompress(received);
  if (!element) return null;
  const unblind = pointMul(state.joiner ? SPAKE_N : SPAKE_M, (L - state.pw) % L);
  const key = compress(pointMul(pointAdd(element, unblind), state.scalar));
  const [first, second] = state.joiner ? [state.element, received] : [received, state.element];
  const transcript = concat(
    await sha256(state.password), await sha256(state.idA), await sha256(state.idB), first, second, key,
  );
  key.fill(0);
  const shared = await sha256(transcript);
  transcript.fill(0);
  return shared;
}

// coqui_peer::pair's messages, which the Rust side runs through coqui-peer: PROTOCOL.md's "Pairing".
const PAIR_VERSION = 1;
const PAIR_HELLO = 1;
const PAIR_READY = 2;
const PAIR_PAKE = 3;
const PAIR_REPLY = 4;
const PAIR_CONFIRM = 5;
const PAIR_DONE = 7;
const PAIR_REFUSED = 8;
const PAIR_MODE_PIN_TYPED = 1;
const PAIR_MODE_DEVICE = 3;
const PAIR_NO_SLOT = 0xff;
const PAIR_TAG_LEN = 32;
export const PAIR_EXPORT_LABEL = 'EXPORTER-coqui-pair';
const KEY_LABEL = 'PUBLIC KEY';
const REFUSALS = Object.freeze([null, 'wrong-code', 'expired', 'exhausted', 'throttled', 'denied', 'disabled']);
const refusalByte = name => REFUSALS.indexOf(name);
const EXPIRED = Symbol('expired');
const OUT_OF_PLACE = 'A pairing message is malformed or unexpected';
// How long a responder waits for a joiner's first message unless told otherwise, in milliseconds. A
// stranger who proved a key and says nothing holds a connection for this long.
export const DEFAULT_FIRST_MESSAGE_TIMEOUT = 60_000;
// setTimeout takes at most this, and fires at once above it.
const MAX_TIMER = 2 ** 31 - 1;
// The longest record of an exchange, as in Rust; this module's own messages are shorter.
export const MAX_PAIRING_RECORD = 350;

function refusal(name) {
  return Object.assign(new Error(`The pairing was refused: ${name}`), {refusal: name});
}

function short(bytes) {
  return concat(Uint8Array.of(bytes.length), bytes);
}

/** A KeyMaterial: the method, the label, then the bytes. */
function keyField(publicKey) {
  return concat(short(encoder.encode(METHOD)), short(encoder.encode(KEY_LABEL)), field(spkiOf(publicKey)));
}

/** A message's fields in order; every shortfall is the one refusal, and `end` refuses what is left over. */
function pairReader(message) {
  let rest = message;
  const take = count => {
    if (rest.length < count) throw new Error(OUT_OF_PLACE);
    const taken = rest.subarray(0, count);
    rest = rest.subarray(count);
    return taken;
  };
  const reader = {
    byte: () => take(1)[0],
    short: () => take(take(1)[0]).slice(),
    tag: () => take(PAIR_TAG_LEN).slice(),
    /** The next KeyMaterial, which must be `publicKey`'s to the byte. */
    key(publicKey) {
      const expected = keyField(publicKey);
      const found = take(expected.length);
      if (!found.every((byte, index) => byte === expected[index])) throw new Error(OUT_OF_PLACE);
    },
    end() {
      if (rest.length !== 0) throw new Error(OUT_OF_PLACE);
    },
  };
  if (reader.byte() !== PAIR_VERSION) throw new Error(OUT_OF_PLACE);
  reader.kind = reader.byte();
  if (reader.kind === PAIR_REFUSED) {
    const name = REFUSALS[reader.byte()];
    reader.end();
    if (!name) throw new Error(OUT_OF_PLACE);
    throw refusal(name);
  }
  return reader;
}

function pairMessage(kind, ...fields) {
  return concat(Uint8Array.of(PAIR_VERSION, kind), ...fields);
}

/** What both PIN confirmations cover, as coqui_peer::pair's `transcript`. */
function pinTranscript(joiner, responder, joinerMessage, responderMessage, binding) {
  return concat(
    encoder.encode('coqui-pair pin'), keyField(joiner), keyField(responder), Uint8Array.of(PAIR_NO_SLOT),
    short(joinerMessage), short(responderMessage), Uint8Array.of(1), field(binding),
  );
}

async function confirmationKeys(shared) {
  const keys = {
    joiner: await hkdf(shared, encoder.encode('coqui-pair joiner confirmation'), HASHLEN),
    responder: await hkdf(shared, encoder.encode('coqui-pair responder confirmation'), HASHLEN),
  };
  shared.fill(0);
  return keys;
}

async function macKey(bytes) {
  const key = await subtle().importKey('raw', bytes, HMAC, false, ['sign', 'verify']);
  bytes.fill(0);
  return key;
}

const macOf = async (key, data) => new Uint8Array(await subtle().sign('HMAC', key, data));
// WebCrypto's `verify` is the comparison made for a MAC, not one that stops at the first difference.
const macVerifies = (key, tag, data) => subtle().verify('HMAC', key, tag, data);

function checkTransport(transport) {
  if (typeof transport?.send !== 'function' || typeof transport?.recv !== 'function') {
    throw new TypeError('A transport with send(bytes) and recv() is required');
  }
}

/**
 * A transport's next record; its end, before the exchange's, is what a cut looks like. What is too long
 * to be a record of the exchange is not opened: a stranger's record costs a decryption only if it can be
 * what it should.
 */
async function nextMessage(session, transport) {
  const record = await transport.recv();
  if (record === null || record === undefined) throw new Error('The stream was truncated: the exchange did not finish');
  if (record.byteLength > MAX_PAIRING_RECORD) throw new Error(OUT_OF_PLACE);
  const message = await session.open(record);
  if (message === null) throw new Error('The stream was truncated: the peer closed before the exchange finished');
  return message;
}

const pairDesks = new WeakMap();
const DESK_DEFAULTS = Object.freeze({combinations: 10 ** 6, pinAttempts: 1, pinTtl: 600_000});

/**
 * Where a responder keeps the PIN it shows. Options, each with a default and no floor:
 * `pinAlphabet` ('0123456789'), `pinLength` (6), `pinTtl` (600000 ms, also how long an exchange lasts),
 * `pinAttempts` (1: how many runs may try a PIN; a run counts once past its first PAKE message), `now`
 * (Date.now) and `random` (the operating system's; replacing it is for test vectors only).
 */
export function createPairingDesk({
  pinAlphabet = '0123456789', pinLength = 6, pinTtl = 600_000, pinAttempts = 1, now = Date.now, random = OS_RANDOM,
} = {}) {
  const alphabet = typeof pinAlphabet === 'string' ? [...pinAlphabet] : [];
  if (alphabet.length === 0 || new Set(alphabet).size !== alphabet.length ||
      !Number.isSafeInteger(pinLength) || pinLength < 1 || !(pinTtl > 0) ||
      !Number.isSafeInteger(pinAttempts) || pinAttempts < 1 ||
      typeof now !== 'function' || typeof random !== 'function') {
    throw new Error('A pairing desk option has no meaning');
  }
  let shown = null;
  let left = 0;
  let gone = 'exhausted';
  const sweep = () => {
    if (shown && now() >= shown.expires) {
      shown = null;
      gone = 'expired';
    }
  };
  // Rejection over a 32-bit word, as coqui_peer's desk draws: every character equally likely.
  const below = bound => {
    const span = 2 ** 32;
    const limit = span - span % bound;
    for (;;) {
      const drawn = random(4);
      const word = new DataView(drawn.buffer, drawn.byteOffset, 4).getUint32(0, false);
      if (word < limit) return word % bound;
    }
  };
  const desk = Object.freeze({
    /** The options looser than their default: `[{setting, value, strict}]`. */
    weakened() {
      const found = [];
      const combinations = alphabet.length ** pinLength;
      if (combinations < DESK_DEFAULTS.combinations) {
        found.push(weakening('pinCombinations', combinations, DESK_DEFAULTS.combinations));
      }
      if (pinAttempts > DESK_DEFAULTS.pinAttempts) found.push(weakening('pinAttempts', pinAttempts, DESK_DEFAULTS.pinAttempts));
      if (pinTtl > DESK_DEFAULTS.pinTtl) found.push(weakening('pinTtl', pinTtl, DESK_DEFAULTS.pinTtl));
      if (random !== OS_RANDOM) found.push(weakening('random', "caller's", "the engine's"));
      if (now !== Date.now) found.push(weakening('now', "caller's", 'Date.now'));
      return found;
    },
    /** Shows a new PIN, replacing any before it, with its attempts. */
    showPin() {
      let pin = '';
      for (let index = 0; index < pinLength; index += 1) pin += alphabet[below(alphabet.length)];
      shown = {pin, expires: now() + pinTtl};
      left = pinAttempts;
      return Object.freeze({...shown});
    },
    /** The PIN shown now, while it lasts and has attempts left, or null. */
    shownPin() {
      sweep();
      return shown && Object.freeze({...shown});
    },
    clearPin() {
      shown = null;
      gone = 'exhausted';
    },
  });
  pairDesks.set(desk, {
    now, random, pinTtl,
    /** The refusal to give now, or null when a PIN is shown. */
    ready() {
      sweep();
      return shown ? null : gone;
    },
    /** One attempt at the shown PIN, burning it after the last; the refusal when there is none. */
    take() {
      sweep();
      if (!shown) return {refused: gone};
      const {pin} = shown;
      left -= 1;
      if (left === 0) {
        shown = null;
        gone = 'exhausted';
      }
      return {pin};
    },
  });
  return desk;
}

/** What a pairing handshake ends in: a proved key that is nobody yet. It runs one exchange and carries nothing else. */
function pairingSessionOf(session, local, remote, verified, random, firstMessageTimeout) {
  let used = false;
  const once = () => {
    if (used) throw new Error('A pairing session runs one exchange');
    used = true;
  };
  const refuse = async (transport, name) => {
    try {
      await transport.send(await session.seal(pairMessage(PAIR_REFUSED, Uint8Array.of(refusalByte(name)))));
    } catch {
      // The other side is told why as far as the transport still takes it.
    }
    return refusal(name);
  };
  const closing = async transport => {
    try {
      await transport.send(await session.close());
    } catch {
      // It already has what it needs: its last message came before this.
    }
  };
  const peer = Object.freeze({method: METHOD, label: KEY_LABEL, publicKey: b64(spkiOf(remote))});
  return Object.freeze({
    id: session.id,
    peer,
    verified,
    /**
     * Joins with the PIN a person typed, each message sealed. Resolves to the responder's
     * `{peerId, peer, mode: 'pin'}`, to pin from now on; rejects with an `Error` whose `refusal` says why
     * when either side refused. A `wrong-code` spends the PIN: never join with it again, and get a new one.
     * Attempts are counted at the responder's desk, which a relay posing as the responder never reaches, so
     * each run with the same PIN gives such a relay a new guess.
     */
    async join(pin, transport) {
      once();
      try {
        if (typeof pin !== 'string' || pin.length === 0) throw new TypeError('A PIN is required');
        checkTransport(transport);
        const [idA, idB] = [await peerIdOf(local.public), await peerIdOf(remote)];
        const binding = await session.export(PAIR_EXPORT_LABEL, HASHLEN);
        const password = encoder.encode(pin);
        await transport.send(await session.seal(
          pairMessage(PAIR_HELLO, Uint8Array.of(PAIR_MODE_PIN_TYPED), keyField(local.public)),
        ));
        const ready = pairReader(await nextMessage(session, transport));
        if (ready.kind !== PAIR_READY) throw new Error(OUT_OF_PLACE);
        ready.key(remote);
        if (ready.byte() !== PAIR_NO_SLOT) throw new Error(OUT_OF_PLACE);
        ready.end();
        const {state, message} = await spakeStart(true, password, encoder.encode(idA), encoder.encode(idB), random);
        await transport.send(await session.seal(pairMessage(PAIR_PAKE, short(message))));
        const reply = pairReader(await nextMessage(session, transport));
        if (reply.kind !== PAIR_REPLY) throw new Error(OUT_OF_PLACE);
        const received = reply.short();
        const tag = reply.tag();
        reply.end();
        const shared = await spakeFinish(state, received);
        password.fill(0);
        if (!shared) throw await refuse(transport, 'wrong-code');
        const keys = await confirmationKeys(shared);
        const transcript = pinTranscript(local.public, remote, message, received, binding);
        const joinerKey = await macKey(keys.joiner);
        const responderKey = await macKey(keys.responder);
        if (!await macVerifies(responderKey, tag, transcript)) throw await refuse(transport, 'wrong-code');
        await transport.send(await session.seal(pairMessage(PAIR_CONFIRM, await macOf(joinerKey, transcript))));
        const done = pairReader(await nextMessage(session, transport));
        if (done.kind !== PAIR_DONE) throw new Error(OUT_OF_PLACE);
        done.key(remote);
        done.end();
        await closing(transport);
        return Object.freeze({peerId: idB, peer, mode: 'pin'});
      } finally {
        session.destroy();
      }
    },
    /**
     * Runs the responder until the end, each message sealed. `accept(peerId, peer)` keeps the joiner's
     * key, and runs only after the PIN confirmed; only then is the joiner told it worked. The joiner has
     * the smaller of `firstMessageTimeout` and the desk's `pinTtl` from this call to send its first
     * message, and `pinTtl` from that message to finish; past either it is told `expired`, and a time
     * already spent is expired with nothing read. This module's responder offers only a PIN typed at the
     * joiner, and refuses other modes as `disabled`.
     */
    async respond(desk, transport, {accept} = {}) {
      once();
      try {
        const counter = pairDesks.get(desk);
        if (!counter) throw new TypeError('A pairing desk is required');
        if (typeof accept !== 'function') throw new TypeError('An accept function is required');
        checkTransport(transport);
        const called = counter.now();
        const [idA, idB] = [await peerIdOf(remote), await peerIdOf(local.public)];
        const binding = await session.export(PAIR_EXPORT_LABEL, HASHLEN);
        const within = async deadline => {
          let timer;
          try {
            if (counter.now() >= deadline) throw EXPIRED;
            const expired = new Promise((_, reject) => {
              timer = setTimeout(reject, Math.min(deadline - counter.now(), MAX_TIMER), EXPIRED);
            });
            const message = await Promise.race([nextMessage(session, transport), expired]);
            if (counter.now() >= deadline) throw EXPIRED;
            return message;
          } catch (error) {
            if (error === EXPIRED) throw await refuse(transport, 'expired');
            throw error;
          } finally {
            clearTimeout(timer);
          }
        };
        const hello = pairReader(await within(called + Math.min(counter.pinTtl, firstMessageTimeout)));
        if (hello.kind !== PAIR_HELLO) throw new Error(OUT_OF_PLACE);
        const mode = hello.byte();
        hello.key(remote);
        if (mode > PAIR_MODE_DEVICE) throw new Error(OUT_OF_PLACE);
        if (mode !== PAIR_MODE_PIN_TYPED) throw await refuse(transport, 'disabled');
        hello.end();
        const deadline = counter.now() + counter.pinTtl;
        const notReady = counter.ready();
        if (notReady) throw await refuse(transport, notReady);
        await transport.send(await session.seal(pairMessage(PAIR_READY, keyField(local.public), Uint8Array.of(PAIR_NO_SLOT))));
        const pake = pairReader(await within(deadline));
        if (pake.kind !== PAIR_PAKE) throw new Error(OUT_OF_PLACE);
        const received = pake.short();
        pake.end();
        const taken = counter.take();
        if (taken.refused) throw await refuse(transport, taken.refused);
        const password = encoder.encode(taken.pin);
        const {state, message} = await spakeStart(
          false, password, encoder.encode(idA), encoder.encode(idB), counter.random,
        );
        const shared = await spakeFinish(state, received);
        password.fill(0);
        if (!shared) throw await refuse(transport, 'wrong-code');
        const keys = await confirmationKeys(shared);
        const transcript = pinTranscript(remote, local.public, received, message, binding);
        const joinerKey = await macKey(keys.joiner);
        const responderKey = await macKey(keys.responder);
        await transport.send(await session.seal(
          pairMessage(PAIR_REPLY, short(message), await macOf(responderKey, transcript)),
        ));
        const confirm = pairReader(await within(deadline));
        if (confirm.kind !== PAIR_CONFIRM) throw new Error(OUT_OF_PLACE);
        const tag = confirm.tag();
        confirm.end();
        if (!await macVerifies(joinerKey, tag, transcript)) throw await refuse(transport, 'wrong-code');
        await accept(idA, peer);
        await transport.send(await session.seal(pairMessage(PAIR_DONE, keyField(local.public))));
        await closing(transport);
        return Object.freeze({peerId: idA, peer, mode: 'pin'});
      } finally {
        session.destroy();
      }
    },
  });
}

/**
 * Starts a handshake that only pairs, as the side that dials. It accepts any proved key, unless
 * `responder` names the id it must be; a PIN authenticates both keys either way. Other options as for
 * `createInitiator`, and `random` as for `createPairingDesk`. `answer` gives a `pairing` and no session.
 */
export async function createPairingInitiator(identity, {responder, random = OS_RANDOM, ...config} = {}) {
  const settings = options(config);
  const local = await checkIdentity(identity);
  if (responder !== undefined && !PEER_ID.test(responder)) throw new Error('A pinned responder id is required');
  const looser = [];
  if (responder === undefined) looser.push(weakening('responders', 'any-with-key-proof', 'pinned'));
  if (random !== OS_RANDOM) looser.push(weakening('random', "caller's", "the engine's"));
  return dialling(local, PURPOSE_PAIR, settings, looser, async id => {
    if (responder !== undefined && id !== responder) throw new Error('Responder is not pinned');
  }, async (session, remote) => ({
    pairing: pairingSessionOf(session, local, remote, responder !== undefined, random),
  }));
}

/**
 * Starts a handshake that only pairs, as the side that accepts: it admits whoever proves a key, since a
 * joiner is a stranger, and `accept` gives a `pairing` and no session. Options as for `createResponder`,
 * without `allowClient`, and `firstMessageTimeout`: the milliseconds a joiner has to send its first
 * message, under the desk's `pinTtl`. `DEFAULT_FIRST_MESSAGE_TIMEOUT` by default, with no floor: 0 refuses
 * as expired without reading.
 */
export async function createPairingResponder(identity, {firstMessageTimeout = DEFAULT_FIRST_MESSAGE_TIMEOUT, ...config} = {}) {
  if (typeof firstMessageTimeout !== 'number' || !(firstMessageTimeout >= 0)) {
    throw new Error('A firstMessageTimeout of that kind has no meaning');
  }
  const settings = options(config);
  const local = await checkIdentity(identity);
  const looser = [weakening('initiators', 'any-with-key-proof', 'pinned')];
  if (firstMessageTimeout > DEFAULT_FIRST_MESSAGE_TIMEOUT) {
    looser.push(weakening('firstMessageTimeout', firstMessageTimeout, DEFAULT_FIRST_MESSAGE_TIMEOUT));
  }
  return accepting(local, PURPOSE_PAIR, settings, looser, async () => {}, async (session, remote) => ({
    pairing: pairingSessionOf(session, local, remote, false, OS_RANDOM, firstMessageTimeout),
  }));
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
export const __testing = Object.freeze({
  newHandshake, newCipher, createSession, isCanonical, pointAdd, pointMul, compress, decompress, passwordScalar,
  spakeStartWith, spakeFinish, BASE, L, P, CURVE_D, SQRT_M1,
});
