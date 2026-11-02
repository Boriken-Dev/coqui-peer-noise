// The published vectors of this protocol, whose handshake messages carry payloads the method never
// sends, so they run against the layer beneath it.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {webcrypto} from 'node:crypto';
import {__testing} from '../src/index.mjs';
import {X25519_PKCS8_PREFIX, toHex, unhex} from './support.mjs';

const {newHandshake, newCipher} = __testing;
const published = JSON.parse(readFileSync(new URL('../../../../tests/vectors/published.json', import.meta.url)));
const X25519 = {name: 'X25519'};

async function keyOf(raw) {
  const pkcs8 = unhex(X25519_PKCS8_PREFIX + raw);
  const usable = await webcrypto.subtle.importKey('pkcs8', pkcs8, X25519, true, ['deriveBits']);
  const {x} = await webcrypto.subtle.exportKey('jwk', usable);
  return {
    privateKey: await webcrypto.subtle.importKey('pkcs8', pkcs8, X25519, false, ['deriveBits']),
    public: Uint8Array.from(Buffer.from(x, 'base64url')),
  };
}

test('the published vectors are present from both sources', () => {
  const sources = published.vectors.map(vector => vector.source).sort();
  assert.deepEqual(sources, ['cacophony', 'noise-c']);
});

for (const vector of published.vectors) {
  test(`the ${vector.source} vector is reproduced in both roles`, async () => {
    const initiator = await newHandshake(
      true, unhex(vector.init_prologue), await keyOf(vector.init_static), await keyOf(vector.init_ephemeral),
    );
    const responder = await newHandshake(
      false, unhex(vector.resp_prologue), await keyOf(vector.resp_static), await keyOf(vector.resp_ephemeral),
    );
    for (const [index, message] of vector.messages.slice(0, 3).entries()) {
      const [from, to] = index % 2 === 0 ? [initiator, responder] : [responder, initiator];
      assert.equal(toHex(await from.writeMessage(unhex(message.payload))), message.ciphertext);
      assert.equal(toHex(await to.readMessage(unhex(message.ciphertext))), message.payload);
    }
    const atInitiator = await initiator.split();
    const atResponder = await responder.split();
    assert.equal(toHex(atInitiator.h), toHex(atResponder.h));
    if (vector.handshake_hash) assert.equal(toHex(atInitiator.h), vector.handshake_hash);
    for (const [offset, message] of vector.messages.slice(3).entries()) {
      const [sending, receiving] = (offset + 3) % 2 === 0
        ? [atInitiator.initiatorToResponder, atResponder.initiatorToResponder]
        : [atResponder.responderToInitiator, atInitiator.responderToInitiator];
      const empty = new Uint8Array();
      assert.equal(toHex(await sending.encrypt(empty, unhex(message.payload))), message.ciphertext);
      assert.equal(toHex(await receiving.decrypt(empty, unhex(message.ciphertext))), message.payload);
    }
  });
}

test('the reserved nonce is never used by a message', async () => {
  const key = new Uint8Array(32).fill(7);
  const empty = new Uint8Array();
  const last = await newCipher(key, 0xfffffffffffffffen);
  await last.encrypt(empty, Uint8Array.of(1));
  await assert.rejects(() => last.encrypt(empty, Uint8Array.of(2)), /nonces/);
  assert.equal(last.remaining, 0n);
  const reserved = await newCipher(key, 0xffffffffffffffffn);
  await assert.rejects(() => reserved.decrypt(empty, new Uint8Array(32)), /nonces/);
});

test('rekey is the first 32 bytes at the reserved nonce and the nonce carries on', async () => {
  const bytes = new Uint8Array(32).fill(9);
  const key = await webcrypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt']);
  const iv = new Uint8Array(12).fill(0xff);
  iv.fill(0, 0, 4);
  const expected = new Uint8Array(await webcrypto.subtle.encrypt({name: 'AES-GCM', iv}, key, new Uint8Array(32)));
  const empty = new Uint8Array();
  const rekeyed = await newCipher(bytes);
  await rekeyed.encrypt(empty, Uint8Array.of(1));
  await rekeyed.rekey();
  const direct = await newCipher(expected.subarray(0, 32), 1n);
  assert.equal(
    toHex(await rekeyed.encrypt(empty, Uint8Array.of(2))),
    toHex(await direct.encrypt(empty, Uint8Array.of(2))),
  );
});
