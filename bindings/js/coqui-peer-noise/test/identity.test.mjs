// Keys: non-extractable, the id a standard tool computes, what is refused.
import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {
  createInitiator, createResponder, generateIdentity, importIdentity, loadOrCreateIdentity, METHOD, __testing,
} from '../src/index.mjs';
import {unhex} from './support.mjs';

// `openssl genpkey -algorithm x25519`, a throwaway test key, as its DER.
const OPENSSL_PKCS8 = Buffer.from('MC4CAQAwBQYDK2VuBCIEIDi29y8jdUtbXzmuAH6tYOxcbCD7wqdUsLfpBzNO5xdV', 'base64');
// `openssl pkey -pubout -outform DER | sha256sum` of that key.
const OPENSSL_ID = 'sha256:85bdd198338bedb20428aab5683b1c5092461a721db1a5bd110cd7577d0f94c2';
const OPENSSL_SPKI = 'MCowBQYDK2VuAyEAxXhaql3PIQwxERcRjkoGe+bu/pxy4v2m2aQErnlpOnA=';

test('one private key proves eight ids, and each is admitted only on its own', async () => {
  const {P, compress, decompress, pointAdd, pointMul} = __testing;
  const power = (base, exponent) => {
    let [result, square, rest] = [1n, base % P, exponent];
    while (rest > 0n) {
      if (rest & 1n) result = result * square % P;
      square = square * square % P;
      rest >>= 1n;
    }
    return result;
  };
  const inverse = value => power((value % P + P) % P, P - 2n);
  const toInteger = bytes => [...bytes].reverse().reduce((value, byte) => (value << 8n) | BigInt(byte), 0n);
  const toBytes = value => Uint8Array.from({length: 32}, (_, index) => Number((value >> BigInt(8 * index)) & 0xffn));
  // The Montgomery u of an Edwards point and back: u = (1 + y) / (1 - y), and the sign of x is lost.
  const edwardsOf = u => decompress(toBytes(((u - 1n + P) % P) * inverse(u + 1n) % P));
  const montgomeryOf = point => {
    const encoded = compress(point);
    encoded[31] &= 0x7f;
    const y = toInteger(encoded);
    return (1n + y) * inverse(1n - y + P) % P;
  };
  const eighth = decompress(unhex('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'));
  const honest = await generateIdentity();
  const honestKey = Buffer.from(honest.publicKey, 'base64url').subarray(12);
  const base = edwardsOf(toInteger(honestKey));
  const variants = [];
  for (let index = 0n; index < 8n; index += 1n) {
    const key = toBytes(montgomeryOf(pointAdd(base, pointMul(eighth, index))));
    const spki = Buffer.concat([Buffer.from(honest.publicKey, 'base64url').subarray(0, 12), key]);
    variants.push({
      method: honest.method,
      peerId: `sha256:${Buffer.from(await webcrypto.subtle.digest('SHA-256', spki)).toString('hex')}`,
      publicKey: spki.toString('base64url'),
      privateKey: honest.privateKey,
    });
  }
  assert.ok(variants.some(({peerId}) => peerId === honest.peerId), 'the honest key is one of them');
  const server = await generateIdentity();
  const run = async (variant, allowed) => {
    const i = await createInitiator(variant, server.peerId);
    const r = await createResponder(server, {allowClient: async id => id === allowed});
    const {reply, session} = await i.answer(await r.challenge(await i.hello()));
    const {session: far, peerId} = await r.accept(reply);
    assert.equal(new TextDecoder().decode(await far.open(await session.seal('the same key'))), 'the same key');
    return peerId;
  };
  const ids = [];
  for (const variant of variants) ids.push(await run(variant, variant.peerId));
  assert.equal(new Set(ids).size, 8, 'one private key, eight ids');
  // No trust carries from one to another.
  for (const variant of variants.filter(({peerId}) => peerId !== honest.peerId)) {
    await assert.rejects(run(variant, honest.peerId), /not paired/);
  }
});

test('a generated identity keeps its private key non-extractable', async () => {
  const identity = await generateIdentity();
  assert.equal(identity.method, METHOD);
  assert.equal(identity.privateKey.extractable, false);
  assert.equal(identity.privateKey.algorithm.name, 'X25519');
  await assert.rejects(() => webcrypto.subtle.exportKey('pkcs8', identity.privateKey));
  assert.match(identity.peerId, /^sha256:[a-f0-9]{64}$/);
});

test('a key openssl wrote has the public key and the id openssl computes', async () => {
  const identity = await importIdentity(OPENSSL_PKCS8);
  assert.equal(identity.peerId, OPENSSL_ID);
  assert.equal(Buffer.from(identity.publicKey, 'base64url').toString('base64'), OPENSSL_SPKI);
  assert.equal(identity.privateKey.extractable, false);
});

test('importIdentity reads its input once and leaves the caller\'s buffer as it was', async () => {
  const buffer = Uint8Array.from(OPENSSL_PKCS8);
  await importIdentity(buffer);
  assert.deepEqual(Buffer.from(buffer), OPENSSL_PKCS8);
});

test('what is not an X25519 PKCS#8 key is refused', async () => {
  for (const bytes of [new Uint8Array(0), new Uint8Array(48), new Uint8Array(49), OPENSSL_PKCS8.subarray(0, 47)]) {
    await assert.rejects(() => importIdentity(bytes), /Not an X25519/);
  }
  await assert.rejects(() => importIdentity('text'), /Expected bytes/);
});

test('an identity with an extractable key or a false id is refused', async () => {
  const fresh = await generateIdentity();
  const id = 'sha256:' + '0'.repeat(64);
  const pair = await webcrypto.subtle.generateKey('X25519', true, ['deriveBits']);
  await assert.rejects(() => createInitiator({...fresh, privateKey: pair.privateKey}, id), /non-extractable/);
  await assert.rejects(() => createInitiator({...fresh, peerId: id}, id), /non-extractable/);
  await assert.rejects(() => createInitiator({...fresh, publicKey: 'AAAA'}, id), /non-extractable/);
  await assert.rejects(() => createInitiator({...fresh, publicKey: '@@@'}, id), /non-extractable/);
  // Another prefix before the same key: its id is computed from the key, so only the prefix can tell.
  const otherPrefix = Buffer.from(fresh.publicKey, 'base64url');
  otherPrefix[0] ^= 1;
  await assert.rejects(
    () => createInitiator({...fresh, publicKey: otherPrefix.toString('base64url')}, id), /non-extractable/,
  );
  const p256 = await webcrypto.subtle.generateKey({name: 'ECDH', namedCurve: 'P-256'}, false, ['deriveBits']);
  await assert.rejects(() => createInitiator({...fresh, privateKey: p256.privateKey}, id), /non-extractable/);
  await assert.rejects(() => createInitiator(fresh, 'not an id'), /pinned responder id/);
  await assert.rejects(() => createInitiator(fresh, undefined), /pinned responder id/);
});

test('an identity store needs a name, and IndexedDB', async () => {
  await assert.rejects(() => loadOrCreateIdentity(''), /store name/);
  await assert.rejects(() => loadOrCreateIdentity('a name'), /IndexedDB/);
});
