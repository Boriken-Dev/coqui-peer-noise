// Keys: non-extractable, the id a standard tool computes, what is refused.
import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {
  createInitiator, generateIdentity, importIdentity, loadOrCreateIdentity, METHOD,
} from '../src/index.mjs';

// `openssl genpkey -algorithm x25519`, a throwaway test key, as its DER.
const OPENSSL_PKCS8 = Buffer.from('MC4CAQAwBQYDK2VuBCIEIDi29y8jdUtbXzmuAH6tYOxcbCD7wqdUsLfpBzNO5xdV', 'base64');
// `openssl pkey -pubout -outform DER | sha256sum` of that key.
const OPENSSL_ID = 'sha256:85bdd198338bedb20428aab5683b1c5092461a721db1a5bd110cd7577d0f94c2';
const OPENSSL_SPKI = 'MCowBQYDK2VuAyEAxXhaql3PIQwxERcRjkoGe+bu/pxy4v2m2aQErnlpOnA=';

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
  const p256 = await webcrypto.subtle.generateKey({name: 'ECDH', namedCurve: 'P-256'}, false, ['deriveBits']);
  await assert.rejects(() => createInitiator({...fresh, privateKey: p256.privateKey}, id), /non-extractable/);
  await assert.rejects(() => createInitiator(fresh, 'not an id'), /pinned responder id/);
  await assert.rejects(() => createInitiator(fresh, undefined), /pinned responder id/);
});

test('an identity store needs a name, and IndexedDB', async () => {
  await assert.rejects(() => loadOrCreateIdentity(''), /store name/);
  await assert.rejects(() => loadOrCreateIdentity('a name'), /IndexedDB/);
});
