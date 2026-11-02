// The vectors the Rust tests pin: this implementation must reach the same bytes and refuse the same
// messages at the same stages.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {createInitiator, createResponder, importIdentity, PROFILE, PROTOCOL_NAME} from '../src/index.mjs';
import {keyPairOf, toHex, unhex} from './support.mjs';

const vectors = JSON.parse(readFileSync(new URL('../../../../tests/vectors/session.json', import.meta.url)));
// What the vectors call each refusal, as this implementation words it.
const refusal = {Malformed: /Invalid peer message/, BadProof: /does not decrypt/};
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const longMessage = Uint8Array.from({length: vectors.longRecord.length}, (_, index) => index % vectors.longRecord.modulo);

const identity = side => importIdentity(unhex(side.pkcs8));
const ephemeralOf = side => () => keyPairOf(unhex(side.ephemeralPkcs8), unhex(side.ephemeralPublic));

async function initiator(options = {}) {
  return createInitiator(await identity(vectors.initiator), vectors.responder.peerId, {
    ephemeral: ephemeralOf(vectors.initiator), ...options,
  });
}

async function responder(options = {}) {
  return createResponder(await identity(vectors.responder), {
    allowClient: async id => id === vectors.initiator.peerId,
    ephemeral: ephemeralOf(vectors.responder),
    ...options,
  });
}

async function run(options) {
  const i = await initiator(options);
  const r = await responder(options);
  const second = await r.challenge(await i.hello());
  const {reply, session: atInitiator} = await i.answer(second);
  const {session: atResponder} = await r.accept(reply);
  return {atInitiator, atResponder};
}

test('the names are the vectors\'', () => {
  assert.equal(vectors.protocol, PROTOCOL_NAME);
  assert.equal(vectors.profile, PROFILE);
});

test('identities give the vector ids and keys', async () => {
  for (const side of [vectors.initiator, vectors.responder]) {
    const imported = await identity(side);
    assert.equal(imported.peerId, side.peerId);
    assert.equal(Buffer.from(imported.publicKey, 'base64url').toString('hex'), side.spki);
    assert.equal(imported.privateKey.extractable, false);
  }
});

test('an initiator reaches the vector messages, id, exports, records and close', async () => {
  const i = await initiator();
  assert.equal(toHex(await i.hello()), vectors.messages[0]);
  const {reply, peerId, session} = await i.answer(unhex(vectors.messages[1]));
  assert.equal(toHex(reply), vectors.messages[2]);
  assert.equal(peerId, vectors.responder.peerId);
  assert.equal(toHex(session.id), vectors.session.id);
  for (const {label, length, bytes} of vectors.session.exports) {
    assert.equal(toHex(await session.export(label, length)), bytes);
  }
  for (const {from, message, record} of vectors.records) {
    if (from === 'initiator') {
      assert.equal(toHex(await session.seal(unhex(message))), record);
    } else {
      assert.equal(toHex(await session.open(unhex(record))), message);
    }
  }
  assert.equal(sha256(await session.seal(longMessage)), vectors.longRecord.recordSha256);
  assert.equal(toHex(await session.close()), vectors.closes.initiator);
  await assert.rejects(() => session.seal('after'), /already closed/);
});

test('a responder reaches the vector messages, id, records and close', async () => {
  const r = await responder();
  assert.equal(toHex(await r.challenge(unhex(vectors.messages[0]))), vectors.messages[1]);
  const {peerId, session} = await r.accept(unhex(vectors.messages[2]));
  assert.equal(peerId, vectors.initiator.peerId);
  assert.equal(toHex(session.id), vectors.session.id);
  for (const {from, message, record} of vectors.records) {
    if (from === 'responder') {
      assert.equal(toHex(await session.seal(unhex(message))), record);
    } else {
      assert.equal(toHex(await session.open(unhex(record))), message);
    }
  }
  assert.equal(toHex(await session.close()), vectors.closes.responder);
  const {atInitiator, atResponder} = await run();
  assert.equal(toHex(await atResponder.open(await atInitiator.seal(longMessage))), toHex(longMessage));
});

test('a small key limit changes the key where the vectors do, and the far end follows', async () => {
  const limit = {keyLimit: vectors.keyLimit.limit};
  const {atInitiator, atResponder} = await run(limit);
  for (const {message, record} of vectors.keyLimit.records) {
    assert.equal(toHex(await atInitiator.seal(unhex(message))), record);
    assert.equal(toHex(await atResponder.open(unhex(record))), message);
  }
});

test('a binding reaches the vector messages and id', async () => {
  const binding = unhex(vectors.binding.value);
  const i = await initiator({binding});
  const r = await responder({binding});
  assert.equal(toHex(await i.hello()), vectors.binding.messages[0]);
  assert.equal(toHex(await r.challenge(unhex(vectors.binding.messages[0]))), vectors.binding.messages[1]);
  const {reply, session} = await i.answer(unhex(vectors.binding.messages[1]));
  assert.equal(toHex(reply), vectors.binding.messages[2]);
  assert.equal(toHex(session.id), vectors.binding.id);
  await r.accept(reply);
});

test('a well-made record after the peer\'s close is refused', async () => {
  const {atResponder} = await run();
  assert.equal(await atResponder.open(unhex(vectors.afterClose.close)), null);
  await assert.rejects(() => atResponder.open(unhex(vectors.afterClose.data)), /session is over/);
  assert.throws(() => atResponder.verifyEnd(), /session is over/);
});

for (const entry of vectors.refused.first) {
  test(`first message refused: ${entry.name}`, async () => {
    const r = await responder();
    await assert.rejects(() => r.challenge(unhex(entry.message)), refusal[entry.error]);
    await assert.rejects(() => r.challenge(unhex(vectors.messages[0])), /Unexpected/);
  });
}

for (const entry of vectors.refused.second) {
  test(`second message refused: ${entry.name}`, async () => {
    const i = await initiator();
    await i.hello();
    await assert.rejects(() => i.answer(unhex(entry.message)), refusal[entry.error]);
    await assert.rejects(() => i.answer(unhex(vectors.messages[1])), /Unexpected/);
  });
}

for (const entry of vectors.refused.third) {
  test(`third message refused: ${entry.name}`, async () => {
    const r = await responder();
    await r.challenge(unhex(vectors.messages[0]));
    await assert.rejects(() => r.accept(unhex(entry.message)), refusal[entry.error]);
    await assert.rejects(() => r.accept(unhex(vectors.messages[2])), /Unexpected/);
  });
}

for (const entry of vectors.refused.records) {
  test(`record refused, and the session ends: ${entry.name}`, async () => {
    const {atInitiator, atResponder} = await run();
    await assert.rejects(() => atResponder.open(unhex(entry.record)), /does not open/);
    const genuine = await atInitiator.seal('after it');
    await assert.rejects(() => atResponder.open(genuine), /session is over/);
    await assert.rejects(() => atResponder.seal('reply'), /session is over/);
    await assert.rejects(() => atResponder.close(), /session is over/);
    assert.throws(() => atResponder.verifyEnd(), /session is over/);
  });
}
