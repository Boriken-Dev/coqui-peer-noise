// What a party carrying the connection can do, such as a reverse proxy that ends TLS. No TLS is
// involved anywhere here: the relay is the function that moves a message.
import test from 'node:test';
import assert from 'node:assert/strict';
import {runInNewContext} from 'node:vm';
import {setFlagsFromString} from 'node:v8';
import {webcrypto} from 'node:crypto';
import {
  __testing, createInitiator, createPairingInitiator, createPairingResponder, createResponder,
  DEFAULT_KEY_LIMIT, generateIdentity, recordLength, supported,
} from '../src/index.mjs';
import {asIs, parties, sessions, through} from './support.mjs';

const text = bytes => new TextDecoder().decode(bytes);
const flip = (bytes, index) => {
  const out = bytes.slice();
  out[index] ^= 1;
  return out;
};

test('a plain relay connects only the real parties, and reads and writes nothing after', async () => {
  const p = await parties();
  const seen = [];
  const {atClient, atServer, answered, accepted} = await through(message => {
    seen.push(message);
    return message;
  }, p);
  assert.equal(answered.peerId, p.server.peerId);
  assert.equal(accepted.peerId, p.client.peerId);
  assert.deepEqual(atClient.id, atServer.id);
  const record = await atClient.seal('not for the relay');
  assert.ok(!Buffer.from(record).includes('not for'));
  assert.equal(text(await atServer.open(record)), 'not for the relay');
  assert.deepEqual(await atClient.export('label', 32), await atServer.export('label', 32));
  // A static key never goes in the clear.
  const all = Buffer.concat(seen);
  for (const identity of [p.client, p.server]) {
    const key = Buffer.from(identity.publicKey, 'base64url').subarray(12);
    assert.ok(!all.includes(key));
  }
  assert.deepEqual(seen.map(message => message.length), [32, 96, 64]);
});

test('a relay cannot inject a message after the proof', async () => {
  const {atClient, atServer} = await sessions();
  await assert.rejects(() => atServer.open(new TextEncoder().encode('{"jsonrpc":"2.0"}')), /does not open/);
  await assert.rejects(async () => atServer.open(await atClient.seal('genuine')), /session is over/);
});

test('a relay cannot replay, reorder, reflect or alter a record', async () => {
  let {atClient, atServer} = await sessions();
  const once = await atClient.seal('once');
  await atServer.open(once);
  await assert.rejects(() => atServer.open(once), /does not open/);

  ({atClient, atServer} = await sessions());
  await atClient.seal('1');
  const second = await atClient.seal('2');
  await assert.rejects(() => atServer.open(second), /does not open/);

  ({atClient, atServer} = await sessions());
  await assert.rejects(async () => atClient.open(await atClient.seal('mine')), /does not open/);
  await assert.rejects(async () => atServer.open(await atServer.seal('mine')), /does not open/);

  const length = (await (await sessions()).atClient.seal('m')).length;
  for (let index = 0; index < length; index += 1) {
    ({atClient, atServer} = await sessions());
    await assert.rejects(async () => atServer.open(flip(await atClient.seal('m'), index)));
  }
});

test('a record of one session does not open in another', async () => {
  const one = await sessions();
  const other = await sessions();
  await assert.rejects(async () => other.atServer.open(await one.atClient.seal('elsewhere')), /does not open/);
});

test('nothing after a bad record is believed, even at its right place', async () => {
  const {atClient, atServer} = await sessions();
  const record = await atClient.seal('1');
  await assert.rejects(() => atServer.open(flip(record, 3)), /does not open/);
  await assert.rejects(() => atServer.open(record), /session is over/);
});

test('a failed open ends sending too', async () => {
  const {atServer} = await sessions();
  await assert.rejects(() => atServer.open(Uint8Array.of(1, 2, 3)), /does not open/);
  await assert.rejects(() => atServer.seal('x'), /session is over/);
  await assert.rejects(() => atServer.close(), /session is over/);
  assert.throws(() => atServer.verifyEnd(), /session is over/);
});

test('a relay altering any handshake message fails the run', async () => {
  for (const [stage, length] of [[0, 32], [1, 96], [2, 64]]) {
    for (let index = 0; index < length; index += 7) {
      const p = await parties();
      let current = -1;
      await assert.rejects(() => through(message => {
        current += 1;
        return current === stage ? flip(message, index) : message;
      }, p));
    }
  }
});

test('messages cannot be cross-wired between two runs', async () => {
  const client = await generateIdentity();
  const server = await generateIdentity();
  const pinned = () => createInitiator(client, server.peerId);
  const accepting = () => createResponder(server, {allowClient: async id => id === client.peerId});
  const [i1, r1, i2, r2] = [await pinned(), await accepting(), await pinned(), await accepting()];
  await r1.challenge(await i1.hello());
  const second = await r2.challenge(await i2.hello());
  await assert.rejects(() => i1.answer(second), /does not decrypt/);

  const [i3, r3] = [await pinned(), await accepting()];
  const {reply} = await i3.answer(await r3.challenge(await i3.hello()));
  await assert.rejects(() => r1.accept(reply), /does not decrypt/);
});

test('a replayed first message gets a fresh run the recorded third cannot complete', async () => {
  const p = await parties();
  const first = await p.i.hello();
  const {reply} = await p.i.answer(await p.r.challenge(first));
  const again = await createResponder(p.server, {allowClient: async () => true});
  await again.challenge(first);
  await assert.rejects(() => again.accept(reply), /does not decrypt/);
});

test('a reflected handshake message is refused', async () => {
  let p = await parties();
  const first = await p.i.hello();
  await assert.rejects(() => p.i.answer(first), /Invalid peer message/);

  p = await parties();
  const mine = await p.i.hello();
  const real = (await p.r.challenge(mine)).slice();
  real.set(mine, 0);
  await assert.rejects(() => p.i.answer(real), /does not decrypt/);

  p = await parties();
  const second = await p.r.challenge(await p.i.hello());
  await assert.rejects(() => p.r.accept(second), /Invalid peer message/);
});

test('a peer dialling itself is refused', async () => {
  const self = await generateIdentity();
  const i = await createInitiator(self, self.peerId);
  const r = await createResponder(self, {allowClient: async () => true});
  await assert.rejects(async () => i.answer(await r.challenge(await i.hello())), /Invalid peer message/);
});

test('a relay answering with a key of its own fails the pin, and sends nothing more', async () => {
  const p = await parties();
  const relay = await generateIdentity();
  const asRelay = await createResponder(relay, {allowClient: async () => true});
  await assert.rejects(async () => p.i.answer(await asRelay.challenge(await p.i.hello())), /not pinned/);
  await assert.rejects(() => p.i.answer(new Uint8Array(96)), /Unexpected/);
});

test('a relay dialling with a key of its own fails the allow-list, only after it proved the key', async () => {
  const p = await parties();
  const relay = await generateIdentity();
  const asRelay = await createInitiator(relay, p.server.peerId);
  const {reply} = await asRelay.answer(await p.r.challenge(await asRelay.hello()));
  await assert.rejects(() => p.r.accept(reply), /not paired/);
});

test('sessions a relay holds with each end share nothing: its forwarding is refused', async () => {
  const [client, server, relay] = [await generateIdentity(), await generateIdentity(), await generateIdentity()];
  const near = {
    i: await createInitiator(client, relay.peerId),
    r: await createResponder(relay, {allowClient: async id => id === client.peerId}),
  };
  const far = {
    i: await createInitiator(relay, server.peerId),
    r: await createResponder(server, {allowClient: async id => id === relay.peerId}),
  };
  const toRelay = await through(asIs, near);
  const fromRelay = await through(asIs, far);
  assert.notDeepEqual(toRelay.atClient.id, fromRelay.atServer.id);
  await assert.rejects(async () => fromRelay.atServer.open(await toRelay.atClient.seal('as the client')), /does not open/);
});

test('an outer binding is optional, and two different channels are refused', async () => {
  const bound = await parties({binding: Uint8Array.of(1, 2, 3)});
  const {atClient, atServer} = await through(asIs, bound);
  assert.deepEqual(atClient.id, atServer.id);

  const client = await generateIdentity();
  const server = await generateIdentity();
  const allow = async id => id === client.peerId;
  const i = await createInitiator(client, server.peerId, {binding: Uint8Array.of(1)});
  const r = await createResponder(server, {allowClient: allow, binding: Uint8Array.of(2)});
  await assert.rejects(async () => i.answer(await r.challenge(await i.hello())), /does not decrypt/);

  const one = await createInitiator(client, server.peerId, {binding: Uint8Array.of(1)});
  const none = await createResponder(server, {allowClient: allow});
  await assert.rejects(async () => one.answer(await none.challenge(await one.hello())), /does not decrypt/);
});

test('a binding must be bytes, not something that turns into other bytes or none', async () => {
  const client = await generateIdentity();
  const server = await generateIdentity();
  for (const binding of ['text', new ArrayBuffer(3), new DataView(new ArrayBuffer(3)), 7, null]) {
    await assert.rejects(() => createInitiator(client, server.peerId, {binding}), /binding must be/);
  }
});

test('a binding is read when the call is made: a caller wiping it on return still binds to it', async () => {
  const client = await generateIdentity();
  const server = await generateIdentity();
  const allow = async id => id === client.peerId;
  const wiped = bytes => {
    const buffer = Uint8Array.of(...bytes);
    return {buffer, done: () => buffer.fill(0)};
  };
  const [one, two] = [wiped([1, 2, 3]), wiped([4, 5, 6])];
  const starting = createInitiator(client, server.peerId, {binding: one.buffer});
  one.done();
  const answering = createResponder(server, {allowClient: allow, binding: two.buffer});
  two.done();
  const [i, r] = await Promise.all([starting, answering]);
  await assert.rejects(async () => i.answer(await r.challenge(await i.hello())), /does not decrypt/);

  // The same for what only pairs, whose handshake has the same two sides.
  const [three, four] = [wiped([7]), wiped([8])];
  const pairingStart = createPairingInitiator(client, {binding: three.buffer});
  three.done();
  const pairingAnswer = createPairingResponder(server, {binding: four.buffer});
  four.done();
  const [near, far] = await Promise.all([pairingStart, pairingAnswer]);
  await assert.rejects(async () => near.answer(await far.challenge(await near.hello())), /does not decrypt/);

  // Wiped, the same value at both ends still finishes: what counts is what was there at the call.
  const [five, six] = [wiped([9]), wiped([9])];
  const same = createInitiator(client, server.peerId, {binding: five.buffer});
  five.done();
  const other = createResponder(server, {allowClient: allow, binding: six.buffer});
  six.done();
  const [a, b] = await Promise.all([same, other]);
  const {reply} = await a.answer(await b.challenge(await a.hello()));
  await b.accept(reply);
  const [seven, eight] = [wiped([9]), wiped([9])];
  const pairingSame = createPairingInitiator(client, {binding: seven.buffer});
  seven.done();
  const pairingOther = createPairingResponder(server, {binding: eight.buffer});
  eight.done();
  const [c, d] = await Promise.all([pairingSame, pairingOther]);
  const {reply: third} = await c.answer(await d.challenge(await c.hello()));
  await d.accept(third);
});

test('a relay cutting at each record boundary is reported as truncation', async () => {
  const messages = 4;
  for (let delivered = 0; delivered <= messages; delivered += 1) {
    const {atClient, atServer} = await sessions();
    const records = [];
    for (let index = 0; index < messages; index += 1) records.push(await atClient.seal(`m${index}`));
    records.push(await atClient.close());
    for (const record of records.slice(0, delivered)) await atServer.open(record);
    assert.throws(() => atServer.verifyEnd(), /truncated/);
  }
});

test('a stream ending with its close record is complete, and each direction closes on its own', async () => {
  const {atClient, atServer} = await sessions();
  assert.equal(text(await atServer.open(await atClient.seal('m'))), 'm');
  assert.equal(await atServer.open(await atClient.close()), null);
  atServer.verifyEnd();
  await assert.rejects(() => atClient.seal('x'), /already closed/);
  await assert.rejects(() => atClient.close(), /already closed/);
  assert.equal(text(await atClient.open(await atServer.seal('still here'))), 'still here');
  assert.throws(() => atClient.verifyEnd(), /truncated/);
  assert.equal(await atClient.open(await atServer.close()), null);
  atClient.verifyEnd();
});

test('a record after the peer\'s close is refused and ends the session', async () => {
  const {atClient, atServer} = await sessions();
  const close = await atClient.close();
  assert.equal(await atServer.open(close), null);
  await assert.rejects(() => atServer.open(close), /session is over/);
  await assert.rejects(() => atServer.seal('x'), /session is over/);
});

test('a message of any length is one record', async () => {
  const {atClient, atServer} = await sessions();
  for (const length of [0, 1, 65517, 65518, 65519, 131035, 131036, 131037, 300000]) {
    const message = new Uint8Array(length).fill(0x5a);
    assert.deepEqual(await atServer.open(await atClient.seal(message)), message, String(length));
  }
});

test('a record cut at a Noise message inside it is refused', async () => {
  let {atClient, atServer} = await sessions();
  const record = await atClient.seal(new Uint8Array(100000));
  await assert.rejects(() => atServer.open(record.subarray(0, 2 + 65535)), /does not open/);
  ({atClient, atServer} = await sessions());
  const other = await atClient.seal(new Uint8Array(100000));
  await assert.rejects(() => atServer.open(other.subarray(2 + 65535)), /does not open/);
});

test('a limit of zero passes only a close, and refuses with nothing sent', async () => {
  const {atClient, atServer} = await sessions({keyLimit: 0});
  await assert.rejects(() => atClient.seal(''), /limit/);
  await assert.rejects(() => atClient.seal('m'), /limit/);
  assert.equal(await atServer.open(await atClient.close()), null);
  atServer.verifyEnd();
});

test('with rekey off the limit stops a direction, and a close still passes', async () => {
  const {atClient, atServer} = await sessions({keyLimit: 298, rekey: false});
  const message = new Uint8Array(100);
  const [first, second] = [await atClient.seal(message), await atClient.seal(message)];
  await assert.rejects(() => atClient.seal(message), /limit/);
  await assert.rejects(() => atClient.seal(Uint8Array.of(1)), /limit/);
  await atServer.open(first);
  await atServer.open(second);
  assert.equal(await atServer.open(await atClient.close()), null);
  atServer.verifyEnd();
});

test('with rekey on the key changes at the limit, and the stream goes on', async () => {
  const {atClient, atServer} = await sessions({keyLimit: 298});
  const lengths = [];
  for (let index = 0; index < 7; index += 1) {
    const message = new Uint8Array(100).fill(index);
    const record = await atClient.seal(message);
    lengths.push(record.length);
    assert.deepEqual(await atServer.open(record), message);
  }
  assert.deepEqual(lengths, [119, 119, 138, 119, 138, 119, 138]);
  assert.equal(await atServer.open(await atClient.close()), null);
  atServer.verifyEnd();
});

test('a key change inside a long record keeps every key under the limit', async () => {
  const {atClient, atServer} = await sessions({keyLimit: 70000});
  const message = new Uint8Array(200000).fill(9);
  assert.deepEqual(await atServer.open(await atClient.seal(message)), message);
});

test('a long record refused at the limit leaves the session as it was', async () => {
  const {atClient, atServer} = await sessions({keyLimit: 70000, rekey: false});
  await assert.rejects(() => atClient.seal(new Uint8Array(200000)), /limit/);
  assert.equal(text(await atServer.open(await atClient.seal('after'))), 'after');
  const rekeying = await sessions({keyLimit: 1000});
  await assert.rejects(() => rekeying.atClient.seal(new Uint8Array(2000)), /limit/);
});

test("a lower limit is for one side's own sending only: a peer at the default is still opened", async () => {
  for (const lowSends of [false, true]) {
    const client = await generateIdentity();
    const server = await generateIdentity();
    const i = await createInitiator(client, server.peerId, {rekey: false});
    const r = await createResponder(server, {allowClient: async () => true, keyLimit: 200});
    const {atClient, atServer} = await through(asIs, {i, r});
    const [sender, receiver] = lowSends ? [atServer, atClient] : [atClient, atServer];
    for (let index = 0; index < 5; index += 1) {
      const message = new Uint8Array(100).fill(index);
      assert.deepEqual(await receiver.open(await sender.seal(message)), message);
    }
  }
});

test('a message length becomes the record length the sealer makes', async () => {
  const {atClient, atServer} = await sessions();
  const part = 65518;
  for (const length of [0, 1, part - 1, part, part + 1, 2 * part, 2 * part + 1, 2 ** 20, 2 ** 24]) {
    const record = await atClient.seal(new Uint8Array(length));
    assert.equal(record.length, recordLength(length), `a message of ${length}`);
    assert.equal((await atServer.open(record)).length, length);
  }
  assert.equal(recordLength(2 ** 20) - 2 ** 20, 323);
  assert.equal(recordLength(2 ** 24) - 2 ** 24, 4883);
  assert.equal(recordLength(65519) - 65519, 38);
  for (const bad of [-1, 1.5, NaN, '3', undefined]) assert.throws(() => recordLength(bad), RangeError);
});

test('supported() says the runtime has what the method needs, without a connection', async () => {
  assert.equal(await supported(), true);
  const real = globalThis.crypto;
  const without = {getRandomValues: real.getRandomValues.bind(real), subtle: undefined};
  Object.defineProperty(globalThis, 'crypto', {value: without, configurable: true});
  try {
    assert.equal(await supported(), false);
  } finally {
    Object.defineProperty(globalThis, 'crypto', {value: real, configurable: true});
  }
  const broken = {
    getRandomValues: real.getRandomValues.bind(real),
    subtle: new Proxy(real.subtle, {get: (target, name) => name === 'generateKey' ? () => Promise.reject(new Error('X25519')) : target[name]?.bind(target)}),
  };
  Object.defineProperty(globalThis, 'crypto', {value: broken, configurable: true});
  try {
    assert.equal(await supported(), false);
  } finally {
    Object.defineProperty(globalThis, 'crypto', {value: real, configurable: true});
  }
});

test('a Buffer binding is copied when the call is made, not viewed', async () => {
  const client = await generateIdentity();
  const server = await generateIdentity();
  const allow = async id => id === client.peerId;
  const [one, two] = [Buffer.from([1, 2, 3]), Buffer.from([4, 5, 6])];
  const starting = createInitiator(client, server.peerId, {binding: one});
  one.fill(0);
  const answering = createResponder(server, {allowClient: allow, binding: two});
  two.fill(0);
  const [i, r] = await Promise.all([starting, answering]);
  await assert.rejects(async () => i.answer(await r.challenge(await i.hello())), /does not decrypt/);
});

test('settings are checked, and the default limit is 2^38', async () => {
  assert.equal(DEFAULT_KEY_LIMIT, 2 ** 38);
  const client = await generateIdentity();
  const server = await generateIdentity();
  await assert.rejects(() => createInitiator(client, server.peerId, {keyLimit: -1}), /keyLimit/);
  await assert.rejects(() => createInitiator(client, server.peerId, {keyLimit: 1.5}), /keyLimit/);
  await assert.rejects(() => createInitiator(client, server.peerId, {rekey: 'yes'}), /rekey/);
});

test('seal and open read their input when called', async () => {
  const {atClient, atServer} = await sessions();
  const buffer = new TextEncoder().encode('original');
  const sealing = atClient.seal(buffer);
  buffer.fill(0);
  const record = await sealing;
  const opening = atServer.open(record);
  record.fill(0);
  assert.equal(text(await opening), 'original');
});

test('calls made together keep their order', async () => {
  const {atClient, atServer} = await sessions();
  const records = await Promise.all([atClient.seal('1'), atClient.seal('2'), atClient.seal('3')]);
  const opened = await Promise.all(records.map(record => atServer.open(record)));
  assert.deepEqual(opened.map(text), ['1', '2', '3']);
});

test('a destroyed session does nothing more', async () => {
  const {atClient} = await sessions();
  atClient.destroy();
  await assert.rejects(() => atClient.seal('x'), /session is over/);
  await assert.rejects(() => atClient.open(new Uint8Array(19)), /session is over/);
  await assert.rejects(() => atClient.export('label', 32), /session is over/);
  assert.throws(() => atClient.verifyEnd(), /session is over/);
});

test('exports of one label and two lengths are unrelated, and their length is bounded', async () => {
  const {atClient} = await sessions();
  const [short, long, other] = [
    await atClient.export('label', 16), await atClient.export('label', 32), await atClient.export('other', 32),
  ];
  assert.notDeepEqual(short, long.subarray(0, 16));
  assert.notDeepEqual(long, other);
  await assert.rejects(() => atClient.export('label', 8161), /8160/);
  assert.equal((await atClient.export('label', 8160)).length, 8160);
  assert.equal((await atClient.export('label', 0)).length, 0);
});

test('a handshake step taken twice, or out of its place, is refused', async () => {
  let p = await parties();
  await p.i.hello();
  await assert.rejects(() => p.i.hello(), /Unexpected/);
  p = await parties();
  await assert.rejects(() => p.i.answer(new Uint8Array(96)), /Unexpected/);
  await assert.rejects(() => p.r.accept(new Uint8Array(64)), /Unexpected/);
});

test('a handshake message that is not bytes is refused', async () => {
  const p = await parties();
  await assert.rejects(() => p.r.challenge('text of the right length, 32 ...'), /Expected bytes/);
});

test('allowClient admits only on exactly true', async () => {
  for (const answer of [1, 'yes', {}, undefined, false]) {
    const client = await generateIdentity();
    const server = await generateIdentity();
    const i = await createInitiator(client, server.peerId);
    const r = await createResponder(server, {allowClient: async () => answer});
    const {reply} = await i.answer(await r.challenge(await i.hello()));
    await assert.rejects(() => r.accept(reply), /not paired/);
  }
});

test('the ephemeral keys are not kept once the handshake ends', async () => {
  setFlagsFromString('--expose-gc');
  const collect = runInNewContext('gc');
  const client = await generateIdentity();
  const server = await generateIdentity();
  const refs = {};
  const tracked = name => async () => {
    const pair = await webcrypto.subtle.generateKey('X25519', false, ['deriveBits']);
    refs[name] = new WeakRef(pair.privateKey);
    return pair;
  };
  const i = await createInitiator(client, server.peerId, {ephemeral: tracked('initiator')});
  const r = await createResponder(server, {allowClient: async () => true, ephemeral: tracked('responder')});
  const {atClient, atServer} = await through(asIs, {i, r});
  for (let round = 0; round < 10 && (refs.initiator.deref() || refs.responder.deref()); round += 1) {
    await new Promise(resolve => setImmediate(resolve));
    collect();
  }
  assert.equal(refs.initiator.deref(), undefined);
  assert.equal(refs.responder.deref(), undefined);
  // The handshake objects and sessions are still alive here.
  assert.ok(i && r && atClient && atServer);
});

test('the last nonces of a direction end the session rather than reach the reserved one', async () => {
  const key = new Uint8Array(32).fill(3);
  const settings = {keyLimit: DEFAULT_KEY_LIMIT, rekey: true};
  const start = async nonce => __testing.createSession({
    h: new Uint8Array(32),
    initiatorToResponder: await __testing.newCipher(key, nonce),
    responderToInitiator: await __testing.newCipher(key, nonce),
    exporter: new Uint8Array(32),
  }, true, settings);
  const enough = await start(0xfffffffffffffffdn);
  await enough.seal('fits: two nonces are left for it');
  await assert.rejects(() => enough.seal('no more'), /limit/);
  await assert.rejects(() => enough.seal('over'), /session is over/);
  const none = await start(0xffffffffffffffffn);
  await assert.rejects(() => none.open(new Uint8Array(40).fill(0).map((_, index) => (index === 1 ? 17 : 0))), /does not open/);
  await assert.rejects(() => none.close(), /session is over/);
});
