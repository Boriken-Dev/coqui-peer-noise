// PIN pairing in JavaScript: the Edwards25519 arithmetic against independent answers, SPAKE2 against the
// `spake2` crate's own known answer, the whole exchange byte for byte against Rust's records, and the
// exchange itself: wrong PINs, retries and relays.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {webcrypto} from 'node:crypto';
import {
  createInitiator, createPairingDesk, createPairingInitiator, createPairingResponder, createResponder,
  generateIdentity, importIdentity, __testing,
} from '../src/index.mjs';
import {keyPairOf, toHex, unhex} from './support.mjs';

const vectors = name => JSON.parse(readFileSync(new URL(`../../../../tests/vectors/${name}.json`, import.meta.url)));
const {BASE, L, P, CURVE_D, SQRT_M1, compress, decompress, pointAdd, pointMul, passwordScalar, spakeStartWith, spakeFinish} = __testing;
const encoder = new TextEncoder();

test('the curve constants are what their definitions give', () => {
  const inverse = value => {
    let [result, square, rest] = [1n, value % P, P - 2n];
    while (rest > 0n) {
      if (rest & 1n) result = result * square % P;
      square = square * square % P;
      rest >>= 1n;
    }
    return result;
  };
  assert.equal(CURVE_D, (P - 121665n * inverse(121666n) % P) % P);
  assert.equal(SQRT_M1 * SQRT_M1 % P, P - 1n);
  assert.equal(toHex(compress(BASE)), '5866666666666666666666666666666666666666666666666666666666666666');
});

test('a point times a scalar is what Node\'s Ed25519 gives as a public key', async () => {
  for (const fill of [1, 7, 0x42, 0xfe]) {
    const seed = new Uint8Array(32).fill(fill);
    const pkcs8 = new Uint8Array([...unhex('302e020100300506032b657004220420'), ...seed]);
    const key = await webcrypto.subtle.importKey('pkcs8', pkcs8, 'Ed25519', true, ['sign']);
    const {x} = await webcrypto.subtle.exportKey('jwk', key);
    const hashed = new Uint8Array(await webcrypto.subtle.digest('SHA-512', seed)).slice(0, 32);
    hashed[0] &= 248;
    hashed[31] = (hashed[31] & 127) | 64;
    let scalar = 0n;
    for (const byte of [...hashed].reverse()) scalar = (scalar << 8n) | BigInt(byte);
    assert.equal(Buffer.from(compress(pointMul(BASE, scalar))).toString('base64url'), x);
  }
});

test('the group behaves: the order, addition, the identity, and a round trip of the encoding', () => {
  assert.equal(toHex(compress(pointMul(BASE, L))), '01' + '00'.repeat(31));
  const [a, b] = [12345678901234567890n, 98765432109876543210n];
  assert.deepEqual(compress(pointAdd(pointMul(BASE, a), pointMul(BASE, b))), compress(pointMul(BASE, a + b)));
  assert.deepEqual(compress(pointMul(BASE, 0n)), compress(pointMul(BASE, L)));
  assert.deepEqual(compress(decompress(compress(pointMul(BASE, a)))), compress(pointMul(BASE, a)));
});

test('an encoding that is not its point\'s one encoding is refused', () => {
  // y = p, and y = p + 1, each the same residue as a small value.
  const p = unhex('ed' + 'ff'.repeat(30) + '7f');
  const pPlusOne = unhex('ee' + 'ff'.repeat(30) + '7f');
  assert.equal(decompress(p), null);
  assert.equal(decompress(pPlusOne), null);
  // y = 1 has x = 0, so a set sign bit has no point to name.
  const signedZero = unhex('01' + '00'.repeat(30) + '80');
  assert.equal(decompress(signedZero), null);
  // y = 2 is not on the curve: u/v has no square root.
  assert.equal(decompress(unhex('02' + '00'.repeat(31))), null);
  assert.equal(decompress(new Uint8Array(31)), null);
  assert.equal(decompress(new Uint8Array(33)), null);
});

test('SPAKE2 reaches the `spake2` crate\'s own known answer in both roles', async () => {
  const known = vectors('spake2');
  const password = encoder.encode(known.password);
  const [idA, idB] = [encoder.encode(known.idA), encoder.encode(known.idB)];
  assert.equal(await passwordScalar(password), BigInt(known.passwordScalar));
  const a = await spakeStartWith(true, password, idA, idB, BigInt(known.scalarA));
  const b = await spakeStartWith(false, password, idA, idB, BigInt(known.scalarB));
  assert.equal(toHex(a.message), known.messageA);
  assert.equal(toHex(b.message), known.messageB);
  assert.equal(toHex(await spakeFinish(a.state, b.message)), known.key);
  assert.equal(toHex(await spakeFinish(b.state, a.message)), known.key);
});

test('SPAKE2 refuses a message of the wrong side, length or encoding, and a wrong password differs', async () => {
  const [idA, idB] = [encoder.encode('a'), encoder.encode('b')];
  const a = await spakeStartWith(true, encoder.encode('123456'), idA, idB, 77n);
  const b = await spakeStartWith(false, encoder.encode('123456'), idA, idB, 88n);
  const c = await spakeStartWith(false, encoder.encode('123457'), idA, idB, 88n);
  assert.equal(await spakeFinish(a.state, a.message), null, 'a reflected message');
  assert.equal(await spakeFinish(a.state, b.message.subarray(1)), null);
  const off = b.message.slice();
  off.set(unhex('ed' + 'ff'.repeat(30) + '7f'), 1);
  assert.equal(await spakeFinish(a.state, off), null);
  assert.notEqual(toHex(await spakeFinish(a.state, c.message)), toHex(await spakeFinish(c.state, a.message)));
  assert.equal(toHex(await spakeFinish(a.state, b.message)), toHex(await spakeFinish(b.state, a.message)));
});

/** Two ends of a transport; `tamper(direction, index, record)` sees each record, and null drops the rest. */
function pipe(tamper = (_, __, record) => record) {
  const lines = [[], []];
  const waiting = [[], []];
  const ended = [false, false];
  const counts = [0, 0];
  const deliver = (to, value) => {
    const waiter = waiting[to].shift();
    if (waiter) waiter(value);
    else lines[to].push(value);
  };
  const end = at => ({
    async send(bytes) {
      const to = 1 - at;
      if (ended[at]) return;
      const passed = tamper(at, counts[at]++, Uint8Array.from(bytes));
      if (passed === null) {
        ended[at] = true;
        deliver(to, null);
        deliver(at, null);
        return;
      }
      deliver(to, passed);
    },
    recv() {
      if (lines[at].length > 0) return Promise.resolve(lines[at].shift());
      return new Promise(resolve => waiting[at].push(resolve));
    },
  });
  return [end(0), end(1), () => {
    deliver(0, null);
    deliver(1, null);
  }];
}

/** Both sides to their end: one that stops closes the connection, as a host does. */
function settled(close, ...runs) {
  return Promise.allSettled(runs.map(run => run.finally(close)));
}

async function strangers(a, b, {joining = {}, responding = {}} = {}) {
  const near = await createPairingInitiator(a, joining);
  const far = await createPairingResponder(b, responding);
  const {reply, pairing: atJoiner} = await near.answer(await far.challenge(await near.hello()));
  const {pairing: atResponder} = await far.accept(reply);
  return {atJoiner, atResponder};
}

async function attempt(joiner, responder, desk, pin, {tamper, accepted = []} = {}) {
  const {atJoiner, atResponder} = await strangers(joiner, responder);
  const [a, b, close] = pipe(tamper);
  const [joined, served] = await settled(
    close,
    atJoiner.join(pin, a),
    atResponder.respond(desk, b, {accept: async id => { accepted.push(id); }}),
  );
  return {joined, served, accepted};
}

const other = pin => (pin === '000000' ? '000001' : '000000');

test('a pairing session holds a key and is nobody: it has no way to seal or open', async () => {
  const [a, b] = [await generateIdentity(), await generateIdentity()];
  const {atJoiner, atResponder} = await strangers(a, b);
  assert.deepEqual(atJoiner.id, atResponder.id);
  assert.equal(atJoiner.peer.publicKey, b.publicKey);
  assert.equal(atResponder.peer.publicKey, a.publicKey);
  assert.equal(atJoiner.verified, false);
  for (const name of ['seal', 'open', 'close', 'export', 'destroy', 'verifyEnd']) {
    assert.equal(atJoiner[name], undefined, name);
    assert.equal(atResponder[name], undefined, name);
  }
});

test('a typed PIN pairs two strangers, and the full key is proved afterwards', async () => {
  const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
  const desk = createPairingDesk();
  const {pin} = desk.showPin();
  assert.match(pin, /^[0-9]{6}$/);
  const {joined, served, accepted} = await attempt(joiner, responder, desk, pin);
  assert.equal(joined.status, 'fulfilled', joined.reason?.stack);
  assert.equal(served.status, 'fulfilled', served.reason?.stack);
  assert.equal(joined.value.peerId, responder.peerId);
  assert.equal(joined.value.peer.publicKey, responder.publicKey);
  assert.equal(joined.value.peer.method, 'noise');
  assert.equal(served.value.peerId, joiner.peerId);
  assert.deepEqual(accepted, [joiner.peerId]);
  assert.equal(desk.shownPin(), null, 'the PIN is used up');

  const near = await createInitiator(joiner, joined.value.peerId);
  const far = await createResponder(responder, {allowClient: async id => id === served.value.peerId});
  const {reply, session} = await near.answer(await far.challenge(await near.hello()));
  const {session: other} = await far.accept(reply);
  assert.equal(new TextDecoder().decode(await other.open(await session.seal('after pairing'))), 'after pairing');
});

test('a wrong PIN is refused at the confirmation, on both sides, and nobody is accepted', async () => {
  const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
  const desk = createPairingDesk();
  const {pin} = desk.showPin();
  const {joined, served, accepted} = await attempt(joiner, responder, desk, other(pin));
  assert.equal(joined.reason?.refusal, 'wrong-code');
  assert.equal(served.reason?.refusal, 'wrong-code');
  assert.deepEqual(accepted, []);
});

test('a wrong PIN uses up a PIN of one attempt: the right one after it is too late, and a new one pairs', async () => {
  const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
  const desk = createPairingDesk();
  const {pin} = desk.showPin();
  assert.equal((await attempt(joiner, responder, desk, other(pin))).joined.reason?.refusal, 'wrong-code');
  assert.equal(desk.shownPin(), null);
  const late = await attempt(joiner, responder, desk, pin);
  assert.equal(late.joined.reason?.refusal, 'exhausted');
  assert.equal(late.served.reason?.refusal, 'exhausted');
  assert.deepEqual(late.accepted, []);
  const again = await attempt(joiner, responder, desk, desk.showPin().pin);
  assert.equal(again.joined.status, 'fulfilled');
  assert.deepEqual(again.accepted, [joiner.peerId]);
});

test('a PIN of several attempts takes that many and no more', async () => {
  const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
  const desk = createPairingDesk({pinAttempts: 3});
  const {pin} = desk.showPin();
  for (let index = 0; index < 2; index += 1) {
    assert.equal((await attempt(joiner, responder, desk, other(pin))).joined.reason?.refusal, 'wrong-code');
  }
  assert.notEqual(desk.shownPin(), null);
  assert.equal((await attempt(joiner, responder, desk, pin)).joined.status, 'fulfilled');
  assert.equal(desk.shownPin(), null, 'every attempt counted');
});

test('a desk with no PIN refuses as used up, a PIN past its time as expired, and neither runs the PAKE', async () => {
  const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
  let clock = 1000;
  const desk = createPairingDesk({pinTtl: 50, now: () => clock});
  const none = await attempt(joiner, responder, desk, '123456');
  assert.equal(none.served.reason?.refusal, 'exhausted');
  const {pin} = desk.showPin();
  clock += 50;
  const late = await attempt(joiner, responder, desk, pin);
  assert.equal(late.joined.reason?.refusal, 'expired');
  assert.equal(late.served.reason?.refusal, 'expired');
});

test('a joiner that goes quiet is told the exchange expired', async () => {
  const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
  const desk = createPairingDesk({pinTtl: 100});
  desk.showPin();
  const {atJoiner, atResponder} = await strangers(joiner, responder);
  const [a, b, close] = pipe();
  const seen = [];
  // A joiner that sends its hello, then never answers: only the first message passes.
  const joining = atJoiner.join('123456', {
    send: async bytes => { if (seen.push(bytes) === 1) await a.send(bytes); },
    recv: () => a.recv(),
  }).catch(error => error);
  await assert.rejects(atResponder.respond(desk, b, {accept: async () => assert.fail('not accepted')}), {refusal: 'expired'});
  close();
  assert.equal((await joining).refusal, 'expired');
});

test('the desk\'s options have defaults and no floors, and meaningless ones are refused', () => {
  assert.match(createPairingDesk({pinLength: 1, pinAlphabet: 'x'}).showPin().pin, /^x$/);
  assert.match(createPairingDesk({pinLength: 12, pinAlphabet: 'AB'}).showPin().pin, /^[AB]{12}$/);
  for (const bad of [{pinLength: 0}, {pinAttempts: 0}, {pinTtl: 0}, {pinAlphabet: ''}, {pinAlphabet: 'aa'}]) {
    assert.throws(() => createPairingDesk(bad), /no meaning/, JSON.stringify(bad));
  }
});

test('a pairing session runs one exchange and needs its arguments', async () => {
  const [a, b] = [await generateIdentity(), await generateIdentity()];
  const {atJoiner, atResponder} = await strangers(a, b);
  const [x, y] = pipe();
  await assert.rejects(atJoiner.join('', x), /PIN is required/);
  await assert.rejects(atJoiner.join('123456', x), /one exchange/);
  await assert.rejects(atResponder.respond({}, y, {accept: async () => {}}), /desk is required/);
  await assert.rejects(atResponder.respond(createPairingDesk(), y, {accept: async () => {}}), /one exchange/);
});

test('a pinned responder is checked at the handshake, and the session is then verified', async () => {
  const [a, b, c] = [await generateIdentity(), await generateIdentity(), await generateIdentity()];
  const {atJoiner} = await strangers(a, b, {joining: {responder: b.peerId}});
  assert.equal(atJoiner.verified, true);
  await assert.rejects(strangers(a, c, {joining: {responder: b.peerId}}), /not pinned/);
});

test('a relay altering any sealed pairing record ends it with nobody accepted', async () => {
  for (const [direction, index] of [[0, 0], [0, 1], [0, 2], [1, 0], [1, 1], [1, 2]]) {
    const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
    const desk = createPairingDesk();
    const {joined, served, accepted} = await attempt(joiner, responder, desk, desk.showPin().pin, {
      tamper(from, at, record) {
        if (from === direction && at === index) record[record.length - 1] ^= 1;
        return record;
      },
    });
    assert.equal(joined.status, 'rejected', `${direction} ${index}`);
    assert.equal(served.status === 'rejected' || accepted.length === 1, true, `${direction} ${index}`);
    // Only the responder's DONE comes after the joiner's key is kept, and it does not change that.
    if (!(direction === 1 && index === 2)) assert.deepEqual(accepted, [], `${direction} ${index}`);
  }
});

test('a relay cutting the exchange before the confirmation leaves nobody accepted', async () => {
  const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
  const desk = createPairingDesk();
  const {joined, served, accepted} = await attempt(joiner, responder, desk, desk.showPin().pin, {
    tamper: (from, at, record) => (from === 0 && at === 2 ? null : record),
  });
  assert.match(joined.reason?.message, /truncated/);
  assert.match(served.reason?.message, /truncated/);
  assert.deepEqual(accepted, []);
});

test('a relay that runs the exchange with each side under its own key has one guess on each', async () => {
  const [joiner, responder, relay] = [await generateIdentity(), await generateIdentity(), await generateIdentity()];
  const desk = createPairingDesk();
  const {pin} = desk.showPin();
  const toRelay = await strangers(joiner, relay);
  const fromRelay = await strangers(relay, responder);
  // Each session proves the relay's key, so the relay runs the exchange itself, with a PIN of its own.
  const relayWorld = createPairingDesk();
  const relayPin = relayWorld.showPin().pin;
  assert.notEqual(relayPin, pin, 'a one in 10^6 chance');
  const [a, b, closeA] = pipe();
  const towardJoiner = await settled(
    closeA,
    toRelay.atJoiner.join(pin, a),
    toRelay.atResponder.respond(relayWorld, b, {accept: async () => assert.fail('not accepted')}),
  );
  assert.equal(towardJoiner[0].reason?.refusal, 'wrong-code');
  const [c, d, closeC] = pipe();
  const accepted = [];
  const towardResponder = await settled(
    closeC,
    fromRelay.atJoiner.join(other(pin), c),
    fromRelay.atResponder.respond(desk, d, {accept: async id => { accepted.push(id); }}),
  );
  assert.equal(towardResponder[1].reason?.refusal, 'wrong-code');
  assert.deepEqual(accepted, []);
  assert.equal(desk.shownPin(), null, 'its guess burned the PIN');
});

/** A whole run against the records Rust made: what this side sends must match them to the byte. */
function replay(side, run) {
  const ours = run[side];
  const theirs = run[side === 'joiner' ? 'responder' : 'joiner'];
  let [sent, read] = [0, 0];
  const transport = {
    async send(bytes) {
      assert.equal(toHex(bytes), ours[sent]?.record, `${side}'s record ${sent}`);
      sent += 1;
    },
    async recv() {
      const entry = theirs[read];
      read += 1;
      return entry ? unhex(entry.record) : null;
    },
  };
  return {transport, done: () => ({sent, expected: ours.length})};
}

async function vectorSessions(known) {
  const side = async entry => {
    const pair = await keyPairOf(unhex(entry.ephemeralPkcs8), unhex(entry.ephemeralPublic));
    return {identity: await importIdentity(unhex(entry.pkcs8)), ephemeral: async () => pair};
  };
  const [j, r] = [await side(known.joiner), await side(known.responder)];
  let draw = unhex(known.joinerPakeRandom);
  const random = length => {
    const out = draw.slice(0, length);
    draw = draw.slice(length);
    return out;
  };
  const near = await createPairingInitiator(j.identity, {ephemeral: j.ephemeral, random});
  const far = await createPairingResponder(r.identity, {ephemeral: r.ephemeral});
  assert.equal(toHex(await near.hello()), known.handshake[0]);
  assert.equal(toHex(await far.challenge(unhex(known.handshake[0]))), known.handshake[1]);
  const {reply, pairing: atJoiner, peerId} = await near.answer(unhex(known.handshake[1]));
  assert.equal(toHex(reply), known.handshake[2]);
  assert.equal(peerId, known.responder.peerId);
  const {pairing: atResponder} = await far.accept(unhex(known.handshake[2]));
  assert.equal(toHex(atJoiner.id), known.id);
  return {atJoiner, atResponder};
}

const deskOf = known => {
  let draw = unhex(known.deskRandom);
  return createPairingDesk({
    random(length) {
      const out = draw.slice(0, length);
      draw = draw.slice(length);
      return out;
    },
  });
};

test('Rust\'s records of a right PIN are reproduced to the byte by a JavaScript joiner', async () => {
  const known = vectors('pairing');
  const {atJoiner} = await vectorSessions(known);
  const {transport, done} = replay('joiner', known.right);
  const paired = await atJoiner.join(known.right.pin, transport);
  assert.equal(paired.peerId, known.responder.peerId);
  assert.deepEqual(done(), {sent: 4, expected: 4});
});

test('Rust\'s records of a right PIN are reproduced to the byte by a JavaScript responder', async () => {
  const known = vectors('pairing');
  const {atResponder} = await vectorSessions(known);
  const {transport, done} = replay('responder', known.right);
  const desk = deskOf(known);
  assert.equal(desk.showPin().pin, known.right.pin);
  const accepted = [];
  const paired = await atResponder.respond(desk, transport, {accept: async id => { accepted.push(id); }});
  assert.equal(paired.peerId, known.joiner.peerId);
  assert.deepEqual(accepted, [known.joiner.peerId]);
  assert.deepEqual(done(), {sent: 4, expected: 4});
});

test('Rust\'s records of a wrong PIN are reproduced to the byte, in both roles, ending in the refusal', async () => {
  const known = vectors('pairing');
  const {atJoiner, atResponder} = await vectorSessions(known);
  const joining = replay('joiner', known.wrong);
  await assert.rejects(atJoiner.join(known.wrong.pin, joining.transport), {refusal: 'wrong-code'});
  assert.deepEqual(joining.done(), {sent: 3, expected: 3});
  const responding = replay('responder', known.wrong);
  const desk = deskOf(known);
  desk.showPin();
  await assert.rejects(
    atResponder.respond(desk, responding.transport, {accept: async () => assert.fail('not accepted')}),
    {refusal: 'wrong-code'},
  );
  assert.deepEqual(responding.done(), {sent: 2, expected: 2});
});
