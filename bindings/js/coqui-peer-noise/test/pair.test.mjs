// PIN pairing in JavaScript: the Edwards25519 arithmetic against independent answers, SPAKE2 against the
// `spake2` crate's own known answer, the whole exchange byte for byte against Rust's records, and the
// exchange itself: wrong PINs, retries and relays.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {webcrypto} from 'node:crypto';
import {
  createInitiator, createPairingDesk, createPairingInitiator, createPairingResponder, createResponder,
  DEFAULT_FIRST_MESSAGE_TIMEOUT, DEFAULT_KEY_LIMIT, generateIdentity, importIdentity, MAX_PAIRING_RECORD, PROFILE, __testing,
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

test('a scalar\'s length does not show in the time of its multiplication', () => {
  // One coarse check of one signal, and BigInt promises nothing about time. Interleaved, so that drift
  // falls on both, and against the largest gap in length there is.
  const median = values => values.slice().sort((a, b) => a - b)[values.length >> 1];
  const timed = scalar => {
    const started = process.hrtime.bigint();
    pointMul(BASE, scalar);
    return Number(process.hrtime.bigint() - started);
  };
  const [one, most] = [[], []];
  for (let round = 0; round < 150; round += 1) {
    const [a, b] = [timed(1n), timed(L - 1n)];
    if (round >= 30) {
      one.push(a);
      most.push(b);
    }
  }
  const ratio = median(one) / median(most);
  assert.ok(ratio > 0.85 && ratio < 1.15, `a one-bit scalar took ${ratio} of the time of a 253-bit one`);
});

test('a multiplication is what repeated addition gives, torsion and the largest scalars included', () => {
  const byAddition = (point, scalar) => {
    let [result, add] = [pointMul(BASE, 0n), point];
    for (let rest = scalar; rest > 0n; rest >>= 1n) {
      if (rest & 1n) result = pointAdd(result, add);
      add = pointAdd(add, add);
    }
    return result;
  };
  const eighth = decompress(unhex('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'));
  assert.equal(toHex(compress(pointMul(eighth, 8n))), `01${'00'.repeat(31)}`, 'a point of order 8');
  assert.notEqual(toHex(compress(pointMul(eighth, 4n))), `01${'00'.repeat(31)}`);
  const scalars = [
    0n, 1n, 2n, 7n, 8n, 9n, 1234567n, 2n ** 128n, L - 1n, L, L + 1n, 8n * L - 1n, 8n * L, 2n ** 255n, 2n ** 256n - 1n,
  ];
  for (const point of [BASE, eighth, pointAdd(BASE, eighth)]) {
    for (const scalar of scalars) {
      assert.equal(toHex(compress(pointMul(point, scalar))), toHex(compress(byAddition(point, scalar))), String(scalar));
    }
  }
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

test('a run of one purpose fails at the second message against the other', async () => {
  const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
  // A client pinning the bridge, sent to the bridge's pairing endpoint.
  const client = await createInitiator(joiner, responder.peerId);
  const pairing = await createPairingResponder(responder);
  await assert.rejects(async () => client.answer(await pairing.challenge(await client.hello())), /does not decrypt/);
  // A joiner sent to the ordinary endpoint of a bridge that already trusts it.
  const stranger = await createPairingInitiator(joiner);
  const ordinary = await createResponder(responder, {allowClient: async () => true});
  await assert.rejects(async () => stranger.answer(await ordinary.challenge(await stranger.hello())), /does not decrypt/);
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

/** `promise`, or a failure saying it was still pending after `ms`. */
function settlesWithin(promise, ms) {
  let timer;
  const late = new Promise((_, reject) => {
    timer = setTimeout(reject, ms, new Error(`still pending after ${ms} ms`));
  });
  return Promise.race([promise, late]).finally(() => clearTimeout(timer));
}

test('a stranger who says nothing ends at the desk\'s time, and is told it expired', async () => {
  const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
  const desk = createPairingDesk({pinTtl: 100});
  desk.showPin();
  const {atJoiner, atResponder} = await strangers(joiner, responder);
  const [a, b, close] = pipe();
  const started = Date.now();
  await assert.rejects(
    settlesWithin(atResponder.respond(desk, b, {accept: async () => assert.fail('not accepted')}), 1500),
    {refusal: 'expired'},
  );
  assert.ok(Date.now() - started < 1000);
  // What a joiner that speaks up now hears.
  await assert.rejects(atJoiner.join('123456', a), {refusal: 'expired'});
  close();
});

test('the first message has its own bound, under the desk\'s, and nothing below it is refused', async () => {
  const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
  const desk = createPairingDesk();
  desk.showPin();
  const quiet = async firstMessageTimeout => {
    const {atResponder} = await strangers(joiner, responder, {responding: {firstMessageTimeout}});
    const [, b] = pipe();
    const started = Date.now();
    await assert.rejects(
      settlesWithin(atResponder.respond(desk, b, {accept: async () => assert.fail('not accepted')}), 1500),
      {refusal: 'expired'},
    );
    return Date.now() - started;
  };
  assert.ok(await quiet(100) < 1000);
  assert.ok(await quiet(0) < 1000);
  for (const bad of [-1, NaN, '5', null]) {
    await assert.rejects(createPairingResponder(responder, {firstMessageTimeout: bad}), /no meaning/, String(bad));
  }
});

test('a first message timeout of zero reads nothing, even with a message waiting', async () => {
  const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
  const desk = createPairingDesk();
  desk.showPin();
  const {atResponder} = await strangers(joiner, responder, {responding: {firstMessageTimeout: 0}});
  let reads = 0;
  const sent = [];
  const transport = {
    async send(bytes) { sent.push(bytes); },
    async recv() { reads += 1; return new Uint8Array(32); },
  };
  await assert.rejects(atResponder.respond(desk, transport, {accept: async () => assert.fail('not accepted')}), {refusal: 'expired'});
  assert.equal(reads, 0);
  assert.equal(sent.length, 1);
});

test('a time too long for a timer is not taken for no time at all', async () => {
  const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
  const desk = createPairingDesk({pinTtl: 2 ** 40});
  const {pin} = desk.showPin();
  const {atJoiner, atResponder} = await strangers(joiner, responder, {responding: {firstMessageTimeout: 2 ** 40}});
  const [a, b, close] = pipe();
  const gate = {
    async send(bytes) { await a.send(bytes); },
    async recv() { await new Promise(resolve => { setTimeout(resolve, 30); }); return a.recv(); },
  };
  const [joined, served] = await settled(
    close, atJoiner.join(pin, gate), atResponder.respond(desk, b, {accept: async () => {}}),
  );
  assert.equal(joined.status, 'fulfilled', joined.reason?.stack);
  assert.equal(served.status, 'fulfilled', served.reason?.stack);
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

// A peer that follows nothing: the layer beneath the method on the pairing prologue, whose session has
// `seal` and `open`, so it can say anything in the exchange. The transcript and keys here are this file's
// own, written from PROTOCOL.md apart from what the module does.
const asBytes = text => encoder.encode(text);
const short = bytes => Uint8Array.from([bytes.length, ...bytes]);
const wide = bytes => Uint8Array.from([0, 0, 0, bytes.length, ...bytes]);
const keyOf = identity => {
  const spki = Buffer.from(identity.publicKey, 'base64url');
  return Uint8Array.from([...short(asBytes('noise')), ...short(asBytes('PUBLIC KEY')), ...wide(spki)]);
};
const plain = (...parts) => Uint8Array.from(parts.flatMap(part => (typeof part === 'number' ? [part] : [...part])));
const NO_SLOT = 0xff;
const TYPED = 1;
const refusedWith = byte => `0108${byte.toString(16).padStart(2, '0')}`;

const pairingPrologue = () => plain(...[asBytes(PROFILE), asBytes('pair'), new Uint8Array()].map(wide));

async function unrulyHandshake(initiator, identity) {
  const pair = await webcrypto.subtle.generateKey('X25519', false, ['deriveBits']);
  const ephemeral = {privateKey: pair.privateKey, public: new Uint8Array(await webcrypto.subtle.exportKey('raw', pair.publicKey))};
  const local = {privateKey: identity.privateKey, public: Uint8Array.from(Buffer.from(identity.publicKey, 'base64url').subarray(12))};
  return __testing.newHandshake(initiator, pairingPrologue(), local, ephemeral);
}

const unrulySession = async (handshake, initiator) => __testing.createSession(
  await handshake.split(), initiator, {keyLimit: DEFAULT_KEY_LIMIT, rekey: true},
);

async function againstResponder(joiner, responder) {
  const near = await unrulyHandshake(true, joiner);
  const far = await createPairingResponder(responder);
  const payload = new Uint8Array();
  await near.readMessage(await far.challenge(await near.writeMessage(payload)));
  const {pairing} = await far.accept(await near.writeMessage(payload));
  return {session: await unrulySession(near, true), pairing};
}

async function againstJoiner(joiner, responder) {
  const near = await createPairingInitiator(joiner);
  const far = await unrulyHandshake(false, responder);
  const payload = new Uint8Array();
  await far.readMessage(await near.hello());
  const {reply, pairing} = await near.answer(await far.writeMessage(payload));
  await far.readMessage(reply);
  return {session: await unrulySession(far, false), pairing};
}

const talking = (session, end) => ({
  send: async message => end.send(await session.seal(message)),
  recv: async () => session.open(await end.recv()),
});

async function confirmations(shared, transcript) {
  const key = async info => {
    const ikm = await webcrypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
    const bits = await webcrypto.subtle.deriveBits(
      {name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info: asBytes(info)}, ikm, 256,
    );
    return webcrypto.subtle.importKey('raw', bits, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  };
  const mac = async name => new Uint8Array(await webcrypto.subtle.sign('HMAC', await key(`coqui-pair ${name} confirmation`), transcript));
  return {joiner: await mac('joiner'), responder: await mac('responder')};
}

const transcriptOf = (joiner, responder, joinerMessage, responderMessage, binding) => plain(
  asBytes('coqui-pair pin'), keyOf(joiner), keyOf(responder), NO_SLOT, short(joinerMessage), short(responderMessage), 1, wide(binding),
);

/** A joiner computing everything itself, up to the confirmation it is told to send. */
async function joinerByHand(pin, {binding, tag} = {}) {
  const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
  const desk = createPairingDesk();
  desk.showPin();
  const {session, pairing} = await againstResponder(joiner, responder);
  const [a, b, close] = pipe();
  const accepted = [];
  const serving = pairing.respond(desk, b, {accept: async id => { accepted.push(id); }}).finally(close);
  const peer = talking(session, a);
  await peer.send(plain(1, 1, TYPED, keyOf(joiner)));
  assert.equal(toHex(await peer.recv()), toHex(plain(1, 2, keyOf(responder), NO_SLOT)));
  const {state, message} = await spakeStartWith(
    true, asBytes(pin(desk)), asBytes(joiner.peerId), asBytes(responder.peerId), 1234567n,
  );
  await peer.send(plain(1, 3, short(message)));
  const reply = await peer.recv();
  assert.equal(toHex(reply.subarray(0, 3)), '010421');
  const received = reply.subarray(3, 36);
  const shared = await spakeFinish(state, received);
  const realBinding = await session.export('EXPORTER-coqui-pair', 32);
  const transcript = transcriptOf(joiner, responder, message, received, binding ?? realBinding);
  const macs = await confirmations(shared, transcript);
  return {joiner, responder, peer, serving, accepted, macs, reply, sendTag: () => peer.send(plain(1, 5, tag ?? macs.joiner))};
}

test('a joiner computing everything itself is accepted, so what the refusals below refuse is only what they change', async () => {
  let shown;
  const run = await joinerByHand(desk => { shown = desk.shownPin().pin; return shown; });
  assert.equal(toHex(run.reply.subarray(36)), toHex(run.macs.responder), 'the responder\'s MAC is the one PROTOCOL.md gives');
  await run.sendTag();
  assert.equal((await run.serving).peerId, run.joiner.peerId);
  assert.deepEqual(run.accepted, [run.joiner.peerId]);
});

test('a responder refuses a confirmation that is not the MAC, and accepts nobody', async () => {
  const run = await joinerByHand(desk => desk.shownPin().pin, {tag: new Uint8Array(32)});
  await run.sendTag();
  await assert.rejects(run.serving, {refusal: 'wrong-code'});
  assert.deepEqual(run.accepted, []);
});

test('a responder refuses a confirmation made under another session\'s binding', async () => {
  const run = await joinerByHand(desk => desk.shownPin().pin, {binding: new Uint8Array(32).fill(7)});
  await run.sendTag();
  await assert.rejects(run.serving, {refusal: 'wrong-code'});
  assert.deepEqual(run.accepted, []);
});

test('a responder refuses a confirmation sent for the wrong side: the two keys differ', async () => {
  const run = await joinerByHand(desk => desk.shownPin().pin);
  await run.peer.send(plain(1, 5, run.macs.responder));
  await assert.rejects(run.serving, {refusal: 'wrong-code'});
  assert.deepEqual(run.accepted, []);
});

test('a confirmation with no PIN behind it does not pass: right bytes need the right PIN', async () => {
  const run = await joinerByHand(desk => other(desk.shownPin().pin));
  await run.sendTag();
  await assert.rejects(run.serving, {refusal: 'wrong-code'});
  assert.deepEqual(run.accepted, []);
});

test('a record longer than any of the exchange is refused before it is opened, in both roles', async () => {
  const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
  const desk = createPairingDesk();
  desk.showPin();
  const fed = (record, sent = []) => ({async send(bytes) { sent.push(bytes); }, async recv() { return record; }});
  const serve = async record => {
    const {atResponder} = await strangers(joiner, responder);
    return atResponder.respond(desk, fed(record), {accept: async () => assert.fail('not accepted')});
  };
  const join = async record => {
    const {atJoiner} = await strangers(joiner, responder);
    return atJoiner.join('123456', fed(record));
  };
  for (const run of [serve, join]) {
    for (const record of [new Uint8Array(MAX_PAIRING_RECORD + 1), new ArrayBuffer(MAX_PAIRING_RECORD + 1)]) {
      await assert.rejects(run(record), /malformed/, 'not opened: a bad record says it does not open');
    }
    // At the limit it is opened, and fails as any bad record does.
    await assert.rejects(run(new Uint8Array(MAX_PAIRING_RECORD)), /does not open/);
  }
  assert.equal(MAX_PAIRING_RECORD, 350);
  // A whole sealed record of 32 MiB, from a peer that proved any key, is refused the same way.
  const {session, pairing} = await againstResponder(joiner, responder);
  const huge = await session.seal(new Uint8Array(32 << 20));
  await assert.rejects(pairing.respond(desk, fed(huge), {accept: async () => assert.fail('not accepted')}), /malformed/);
});

test('nonDefaults() names each setting that differs from its default by its Rust key path, and nothing else', async () => {
  const [a, b] = [await generateIdentity(), await generateIdentity()];
  const names = object => object.nonDefaults().map(({setting}) => setting);
  const replaced = async () => webcrypto.subtle.generateKey('X25519', false, ['deriveBits']);
  assert.deepEqual(names(await createInitiator(a, b.peerId)), []);
  assert.deepEqual(names(await createInitiator(a, b.peerId, {keyLimit: DEFAULT_KEY_LIMIT})), []);
  assert.deepEqual(names(await createInitiator(a, b.peerId, {keyLimit: 16})), ['key_limit']);
  assert.deepEqual(names(await createInitiator(a, b.peerId, {keyLimit: DEFAULT_KEY_LIMIT + 1})), ['key_limit']);
  assert.deepEqual(names(await createInitiator(a, b.peerId, {rekey: false})), ['rekey']);
  assert.deepEqual(names(await createInitiator(a, b.peerId, {ephemeral: replaced})), ['ephemeral']);
  assert.deepEqual(names(await createResponder(b, {allowClient: async () => true, rekey: false})), ['rekey']);
  assert.deepEqual((await createInitiator(a, b.peerId, {rekey: false})).nonDefaults(), [{setting: 'rekey', value: 'false', default: 'true'}]);
  assert.deepEqual(
    (await createInitiator(a, b.peerId, {keyLimit: 16})).nonDefaults(),
    [{setting: 'key_limit', value: '16', default: String(DEFAULT_KEY_LIMIT)}],
  );

  // Admitting any proved key is what pairing is: it is not listed.
  assert.deepEqual(names(await createPairingInitiator(a)), []);
  assert.deepEqual(names(await createPairingInitiator(a, {responder: b.peerId})), []);
  assert.deepEqual(names(await createPairingInitiator(a, {responder: b.peerId, random: () => new Uint8Array(64)})), ['random']);
  assert.deepEqual(names(await createPairingResponder(b)), []);
  assert.deepEqual(names(await createPairingResponder(b, {firstMessageTimeout: 0})), ['first_message_timeout']);
  assert.deepEqual(names(await createPairingResponder(b, {firstMessageTimeout: DEFAULT_FIRST_MESSAGE_TIMEOUT})), []);
  assert.deepEqual(
    names(await createPairingResponder(b, {firstMessageTimeout: DEFAULT_FIRST_MESSAGE_TIMEOUT + 1, rekey: false})),
    ['rekey', 'first_message_timeout'],
  );
  assert.deepEqual(
    (await createPairingResponder(b, {firstMessageTimeout: 1500})).nonDefaults(),
    [{setting: 'first_message_timeout', value: '[1,500000000]', default: '[60,0]'}],
  );

  // The desk, by what a guess's chance and a PIN's life come to.
  assert.deepEqual(names(createPairingDesk()), []);
  assert.deepEqual(names(createPairingDesk({pinLength: 7, pinTtl: 1})), []);
  assert.deepEqual(names(createPairingDesk({pinLength: 1})), ['pinCombinations']);
  assert.deepEqual(createPairingDesk({pinLength: 1}).nonDefaults(), [{setting: 'pinCombinations', value: '10', default: '1000000'}]);
  assert.deepEqual(names(createPairingDesk({pinAlphabet: '01'})), ['pinCombinations']);
  assert.deepEqual(names(createPairingDesk({pinAlphabet: '01', pinLength: 20})), []);
  assert.deepEqual(names(createPairingDesk({pinAttempts: 2})), ['pinAttempts']);
  assert.deepEqual(names(createPairingDesk({pinTtl: 600_001})), ['pinTtl']);
  assert.deepEqual(names(createPairingDesk({random: () => new Uint8Array(4)})), ['random']);
  assert.deepEqual(names(createPairingDesk({now: () => 0})), ['now']);
});

/** The responder's answer to a first message, with a desk that has a PIN unless told otherwise. */
async function helloRefused(message, {show = true} = {}) {
  const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
  const desk = createPairingDesk();
  if (show) desk.showPin();
  const {session, pairing} = await againstResponder(joiner, responder);
  const [a, b, close] = pipe();
  const serving = pairing.respond(desk, b, {accept: async () => assert.fail('not accepted')})
    .then(() => 'served', error => error).finally(close);
  const peer = talking(session, a);
  await peer.send(message(joiner));
  const answer = await peer.recv().catch(() => null);
  const outcome = await serving;
  return {answer: answer && toHex(answer), outcome};
}

test('a first message of another version, with more after it, or naming another key, ends it with no answer', async () => {
  const stranger = await generateIdentity();
  for (const [name, message] of [
    ['version', joiner => plain(2, 1, TYPED, keyOf(joiner))],
    ['more', joiner => plain(1, 1, TYPED, keyOf(joiner), 0)],
    ['key', () => plain(1, 1, TYPED, keyOf(stranger))],
    ['mode', joiner => plain(1, 1, 9, keyOf(joiner))],
    ['kind', joiner => plain(1, 3, TYPED, keyOf(joiner))],
  ]) {
    const {answer, outcome} = await helloRefused(message);
    assert.equal(answer, null, name);
    assert.match(outcome.message, /malformed/, name);
    assert.equal(outcome.refusal, undefined, name);
  }
});

test('a responder with no PIN refuses at the first message, and sends no ready', async () => {
  const {answer, outcome} = await helloRefused(joiner => plain(1, 1, TYPED, keyOf(joiner)), {show: false});
  assert.equal(answer, refusedWith(3));
  assert.equal(outcome.refusal, 'exhausted');
});

test('a responder refuses the modes it does not offer, as disabled', async () => {
  for (const mode of [0, 2, 3]) {
    const {answer, outcome} = await helloRefused(joiner => plain(1, 1, mode, keyOf(joiner)));
    assert.equal(answer, refusedWith(6), String(mode));
    assert.equal(outcome.refusal, 'disabled', String(mode));
  }
});

test('a message that arrives after the deadline is refused, even when the timer has not fired', async () => {
  const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
  let clock = 1000;
  const desk = createPairingDesk({pinTtl: 60_000, now: () => clock});
  desk.showPin();
  const {session, pairing} = await againstResponder(joiner, responder);
  const [a, b, close] = pipe();
  const serving = pairing.respond(desk, b, {accept: async () => assert.fail('not accepted')})
    .then(() => 'served', error => error).finally(close);
  const peer = talking(session, a);
  await peer.send(plain(1, 1, TYPED, keyOf(joiner)));
  await peer.recv();
  clock += 60_000;
  // A PIN shown just now is alive: what has run out is this exchange's time.
  assert.notEqual(desk.showPin().expires, clock);
  const {message} = await spakeStartWith(true, asBytes('123456'), asBytes(joiner.peerId), asBytes(responder.peerId), 5n);
  await peer.send(plain(1, 3, short(message)));
  assert.equal(toHex(await peer.recv()), refusedWith(2), 'no reply, and no attempt taken');
  assert.notEqual(desk.shownPin(), null);
  assert.equal((await serving).refusal, 'expired');
});

test('a joiner refuses a key it did not prove, more after a message, and a close in the middle', async () => {
  const stranger = await generateIdentity();
  const run = async answer => {
    const [joiner, responder] = [await generateIdentity(), await generateIdentity()];
    const {session, pairing} = await againstJoiner(joiner, responder);
    const [a, b, close] = pipe();
    const joining = pairing.join('123456', a).finally(close);
    await session.open(await b.recv());
    await answer(session, b, responder);
    return joining;
  };
  const say = message => async (session, end) => end.send(await session.seal(message));
  await assert.rejects(run(say(plain(1, 2, keyOf(stranger), NO_SLOT))), /malformed/);
  await assert.rejects(run((session, end, responder) => say(plain(1, 2, keyOf(responder), NO_SLOT, 0))(session, end)), /malformed/);
  await assert.rejects(run((session, end, responder) => say(plain(1, 2, keyOf(responder), 3))(session, end)), /malformed/);
  await assert.rejects(run((session, end, responder) => say(plain(2, 2, keyOf(responder), NO_SLOT))(session, end)), /malformed/);
  await assert.rejects(run(say(plain(1, 7, keyOf(stranger)))), /malformed/);
  await assert.rejects(run(say(plain(1, 8, 6))), {refusal: 'disabled'});
  await assert.rejects(run(say(plain(1, 8, 99))), /malformed/);
  await assert.rejects(run(async (session, end) => end.send(await session.close())), /truncated/);
});

test('a joiner refuses a responder whose last message names another key', async () => {
  const [joiner, responder, stranger] = [await generateIdentity(), await generateIdentity(), await generateIdentity()];
  const {session, pairing} = await againstJoiner(joiner, responder);
  const [a, b, close] = pipe();
  const joining = pairing.join('123456', a).finally(close);
  const peer = talking(session, b);
  await peer.recv();
  await peer.send(plain(1, 2, keyOf(responder), NO_SLOT));
  const pake = await peer.recv();
  const received = pake.subarray(3);
  const {state, message} = await spakeStartWith(false, asBytes('123456'), asBytes(joiner.peerId), asBytes(responder.peerId), 9n);
  const shared = await spakeFinish(state, received);
  const binding = await session.export('EXPORTER-coqui-pair', 32);
  const macs = await confirmations(shared, transcriptOf(joiner, responder, received, message, binding));
  await peer.send(plain(1, 4, short(message), macs.responder));
  const confirm = await peer.recv();
  assert.equal(toHex(confirm), toHex(plain(1, 5, macs.joiner)), 'its MAC is the one PROTOCOL.md gives');
  await peer.send(plain(1, 7, keyOf(stranger)));
  await assert.rejects(joining, /malformed/);
});

test('a desk draws without bias: a word above the last whole multiple is drawn again', () => {
  const words = [[0xff, 0xff, 0xff, 0xff], [0, 0, 0, 1]];
  const desk = createPairingDesk({pinAlphabet: 'abc', pinLength: 1, random: () => Uint8Array.from(words.shift())});
  assert.equal(desk.showPin().pin, 'b');
  assert.equal(words.length, 0);
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

