// PIN pairing between the languages, each in both roles, over real TCP: a right PIN, a wrong one and a
// retry, a relay that alters a sealed record, and the ordinary method afterwards under the key that was
// paired.
import test, {before} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {
  createInitiator, createPairingDesk, createPairingInitiator, createPairingResponder, createResponder,
  generateIdentity,
} from '../src/index.mjs';
import {buildPeer, dial, haveCargo, listen, startPairPeer, toHex, unavailable} from './support.mjs';

const cargo = haveCargo();

before(() => { if (cargo) buildPeer(); }, {timeout: 600_000});

const transportOf = channel => ({
  send: async bytes => channel.send(bytes),
  recv: () => channel.next(),
});

async function rustResponder() {
  const store = mkdtempSync(join(tmpdir(), 'coqui-pair-'));
  const peer = startPairPeer('responder', store);
  const {peerId} = JSON.parse(await peer.next());
  const port = Number(await peer.next());
  const {pin} = JSON.parse(await peer.next());
  return {
    peer, peerId, port, pin,
    close() {
      peer.child.kill();
      rmSync(store, {recursive: true, force: true, maxRetries: 10, retryDelay: 100});
    },
  };
}

/** One pairing attempt by a JavaScript joiner on its own connection. */
async function jsJoin(identity, port, pin, through = dial) {
  const socket = await through(port);
  try {
    const near = await createPairingInitiator(identity);
    socket.send(await near.hello());
    const {reply, pairing} = await near.answer(await socket.next());
    socket.send(reply);
    return await pairing.join(pin, transportOf(socket));
  } finally {
    socket.destroy();
  }
}

/** The ordinary method after pairing, against the Rust echo. */
async function jsEcho(identity, responderId, port, peer) {
  const socket = await dial(port);
  try {
    const initiator = await createInitiator(identity, responderId);
    socket.send(await initiator.hello());
    const {reply, session} = await initiator.answer(await socket.next());
    socket.send(reply);
    assert.deepEqual(JSON.parse(await peer.next()), {id: toHex(session.id)});
    socket.send(await session.seal('ping from javascript'));
    assert.equal(new TextDecoder().decode(await session.open(await socket.next())), 'echo:ping from javascript');
    socket.send(await session.close());
    assert.equal(await session.open(await socket.next()), null);
    session.verifyEnd();
  } finally {
    socket.destroy();
  }
}

test('a JavaScript joiner pairs with a Rust responder by PIN, and the key is then what the method proves', async t => {
  if (!cargo) return unavailable(t, 'cargo');
  const identity = await generateIdentity();
  const rust = await rustResponder();
  try {
    const paired = await jsJoin(identity, rust.port, rust.pin);
    assert.equal(paired.peerId, rust.peerId);
    assert.deepEqual(JSON.parse(await rust.peer.next()), {paired: identity.peerId});
    await jsEcho(identity, paired.peerId, rust.port, rust.peer);
    assert.equal(await rust.peer.exit, 0, rust.peer.errors());
    assert.match(rust.peer.errors(), new RegExp(`verified ${identity.peerId}`));
  } finally {
    rust.close();
  }
});

test('a Rust responder refuses a wrong PIN from JavaScript, burns the PIN, and a new one pairs', async t => {
  if (!cargo) return unavailable(t, 'cargo');
  const identity = await generateIdentity();
  const rust = await rustResponder();
  try {
    const wrong = rust.pin === '000000' ? '000001' : '000000';
    await assert.rejects(jsJoin(identity, rust.port, wrong), {refusal: 'wrong-code'});
    assert.match(await rust.peer.next(), /WrongCode/);
    const {pin} = JSON.parse(await rust.peer.next());
    const paired = await jsJoin(identity, rust.port, pin);
    assert.equal(paired.peerId, rust.peerId);
    assert.deepEqual(JSON.parse(await rust.peer.next()), {paired: identity.peerId});
  } finally {
    rust.close();
  }
});

test('a connection that proves a key and says nothing more pairs nobody, and leaves the PIN', async t => {
  if (!cargo) return unavailable(t, 'cargo');
  const identity = await generateIdentity();
  const rust = await rustResponder();
  const socket = await dial(rust.port);
  try {
    const initiator = await createPairingInitiator(identity, {responder: rust.peerId});
    socket.send(await initiator.hello());
    const {reply} = await initiator.answer(await socket.next());
    socket.send(reply);
    socket.destroy();
    assert.match(await rust.peer.next(), /refused/);
    const paired = await jsJoin(identity, rust.port, rust.pin);
    assert.equal(paired.peerId, rust.peerId);
  } finally {
    socket.destroy();
    rust.close();
  }
});

/** A relay on real sockets, passing frames both ways through `tamper(from, index, frame)`. */
async function relayTo(port, tamper) {
  const listener = await listen();
  const counts = {joiner: 0, responder: 0};
  const running = [];
  const serve = async () => {
    const near = await listener.accept();
    const far = await dial(port);
    const pass = async (from, to, name) => {
      for (;;) {
        const frame = await from.next();
        if (frame === null) break;
        to.send(tamper(name, counts[name]++, frame));
      }
      to.end();
      from.destroy();
    };
    running.push(pass(near, far, 'joiner'), pass(far, near, 'responder'));
  };
  return {
    port: listener.port,
    serve,
    close: async () => {
      await Promise.allSettled(running);
      listener.close();
    },
  };
}

test('a relay altering a sealed pairing record is refused by Rust, with the PIN left for the real run', async t => {
  if (!cargo) return unavailable(t, 'cargo');
  const identity = await generateIdentity();
  const rust = await rustResponder();
  // The joiner's frames: two of the handshake, then the hello.
  const relay = await relayTo(rust.port, (from, index, frame) => {
    if (from === 'joiner' && index === 2) frame[frame.length - 1] ^= 1;
    return frame;
  });
  try {
    const serving = relay.serve();
    const refused = jsJoin(identity, relay.port, rust.pin);
    await serving;
    await assert.rejects(refused, /truncated/);
    assert.match(await rust.peer.next(), /Record/);
    const paired = await jsJoin(identity, rust.port, rust.pin);
    assert.equal(paired.peerId, rust.peerId);
  } finally {
    await relay.close();
    rust.close();
  }
});

test('a relay carrying the exchange unchanged pairs the real parties with each other', async t => {
  if (!cargo) return unavailable(t, 'cargo');
  const identity = await generateIdentity();
  const rust = await rustResponder();
  const relay = await relayTo(rust.port, (_, __, frame) => frame);
  try {
    const serving = relay.serve();
    const paired = await jsJoin(identity, relay.port, rust.pin);
    await serving;
    assert.equal(paired.peerId, rust.peerId);
    assert.deepEqual(JSON.parse(await rust.peer.next()), {paired: identity.peerId});
  } finally {
    await relay.close();
    rust.close();
  }
});

/** The Rust joiner against a JavaScript responder, until it pairs or `pins` run out. */
async function rustJoiner(identity, desk, pins) {
  const listener = await listen();
  const peer = startPairPeer('joiner');
  const {peerId} = JSON.parse(await peer.next());
  peer.send(String(listener.port));
  const results = [];
  const accepted = [];
  let paired;
  for (const next of pins) {
    peer.send(next);
    const socket = await listener.accept();
    try {
      const far = await createPairingResponder(identity);
      socket.send(await far.challenge(await socket.next()));
      const {pairing, peerId: proved} = await far.accept(await socket.next());
      assert.equal(proved, peerId);
      try {
        paired = await pairing.respond(desk, transportOf(socket), {accept: async id => { accepted.push(id); }});
        results.push('paired');
        break;
      } catch (error) {
        results.push(error.refusal ?? error.message);
      }
    } finally {
      socket.destroy();
    }
    assert.match(await peer.next(), /refused/);
  }
  return {listener, peer, peerId, results, accepted, paired};
}

test('a Rust joiner pairs with a JavaScript responder by PIN, and the key is then what the method proves', async t => {
  if (!cargo) return unavailable(t, 'cargo');
  const identity = await generateIdentity();
  const desk = createPairingDesk();
  const {listener, peer, peerId, results, accepted} = await rustJoiner(identity, desk, [desk.showPin().pin]);
  let socket;
  try {
    assert.deepEqual(results, ['paired']);
    assert.deepEqual(accepted, [peerId]);
    assert.deepEqual(JSON.parse(await peer.next()), {paired: identity.peerId});
    socket = await listener.accept();
    const responder = await createResponder(identity, {allowClient: async id => accepted.includes(id)});
    socket.send(await responder.challenge(await socket.next()));
    const {session, peerId: proved} = await responder.accept(await socket.next());
    assert.equal(proved, peerId);
    assert.deepEqual(JSON.parse(await peer.next()), {id: toHex(session.id)});
    assert.equal(new TextDecoder().decode(await session.open(await socket.next())), 'ping from rust');
    socket.send(await session.seal('echo:ping from rust'));
    assert.equal(await peer.next(), 'echo:ping from rust');
    assert.equal(await session.open(await socket.next()), null);
    socket.send(await session.close());
    session.verifyEnd();
    assert.equal(await peer.exit, 0, peer.errors());
  } finally {
    socket?.destroy();
    listener.close();
    peer.child.kill();
  }
});

test('a JavaScript responder refuses a wrong PIN from Rust, burns the PIN, and a new one pairs', async t => {
  if (!cargo) return unavailable(t, 'cargo');
  const identity = await generateIdentity();
  const desk = createPairingDesk();
  const {pin} = desk.showPin();
  const wrong = pin === '000000' ? '000001' : '000000';
  const listener = await listen();
  const peer = startPairPeer('joiner');
  const {peerId} = JSON.parse(await peer.next());
  peer.send(String(listener.port));
  const attempt = async next => {
    peer.send(next);
    const socket = await listener.accept();
    try {
      const far = await createPairingResponder(identity);
      socket.send(await far.challenge(await socket.next()));
      const {pairing} = await far.accept(await socket.next());
      return await pairing.respond(desk, transportOf(socket), {accept: async () => {}});
    } finally {
      socket.destroy();
    }
  };
  try {
    await assert.rejects(attempt(wrong), {refusal: 'wrong-code'});
    assert.match(await peer.next(), /WrongCode/);
    assert.equal(desk.shownPin(), null);
    const paired = await attempt(desk.showPin().pin);
    assert.equal(paired.peerId, peerId);
    assert.deepEqual(JSON.parse(await peer.next()), {paired: identity.peerId});
  } finally {
    listener.close();
    peer.child.kill();
  }
});
