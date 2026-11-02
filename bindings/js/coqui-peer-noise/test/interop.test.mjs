// JavaScript against the Rust implementation, each in both roles, over real TCP, and through a relay
// that tampers: what one language refuses, the other made, and each reports a cut stream.
import test, {before} from 'node:test';
import assert from 'node:assert/strict';
import {createInitiator, createResponder, generateIdentity} from '../src/index.mjs';
import {buildPeer, dial, haveCargo, listen, startPeer, toHex, unavailable} from './support.mjs';

const cargo = haveCargo();

before(() => { if (cargo) buildPeer(); }, {timeout: 600_000});

async function rustResponder(clientId) {
  const peer = startPeer('responder');
  const {peerId} = JSON.parse(await peer.next());
  peer.send(clientId);
  const port = Number(await peer.next());
  return {peer, peerId, port};
}

test('a JavaScript initiator authenticates a Rust responder and they exchange records', async t => {
  if (!cargo) return unavailable(t, 'cargo');
  const client = await generateIdentity();
  const {peer, peerId, port} = await rustResponder(client.peerId);
  const socket = await dial(port);
  try {
    const initiator = await createInitiator(client, peerId);
    socket.send(await initiator.hello());
    const {reply, session, peerId: proven} = await initiator.answer(await socket.next());
    socket.send(reply);
    assert.equal(proven, peerId);
    assert.deepEqual(JSON.parse(await peer.next()), {id: toHex(session.id)});
    socket.send(await session.seal('ping from javascript'));
    assert.equal(new TextDecoder().decode(await session.open(await socket.next())), 'echo:ping from javascript');
    const long = new Uint8Array(200000).fill(0x42);
    socket.send(await session.seal(long));
    const echoed = await session.open(await socket.next());
    assert.equal(echoed.length, long.length + 5);
    socket.send(await session.close());
    assert.equal(await session.open(await socket.next()), null);
    session.verifyEnd();
    assert.equal(await peer.exit, 0, peer.errors());
    assert.match(peer.errors(), new RegExp(`verified ${client.peerId}`));
  } finally {
    socket.destroy();
    peer.child.kill();
  }
});

test('a Rust responder refuses a JavaScript peer it does not know, once that peer proved its key', async t => {
  if (!cargo) return unavailable(t, 'cargo');
  const client = await generateIdentity();
  const {peer, peerId, port} = await rustResponder('sha256:' + '0'.repeat(64));
  const socket = await dial(port);
  try {
    const initiator = await createInitiator(client, peerId);
    socket.send(await initiator.hello());
    const {reply} = await initiator.answer(await socket.next());
    socket.send(reply);
    assert.equal(await peer.exit, 3, peer.errors());
    assert.match(peer.errors(), /Untrusted/);
  } finally {
    socket.destroy();
    peer.child.kill();
  }
});

test('a Rust initiator authenticates a JavaScript responder and they exchange records', async t => {
  if (!cargo) return unavailable(t, 'cargo');
  const server = await generateIdentity();
  const listener = await listen();
  const peer = startPeer('initiator');
  let socket;
  try {
    const {peerId: clientId} = JSON.parse(await peer.next());
    peer.send(server.peerId);
    peer.send(String(listener.port));
    socket = await listener.accept();
    const responder = await createResponder(server, {allowClient: async id => id === clientId});
    socket.send(await responder.challenge(await socket.next()));
    const accepted = await responder.accept(await socket.next());
    assert.equal(accepted.peerId, clientId);
    assert.deepEqual(JSON.parse(await peer.next()), {id: toHex(accepted.session.id)});
    const opened = await accepted.session.open(await socket.next());
    assert.equal(new TextDecoder().decode(opened), 'ping from rust');
    socket.send(await accepted.session.seal('echo:ping from rust'));
    assert.equal(await peer.next(), 'echo:ping from rust');
    assert.equal(await accepted.session.open(await socket.next()), null);
    accepted.session.verifyEnd();
    socket.send(await accepted.session.close());
    assert.equal(await peer.exit, 0, peer.errors());
  } finally {
    socket?.destroy();
    listener.close();
    peer.child.kill();
  }
});

test('a Rust initiator pinning another key refuses a JavaScript responder, sending no third message', async t => {
  if (!cargo) return unavailable(t, 'cargo');
  const server = await generateIdentity();
  const pinned = await generateIdentity();
  const listener = await listen();
  const peer = startPeer('initiator');
  let socket;
  try {
    const {peerId: clientId} = JSON.parse(await peer.next());
    peer.send(pinned.peerId);
    peer.send(String(listener.port));
    socket = await listener.accept();
    const responder = await createResponder(server, {allowClient: async id => id === clientId});
    socket.send(await responder.challenge(await socket.next()));
    assert.equal(await socket.next(), null, 'the connection ended with no third message');
    assert.equal(await peer.exit, 3, peer.errors());
    assert.match(peer.errors(), /Untrusted/);
  } finally {
    socket?.destroy();
    listener.close();
    peer.child.kill();
  }
});

/** A JavaScript client, a relay, and the Rust responder, past the handshake. */
async function throughRelay() {
  const client = await generateIdentity();
  const {peer, peerId, port} = await rustResponder(client.peerId);
  const relay = await listen();
  const toRelay = await dial(relay.port);
  const near = await relay.accept();
  const far = await dial(port);
  const initiator = await createInitiator(client, peerId);
  toRelay.send(await initiator.hello());
  far.send(await near.next());
  near.send(await far.next());
  const {reply, session} = await initiator.answer(await toRelay.next());
  toRelay.send(reply);
  far.send(await near.next());
  await peer.next();
  return {
    peer, session, toRelay, near, far,
    close() {
      for (const end of [toRelay, near, far]) end.destroy();
      relay.close();
      peer.child.kill();
    },
  };
}

test('a relay injecting a message at a Rust responder is refused by it', async t => {
  if (!cargo) return unavailable(t, 'cargo');
  const run = await throughRelay();
  try {
    run.far.send(new TextEncoder().encode('{"jsonrpc":"2.0"}'));
    assert.equal(await run.peer.exit, 3, run.peer.errors());
    assert.match(run.peer.errors(), /Record/);
  } finally {
    run.close();
  }
});

test('a relay reordering a JavaScript client\'s records is refused by the Rust responder', async t => {
  if (!cargo) return unavailable(t, 'cargo');
  const run = await throughRelay();
  try {
    run.toRelay.send(await run.session.seal('first'));
    run.toRelay.send(await run.session.seal('second'));
    const [first, second] = [await run.near.next(), await run.near.next()];
    run.far.send(second);
    run.far.send(first);
    assert.equal(await run.peer.exit, 3, run.peer.errors());
    assert.match(run.peer.errors(), /Record/);
  } finally {
    run.close();
  }
});

test('a relay cutting a JavaScript client off is reported by the Rust responder as truncated', async t => {
  if (!cargo) return unavailable(t, 'cargo');
  const run = await throughRelay();
  try {
    run.toRelay.send(await run.session.seal('one'));
    run.far.send(await run.near.next());
    await run.far.next();
    run.far.end();
    assert.equal(await run.peer.exit, 4, run.peer.errors());
  } finally {
    run.close();
  }
});

test('a relay cutting a Rust client off is reported by the JavaScript responder as truncated', async t => {
  if (!cargo) return unavailable(t, 'cargo');
  const server = await generateIdentity();
  const listener = await listen();
  const peer = startPeer('initiator');
  let socket;
  try {
    const {peerId: clientId} = JSON.parse(await peer.next());
    peer.send(server.peerId);
    peer.send(String(listener.port));
    socket = await listener.accept();
    const responder = await createResponder(server, {allowClient: async id => id === clientId});
    socket.send(await responder.challenge(await socket.next()));
    const {session} = await responder.accept(await socket.next());
    await session.open(await socket.next());
    socket.end();
    assert.equal(await socket.next(), null);
    assert.throws(() => session.verifyEnd(), /truncated/);
    assert.equal(await peer.exit, 4, peer.errors());
  } finally {
    socket?.destroy();
    listener.close();
    peer.child.kill();
  }
});
