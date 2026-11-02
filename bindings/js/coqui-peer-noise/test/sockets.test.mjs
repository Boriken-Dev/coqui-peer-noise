// The same parties as in relay.test.mjs on real sockets, as a proxy between two TCP connections.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createInitiator, createResponder, generateIdentity} from '../src/index.mjs';
import {dial, listen} from './support.mjs';

/** Client and server on TCP, with `relaying` between them after it passed the three messages. */
async function acrossRelay(relaying, {clientOptions = {}, serverOptions = {}, handshake} = {}) {
  const client = await generateIdentity();
  const server = await generateIdentity();
  const outer = await listen();
  const inner = await listen();
  const toRelay = await dial(outer.port);
  const near = await outer.accept();
  const far = await dial(inner.port);
  const atServerSocket = await inner.accept();
  const i = await createInitiator(client, server.peerId, clientOptions);
  const r = await createResponder(server, {allowClient: async id => id === client.peerId, ...serverOptions});

  const forward = async (from, to) => {
    const message = await from.next();
    to.send(message);
    return message;
  };
  const dialing = (async () => {
    toRelay.send(await i.hello());
    const {reply, session} = await i.answer(await toRelay.next());
    toRelay.send(reply);
    return session;
  })();
  const serving = (async () => {
    const second = await r.challenge(await atServerSocket.next());
    atServerSocket.send(second);
    return (await r.accept(await atServerSocket.next())).session;
  })();
  const close = () => {
    for (const end of [toRelay, near, far, atServerSocket]) end.destroy();
    outer.close();
    inner.close();
  };
  try {
    await (handshake ?? (async () => {
      await forward(near, far);
      await forward(far, near);
      await forward(near, far);
    }))(near, far, forward);
    const atClient = await dialing;
    const atServer = await serving;
    await relaying({near, far, forward, atClient, atServer, toRelay, atServerSocket});
  } finally {
    close();
  }
  return {dialing, serving};
}

test('a relay carries the proof and a record, and its own injected message is refused', async () => {
  await acrossRelay(async ({near, far, forward, atClient, atServer, toRelay, atServerSocket}) => {
    toRelay.send(await atClient.seal('only for the server'));
    const carried = await forward(near, far);
    assert.ok(!Buffer.from(carried).includes('only for'));
    assert.equal(new TextDecoder().decode(await atServer.open(await atServerSocket.next())), 'only for the server');
    atServerSocket.send(await atServer.seal('acknowledged'));
    await forward(far, near);
    assert.equal(new TextDecoder().decode(await atClient.open(await toRelay.next())), 'acknowledged');
    far.send(new TextEncoder().encode('{"jsonrpc":"2.0","method":"session/prompt"}'));
    await assert.rejects(async () => atServer.open(await atServerSocket.next()), /does not open/);
  });
});

test('a relay swapping two records is refused', async () => {
  await acrossRelay(async ({near, far, atClient, atServer, toRelay, atServerSocket}) => {
    toRelay.send(await atClient.seal('first'));
    toRelay.send(await atClient.seal('second'));
    const [first, second] = [await near.next(), await near.next()];
    far.send(second);
    far.send(first);
    await assert.rejects(async () => atServer.open(await atServerSocket.next()), /does not open/);
  });
});

test('a relay reflecting a record is refused', async () => {
  await acrossRelay(async ({near, atClient, toRelay}) => {
    toRelay.send(await atClient.seal('out'));
    near.send(await near.next());
    await assert.rejects(async () => atClient.open(await toRelay.next()), /does not open/);
  });
});

test('a relay cutting the connection is seen as truncation', async () => {
  await acrossRelay(async ({near, far, forward, atClient, atServer, toRelay, atServerSocket}) => {
    toRelay.send(await atClient.seal('one'));
    toRelay.send(await atClient.close());
    await forward(near, far);
    await near.next();
    far.destroy();
    await atServer.open(await atServerSocket.next());
    assert.equal(await atServerSocket.next(), null, 'the connection ended');
    assert.throws(() => atServer.verifyEnd(), /truncated/);
  });
});

test('the same stream carried whole, with its close record, is complete', async () => {
  await acrossRelay(async ({near, far, forward, atClient, atServer, toRelay, atServerSocket}) => {
    toRelay.send(await atClient.seal('one'));
    toRelay.send(await atClient.close());
    await forward(near, far);
    await forward(near, far);
    far.end();
    await atServer.open(await atServerSocket.next());
    assert.equal(await atServer.open(await atServerSocket.next()), null);
    assert.equal(await atServerSocket.next(), null);
    atServer.verifyEnd();
  });
});

test('a long message crosses a real socket in one record', async () => {
  await acrossRelay(async ({near, far, forward, atClient, atServer, toRelay, atServerSocket}) => {
    const message = new Uint8Array(300000).fill(0xa5);
    toRelay.send(await atClient.seal(message));
    await forward(near, far);
    assert.deepEqual(await atServer.open(await atServerSocket.next()), message);
  });
});

test('a key change crosses a real socket', async () => {
  const limit = {keyLimit: 298};
  await acrossRelay(async ({near, far, forward, atClient, atServer, toRelay, atServerSocket}) => {
    for (let index = 0; index < 5; index += 1) {
      const message = new Uint8Array(100).fill(index);
      toRelay.send(await atClient.seal(message));
      await forward(near, far);
      assert.deepEqual(await atServer.open(await atServerSocket.next()), message);
    }
  }, {clientOptions: limit, serverOptions: limit});
});

test('a relay answering for a pinned server on a real socket fails the pin', async () => {
  const client = await generateIdentity();
  const pinned = await generateIdentity();
  const relay = await generateIdentity();
  const listener = await listen();
  const socket = await dial(listener.port);
  const accepted = await listener.accept();
  try {
    const i = await createInitiator(client, pinned.peerId);
    const asRelay = await createResponder(relay, {allowClient: async () => true});
    socket.send(await i.hello());
    accepted.send(await asRelay.challenge(await accepted.next()));
    await assert.rejects(async () => i.answer(await socket.next()), /not pinned/);
  } finally {
    socket.destroy();
    accepted.destroy();
    listener.close();
  }
});

test('a binding refuses a relay that ends the outer channel on real sockets', async () => {
  const client = await generateIdentity();
  const server = await generateIdentity();
  const listener = await listen();
  const socket = await dial(listener.port);
  const accepted = await listener.accept();
  try {
    const i = await createInitiator(client, server.peerId, {binding: Uint8Array.of(1)});
    const r = await createResponder(server, {allowClient: async () => true, binding: Uint8Array.of(2)});
    socket.send(await i.hello());
    accepted.send(await r.challenge(await accepted.next()));
    await assert.rejects(async () => i.answer(await socket.next()), /does not decrypt/);
  } finally {
    socket.destroy();
    accepted.destroy();
    listener.close();
  }
});
