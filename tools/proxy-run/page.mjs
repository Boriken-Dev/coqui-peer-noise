// The browser's end: it asks the relay for a scenario, runs it over wss through the proxy, and reports
// what the module said. It decides nothing: the driver compares the reports with what it expected.
import {
  createInitiator, createPairingInitiator, createResponder, loadOrCreateIdentity,
} from '/index.mjs';

const hex = bytes => [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
const text = bytes => new TextDecoder().decode(bytes);
const report = body => fetch('/report', {method: 'POST', body: JSON.stringify(body)});

function dial(path) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(`wss://${location.host}${path}`);
    socket.binaryType = 'arraybuffer';
    const inbox = [];
    const waiters = [];
    let ended = null;
    const deliver = value => {
      const waiter = waiters.shift();
      if (waiter) waiter(value);
      else inbox.push(value);
    };
    socket.onmessage = event => deliver(new Uint8Array(event.data));
    socket.onclose = event => {
      ended = {code: event.code, clean: event.wasClean};
      for (const waiter of waiters.splice(0)) waiter(null);
      reject(new Error('the connection closed before it opened'));
    };
    socket.onopen = () => resolve({
      send: bytes => socket.send(bytes),
      recv: () => {
        if (inbox.length > 0) return Promise.resolve(inbox.shift());
        if (ended) return Promise.resolve(null);
        return new Promise(done => waiters.push(done));
      },
      close: () => socket.close(),
      ended: () => ended,
    });
  });
}

const identity = await loadOrCreateIdentity('coqui-proxy-run');

async function prove(connection, peerId) {
  const initiator = await createInitiator(identity, peerId);
  connection.send(await initiator.hello());
  const {reply, session} = await initiator.answer(await connection.recv());
  connection.send(reply);
  return session;
}

const truncation = session => {
  try {
    session.verifyEnd();
    return 'none';
  } catch (error) {
    return error.message;
  }
};

const handlers = {
  // A whole stream, a long record, and both closes.
  async echo({path, peerId, long}) {
    const connection = await dial(path);
    const session = await prove(connection, peerId);
    connection.send(await session.seal('ping from a browser'));
    const echo = text(await session.open(await connection.recv()));
    const message = new Uint8Array(long).fill(0x42);
    connection.send(await session.seal(message));
    const longEcho = await session.open(await connection.recv());
    connection.send(await session.close());
    const closed = await session.open(await connection.recv()) === null;
    const end = truncation(session);
    connection.close();
    return {id: hex(session.id), echo, longEcho: longEcho.length, closed, end};
  },
  // Through to a record the relay spoils: the module must refuse it.
  async refused({path, peerId, opens = 1}) {
    const connection = await dial(path);
    const session = await prove(connection, peerId);
    connection.send(await session.seal('ping from a browser'));
    const opened = [];
    let refused = 'nothing refused';
    try {
      for (let index = 0; index < opens; index += 1) opened.push(text(await session.open(await connection.recv())));
    } catch (error) {
      refused = error.message;
    }
    connection.close();
    return {opened, refused};
  },
  // The connection ends under the page: the module must report a cut and not a clean end.
  async cut({path, peerId, sendClose}) {
    const connection = await dial(path);
    const session = await prove(connection, peerId);
    connection.send(await session.seal('ping from a browser'));
    const first = await connection.recv();
    const echo = first && text(await session.open(first));
    if (sendClose && first) connection.send(await session.close());
    const rest = await connection.recv();
    return {echo, rest: rest === null ? 'ended' : 'a record', end: truncation(session), closed: connection.ended()};
  },
  // Nothing moves until the proxy's own read timeout ends the connection.
  async idle({path, peerId}) {
    const started = performance.now();
    const connection = await dial(path);
    const session = await prove(connection, peerId);
    const rest = await connection.recv();
    return {
      rest: rest === null ? 'ended' : 'a record',
      end: truncation(session),
      closed: connection.ended(),
      seconds: Math.round((performance.now() - started) / 100) / 10,
    };
  },
  // The browser as the side that accepts, with the Rust side dialling.
  async accept({path, peerId}) {
    const connection = await dial(path);
    const responder = await createResponder(identity, {allowClient: async id => id === peerId});
    connection.send(await responder.challenge(await connection.recv()));
    const {session, peerId: proved} = await responder.accept(await connection.recv());
    const ping = text(await session.open(await connection.recv()));
    connection.send(await session.seal(`echo:${ping}`));
    const closed = await session.open(await connection.recv()) === null;
    connection.send(await session.close());
    const end = truncation(session);
    connection.close();
    return {id: hex(session.id), proved, ping, closed, end};
  },
  // A PIN pairing: the handshake that only pairs, then the exchange, sealed.
  async pin({path, pin}) {
    const connection = await dial(path);
    let outcome;
    try {
      const near = await createPairingInitiator(identity);
      connection.send(await near.hello());
      const {reply, pairing} = await near.answer(await connection.recv());
      connection.send(reply);
      const paired = await pairing.join(pin, {
        send: async bytes => connection.send(bytes),
        recv: () => connection.recv(),
      });
      outcome = {paired: paired.peerId, method: paired.peer.method};
    } catch (error) {
      outcome = {refusal: error.refusal ?? null, error: error.message};
    }
    connection.close();
    return outcome;
  },
};

try {
  await report({
    kind: 'hello', peerId: identity.peerId, secure: isSecureContext, origin: location.origin,
    userAgent: navigator.userAgent, extractable: identity.privateKey.extractable,
  });
  for (;;) {
    const scenario = await (await fetch('/next')).json();
    if (scenario.kind === 'done') break;
    try {
      await report({kind: 'result', name: scenario.name, result: await handlers[scenario.kind](scenario)});
    } catch (error) {
      await report({kind: 'result', name: scenario.name, thrown: String(error), stack: error?.stack});
    }
  }
  await report({kind: 'done'});
} catch (error) {
  await report({kind: 'failed', thrown: String(error), stack: error?.stack});
}
