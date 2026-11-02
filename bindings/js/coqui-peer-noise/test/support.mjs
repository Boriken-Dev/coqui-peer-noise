// Starting the Rust side, and what to do when a peer is absent: a skip that says so, or with
// COQUI_PEER_NOISE_REQUIRE_PEERS set, as in CI, a failure. Also the frames on real sockets, and keys
// from raw bytes.
import {spawn, spawnSync} from 'node:child_process';
import {connect, createServer} from 'node:net';
import {webcrypto} from 'node:crypto';
import {createInterface} from 'node:readline';
import {fileURLToPath} from 'node:url';
import {createInitiator, createResponder, generateIdentity} from '../src/index.mjs';

const root = fileURLToPath(new URL('../../../../', import.meta.url));

export const unhex = text => Uint8Array.from(Buffer.from(text, 'hex'));
export const toHex = bytes => Buffer.from(bytes).toString('hex');
export const X25519_PKCS8_PREFIX = '302e020100300506032b656e04220420';

export function unavailable(t, what) {
  if (process.env.COQUI_PEER_NOISE_REQUIRE_PEERS) throw new Error(`${what} is required`);
  t.skip(`SKIPPED: ${what} is absent`);
}

export function haveCargo() {
  return spawnSync('cargo', ['--version'], {stdio: 'ignore'}).status === 0;
}

/** Builds once, so a test's timeout does not include compiling. */
export function buildPeer() {
  const built = spawnSync('cargo', ['build', '--quiet', '--features', 'pin', '--examples'], {cwd: root, stdio: 'inherit'});
  if (built.status !== 0) throw new Error('the Rust example does not build');
}

/** `peer` running: `next()` is its next line, `send(line)` writes one, `exit` its status. */
export function startPeer(...args) {
  return startExample('peer', args);
}

/** As `startPeer`, for the example that pairs by PIN first. */
export function startPairPeer(...args) {
  return startExample('pair', args);
}

function startExample(name, args) {
  const child = spawn('cargo', ['run', '--quiet', '--features', 'pin', '--example', name, '--', ...args], {
    cwd: root, stdio: ['pipe', 'pipe', 'pipe'],
  });
  const reader = createInterface({input: child.stdout})[Symbol.asyncIterator]();
  let errors = '';
  child.stderr.on('data', data => { errors += data.toString(); });
  const exit = new Promise(resolve => child.once('close', resolve));
  return {
    child, exit,
    errors: () => errors,
    send: line => child.stdin.write(line + '\n'),
    async next() {
      const line = await reader.next();
      if (line.done) throw new Error('the Rust peer closed: ' + errors);
      return line.value;
    },
  };
}

/** A socket as whole frames: four big-endian length bytes, then the message, as `coqui_peer` has it. */
export function framed(socket) {
  let buffered = Buffer.alloc(0);
  let ended = false;
  const waiting = [];
  const settle = () => {
    while (waiting.length > 0) {
      if (buffered.length >= 4) {
        const length = buffered.readUInt32BE(0);
        if (buffered.length < 4 + length) {
          if (!ended) return;
        } else {
          const message = new Uint8Array(buffered.subarray(4, 4 + length));
          buffered = buffered.subarray(4 + length);
          waiting.shift().resolve(message);
          continue;
        }
      } else if (!ended) {
        return;
      }
      waiting.shift().resolve(null);
    }
  };
  socket.on('data', chunk => {
    buffered = Buffer.concat([buffered, chunk]);
    settle();
  });
  const end = () => {
    ended = true;
    settle();
  };
  socket.on('end', end);
  socket.on('close', end);
  socket.on('error', end);
  return {
    socket,
    send(message) {
      const prefix = Buffer.alloc(4);
      prefix.writeUInt32BE(message.length);
      socket.write(Buffer.concat([prefix, Buffer.from(message)]));
    },
    /** The next message, or null when the connection ended first. */
    next() {
      return new Promise(resolve => {
        waiting.push({resolve});
        settle();
      });
    },
    end() { socket.end(); },
    destroy() { socket.destroy(); },
  };
}

export function listen() {
  return new Promise((resolve, reject) => {
    const accepted = [];
    const waiters = [];
    const server = createServer(socket => {
      socket.setNoDelay(true);
      const waiter = waiters.shift();
      if (waiter) waiter(framed(socket));
      else accepted.push(framed(socket));
    });
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve({
      server,
      port: server.address().port,
      accept: () => new Promise(done => {
        const ready = accepted.shift();
        if (ready) done(ready);
        else waiters.push(done);
      }),
      close: () => server.close(),
    }));
  });
}

export function dial(port) {
  return new Promise((resolve, reject) => {
    const socket = connect({host: '127.0.0.1', port, noDelay: true});
    const channel = framed(socket);
    socket.once('error', reject);
    socket.once('connect', () => resolve(channel));
  });
}

/** Two identities that pin each other, as the two ends of a run. */
export async function parties(optionsOfBoth = {}) {
  const client = await generateIdentity();
  const server = await generateIdentity();
  return {
    client, server,
    i: await createInitiator(client, server.peerId, optionsOfBoth),
    r: await createResponder(server, {allowClient: async id => id === client.peerId, ...optionsOfBoth}),
  };
}

/** A whole run through `relay`, a function of each message. */
export async function through(relay, p) {
  const second = await p.r.challenge(relay(await p.i.hello()));
  const answered = await p.i.answer(relay(second));
  const accepted = await p.r.accept(relay(answered.reply));
  return {atClient: answered.session, atServer: accepted.session, answered, accepted};
}

export const asIs = message => message;

export async function sessions(optionsOfBoth) {
  return through(asIs, await parties(optionsOfBoth));
}

const X25519 = {name: 'X25519'};

/** An identity-like pair of keys from a PKCS#8 and public bytes, as `ephemeral` wants it. */
export async function keyPairOf(pkcs8, publicKey) {
  return {
    privateKey: await webcrypto.subtle.importKey('pkcs8', pkcs8, X25519, false, ['deriveBits']),
    publicKey: await webcrypto.subtle.importKey('raw', publicKey, X25519, true, []),
  };
}
