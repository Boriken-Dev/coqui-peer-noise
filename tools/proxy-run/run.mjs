// A real reverse proxy between a real browser and the Rust side: see README.md here. Exits 0 only when
// every scenario did what is written beside it.
import {spawn, spawnSync} from 'node:child_process';
import {existsSync, mkdtempSync} from 'node:fs';
import {rm} from 'node:fs/promises';
import {connect as tcpConnect, createServer as tcpServer} from 'node:net';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {createInterface} from 'node:readline';
import {fileURLToPath} from 'node:url';
import {framed} from '../../bindings/js/coqui-peer-noise/test/support.mjs';
import {connect as wss} from './ws.mjs';

const env = process.env;
const here = fileURLToPath(new URL('./', import.meta.url));
const root = resolve(here, '../..');
const wsl = env.COQUI_PROXY_WSL;
const nginxBin = env.COQUI_PROXY_NGINX;
const remoteNode = env.COQUI_PROXY_NODE ?? 'node';
const idle = env.COQUI_PROXY_IDLE ?? '2';
const browser = env.COQUI_TEST_BROWSER;
if (!nginxBin) throw new Error('COQUI_PROXY_NGINX names the nginx binary');
if (!browser || !existsSync(browser)) throw new Error('COQUI_TEST_BROWSER names Chrome or Edge');

const asRemotePath = path => (wsl ? path.replace(/^([A-Za-z]):/, (_, drive) => `/mnt/${drive.toLowerCase()}`).replaceAll('\\', '/') : path);
const examples = join(env.CARGO_TARGET_DIR ?? join(root, 'target'), 'debug', 'examples');
const suffix = process.platform === 'win32' ? '.exe' : '';
const randomPort = () => 20000 + Math.floor(Math.random() * 20000);

const built = spawnSync('cargo', ['build', '--quiet', '--features', 'pin', '--examples'], {cwd: root, stdio: 'inherit'});
if (built.status !== 0) throw new Error('the Rust examples do not build');

const [port, relayPort] = [randomPort(), randomPort()];
const serveArgs = [join(here, 'serve.sh'), nginxBin, remoteNode, String(port), String(relayPort), idle].map((value, index) => (index === 0 ? asRemotePath(value) : value));
const serve = wsl
  ? spawn('wsl.exe', ['-d', wsl, '--', 'bash', ...serveArgs], {stdio: ['pipe', 'pipe', 'inherit']})
  : spawn('bash', serveArgs, {stdio: ['pipe', 'pipe', 'inherit']});
const serveEnded = new Promise(done => serve.once('close', done));

let ready;
const readyOnce = new Promise(done => { ready = done; });
const reports = [];
const reportWaiters = [];
const access = [];
const nginxErrors = [];
const relayLines = [];
createInterface({input: serve.stdout}).on('line', line => {
  const [kind, ...rest] = line.split(' ');
  const body = rest.join(' ');
  if (kind === 'READY') ready(JSON.parse(body));
  else if (kind === 'ACCESS') access.push(body);
  else if (kind === 'NGINXERROR') nginxErrors.push(body);
  else if (kind === 'RELAY') relayLines.push(JSON.parse(body));
  else if (kind === 'REPORT') {
    const waiter = reportWaiters.shift();
    if (waiter) waiter(JSON.parse(body));
    else reports.push(JSON.parse(body));
  }
});
const nextReport = () => (reports.length > 0 ? Promise.resolve(reports.shift()) : new Promise(done => reportWaiters.push(done)));
const within = (promise, seconds, what) => Promise.race([
  promise,
  new Promise((_, reject) => setTimeout(() => reject(new Error(`no ${what} in ${seconds} s`)), seconds * 1000).unref()),
]);

const info = await within(readyOnce, 60, 'proxy');
const ca = Buffer.from(info.cert, 'base64');

/** Waits for the proxy to answer on its port, which is forwarded when the proxy is in WSL. */
async function proxyAnswers() {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const open = await new Promise(done => {
      const socket = tcpConnect({host: '127.0.0.1', port});
      socket.once('connect', () => { socket.destroy(); done(true); });
      socket.once('error', () => done(false));
    });
    if (open) return;
    await new Promise(done => setTimeout(done, 200));
  }
  throw new Error('the proxy did not answer');
}
await proxyAnswers();

function startExample(name, args) {
  const child = spawn(join(examples, name + suffix), args, {stdio: ['pipe', 'pipe', 'pipe']});
  const reader = createInterface({input: child.stdout})[Symbol.asyncIterator]();
  let errors = '';
  child.stderr.on('data', data => { errors += data; });
  const exit = new Promise(done => child.once('close', done));
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

const tlsProtocols = new Set();

/** Moves frames between a Rust socket and a wss connection through the proxy. */
async function carry(socket, path) {
  const {connection, protocol} = await wss({host: '127.0.0.1', port, path, ca, servername: 'localhost'});
  tlsProtocols.add(protocol);
  const channel = framed(socket);
  connection.onMessage = message => channel.send(message);
  connection.onClose = () => channel.end();
  (async () => {
    for (;;) {
      const message = await channel.next();
      if (message === null) {
        connection.close();
        return;
      }
      connection.send(message);
    }
  })();
}

const dialRust = (rustPort, path) => new Promise((done, reject) => {
  const socket = tcpConnect({host: '127.0.0.1', port: rustPort, noDelay: true});
  socket.once('error', reject);
  socket.once('connect', () => carry(socket, path).then(done, reject));
});

let runCount = 0;
const pathOf = (query = '', location = 'relay') => {
  runCount += 1;
  return {
    forRust: `/${location}/run${runCount}?side=rust${query}`,
    forBrowser: `/${location}/run${runCount}?side=browser${query}`,
  };
};

const pageBrowser = async scenario => {
  serve.stdin.write(JSON.stringify(scenario) + '\n');
  return within(nextReport(), 60, `report for ${scenario.name}`);
};

const profile = mkdtempSync(join(tmpdir(), 'coqui-proxy-browser-'));
const running = spawn(browser, [
  '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
  ...(env.CI ? ['--no-sandbox'] : []),
  // Trusts this run's one key and nothing else, with no change to any certificate store.
  `--ignore-certificate-errors-spki-list=${info.spki}`,
  `--user-data-dir=${profile}`, `https://localhost:${port}/`,
], {stdio: 'ignore'});
const browserEnded = new Promise(done => running.once('close', done));

const failures = [];
const passed = [];
function check(name, actual, expected) {
  const same = Object.entries(expected).every(([key, value]) => JSON.stringify(actual?.[key]) === JSON.stringify(value));
  (same ? passed : failures).push({name, ...(same ? {} : {expected, actual})});
  console.log(`${same ? 'ok  ' : 'FAIL'} ${name}: ${JSON.stringify(actual)}`);
}

const REFUSED = 3;
const TRUNCATED = 4;
const OPEN_REFUSED = 'A session record does not open';
const CUT = 'The stream was truncated: it ended before the peer closed it';

/** A scenario of the browser against `peer responder`, with what each side must then say. */
async function againstResponder(name, kind, query, expected, rustExit, location, extra = {}) {
  const peer = startExample('peer', ['responder']);
  const {peerId} = JSON.parse(await peer.next());
  peer.send(hello.peerId);
  const rustPort = Number(await peer.next());
  const path = pathOf(query, location);
  await dialRust(rustPort, path.forRust);
  const report = await pageBrowser({name, kind, peerId, path: path.forBrowser, ...extra});
  const exit = await within(peer.exit, 30, `exit of the Rust side in ${name}`);
  peer.child.kill();
  if (report.thrown) console.log(report.thrown, report.stack);
  check(name, {...report.result, ...(report.thrown ? {thrown: report.thrown} : {}), rustExit: exit}, {...expected, rustExit});
}

let hello;
let exitCode = 1;
const summary = {};
try {
  hello = await within(nextReport(), 60, 'page');
  if (hello.kind !== 'hello') throw new Error(JSON.stringify(hello));
  summary.userAgent = hello.userAgent;
  summary.origin = hello.origin;
  check('the page is a secure context on the proxy\'s origin, with a key it cannot export', hello, {
    secure: true, extractable: false, origin: `https://localhost:${port}`,
  });

  await againstResponder('both ends, through the proxy: records, a long record and both closes', 'echo', '', {
    echo: 'echo:ping from a browser', longEcho: 700005, closed: true, end: 'none',
  }, 0, 'relay', {long: 700000});

  // A dialling Rust side: the browser takes the connection and accepts.
  {
    const listener = await new Promise(done => {
      const server = tcpServer();
      server.listen(0, '127.0.0.1', () => done(server));
    });
    const path = pathOf();
    const peer = startExample('peer', ['initiator']);
    const {peerId} = JSON.parse(await peer.next());
    const accepted = new Promise(done => listener.once('connection', done));
    peer.send(hello.peerId);
    peer.send(String(listener.address().port));
    const socket = await accepted;
    socket.setNoDelay(true);
    await carry(socket, path.forRust);
    const report = await pageBrowser({name: 'accept', kind: 'accept', peerId, path: path.forBrowser});
    const exit = await within(peer.exit, 30, 'exit of the Rust initiator');
    listener.close();
    check('the browser accepts, the Rust side dials', {...report.result, rustExit: exit}, {
      proved: peerId, ping: 'ping from rust', closed: true, end: 'none', rustExit: 0,
    });
  }

  await againstResponder('the relay alters a record to the browser: refused', 'refused', '&mode=tamper&to=browser&at=1', {
    opened: [], refused: OPEN_REFUSED,
  }, TRUNCATED);
  await againstResponder('the relay alters a record to Rust: refused, and the browser sees a cut', 'cut', '&mode=tamper&to=rust&at=2', {
    echo: null, end: CUT,
  }, REFUSED);
  await againstResponder('the relay injects a plain message to the browser: refused', 'refused', '&mode=inject&to=browser&at=1', {
    opened: [], refused: OPEN_REFUSED,
  }, TRUNCATED);
  await againstResponder('the relay injects a plain message to Rust: refused', 'cut', '&mode=inject&to=rust&at=2', {
    echo: null, end: CUT,
  }, REFUSED);
  await againstResponder('the relay repeats a record to the browser: refused', 'refused', '&mode=replay&to=browser&at=1', {
    opened: ['echo:ping from a browser'], refused: OPEN_REFUSED,
  }, TRUNCATED, 'relay', {opens: 2});
  await againstResponder('the relay cuts before the echo: a cut on both sides', 'cut', '&mode=cut&to=browser&at=1', {
    echo: null, rest: 'ended', end: CUT,
  }, TRUNCATED);
  await againstResponder('the relay swallows the browser\'s close: a cut on both sides', 'cut', '&mode=cut&to=rust&at=3', {
    echo: 'echo:ping from a browser', rest: 'ended', end: CUT,
  }, TRUNCATED, 'relay', {sendClose: true});
  await againstResponder('the relay swallows Rust\'s close: the browser sees a cut, Rust a clean end', 'cut', '&mode=cut&to=browser&at=2', {
    echo: 'echo:ping from a browser', rest: 'ended', end: CUT,
  }, 0, 'relay', {sendClose: true});
  await againstResponder('the proxy\'s own read timeout ends an idle stream: a cut on both sides', 'idle', '', {
    rest: 'ended', end: CUT,
  }, TRUNCATED, 'idle');

  // PIN pairing: an altered record, a wrong PIN, a right one, then the ordinary method.
  const store = mkdtempSync(join(tmpdir(), 'coqui-proxy-store-'));
  const pairPeer = startExample('pair', ['responder', store]);
  try {
    const {peerId} = JSON.parse(await pairPeer.next());
    const pairPort = Number(await pairPeer.next());
    let {pin} = JSON.parse(await pairPeer.next());
    const attempt = async (name, guess, query = '') => {
      const path = pathOf(query);
      await dialRust(pairPort, path.forRust);
      const report = await pageBrowser({name, kind: 'pin', pin: guess, path: path.forBrowser});
      if (report.thrown) console.log(report.thrown, report.stack);
      return report.result;
    };
    // The joiner's frames: two of the handshake, then the hello.
    check('the relay alters a sealed pairing record: refused, and the PIN stays', {
      ...await attempt('tampered', pin, '&mode=tamper&to=rust&at=2'),
      rust: await pairPeer.next(),
    }, {refusal: null, rust: '{"refused":"Record"}'});
    const wrong = pin === '000000' ? '000001' : '000000';
    check('a wrong PIN: refused at the confirmation, on both sides', {
      ...await attempt('wrong', wrong),
      rust: await pairPeer.next(),
    }, {refusal: 'wrong-code', rust: '{"refused":"Refused(WrongCode)"}'});
    ({pin} = JSON.parse(await pairPeer.next()));
    check('the right PIN pairs the real parties', {
      ...await attempt('right', pin),
      rust: await pairPeer.next(),
    }, {paired: peerId, method: 'noise', rust: JSON.stringify({paired: hello.peerId})});
    const path = pathOf();
    await dialRust(pairPort, path.forRust);
    const report = await pageBrowser({name: 'after', kind: 'echo', peerId, path: path.forBrowser, long: 700000});
    const exit = await within(pairPeer.exit, 30, 'exit of the pairing peer');
    check('the key that was paired is what the ordinary method then proves', {...report.result, rustExit: exit}, {
      echo: 'echo:ping from a browser', longEcho: 700005, closed: true, end: 'none', rustExit: 0,
    });
    if (!pairPeer.errors().includes(`verified ${hello.peerId}`)) failures.push({name: 'the Rust side proved the browser\'s key'});
  } finally {
    pairPeer.child.kill();
    await rm(store, {recursive: true, force: true, maxRetries: 10, retryDelay: 200}).catch(() => {});
  }
  serve.stdin.write(JSON.stringify({kind: 'done'}) + '\n');
  await within(nextReport(), 20, 'end of the page');
  exitCode = failures.length === 0 ? 0 : 1;
} catch (error) {
  console.error(error);
} finally {
  running.kill();
  await within(browserEnded, 10, 'browser exit').catch(() => {});
  serve.stdin.end();
  await within(serveEnded, 20, 'proxy exit').catch(error => console.error(error.message));
  await rm(profile, {recursive: true, force: true, maxRetries: 10, retryDelay: 200}).catch(() => {});
}

const statuses = {};
for (const line of access) statuses[line.split(' ')[0]] = (statuses[line.split(' ')[0]] ?? 0) + 1;
const upgraded = access.filter(line => line.startsWith('101 '));
summary.nginx = info.nginx;
summary.openssl = info.openssl;
summary.scenarios = {passed: passed.length, failed: failures.length};
summary.accessLogStatuses = statuses;
summary.tlsSeenByProxy = [...new Set(upgraded.map(line => line.split(' ').slice(1, 3).join(' ')))];
summary.tlsSeenByRustSide = [...tlsProtocols];
summary.relayConnectionsEncrypted = relayLines.filter(line => line.side && line.encrypted).length;
summary.relayConnections = relayLines.filter(line => line.side).length;
summary.nginxErrors = nginxErrors;
console.log(JSON.stringify(summary, null, 2));
if (failures.length > 0) console.log(JSON.stringify(failures, null, 2));
if (upgraded.length === 0 || summary.relayConnectionsEncrypted !== 0) {
  console.log('FAIL the proxy did not carry the connections, or the relay saw TLS');
  exitCode = 1;
}
process.exit(exitCode);
