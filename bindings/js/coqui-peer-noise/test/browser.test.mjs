// A real browser, where Node's WebCrypto stands in nowhere: the module in a page on a secure origin,
// its key kept in IndexedDB, reproducing the vectors and proving itself to the Rust responder over a
// real socket. Point COQUI_TEST_BROWSER at Chrome or Edge when it is not in a usual place; the report
// the page sends is printed as a diagnostic.
import test, {before} from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {existsSync, mkdtempSync, readFileSync} from 'node:fs';
import {rm} from 'node:fs/promises';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {buildPeer, dial, haveCargo, startPeer, toHex, unavailable, unhex} from './support.mjs';

const candidates = [
  process.env.COQUI_TEST_BROWSER,
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
];
const browser = candidates.find(path => path && existsSync(path));
const cargo = haveCargo();

before(() => { if (cargo && browser) buildPeer(); }, {timeout: 600_000});

const page = `<!doctype html><meta charset="utf-8"><title>test</title><script type="module">
import {
  generateIdentity, importIdentity, loadOrCreateIdentity, createInitiator, createResponder, __testing,
} from '/index.mjs';
const post = async (path, body) => (await fetch(path, {method: 'POST', body})).text();
const hex = bytes => [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
const unhex = text => Uint8Array.from(text.match(/../g) ?? [], pair => parseInt(pair, 16));
const X25519 = {name: 'X25519'};
const pkcs8 = raw => unhex('302e020100300506032b656e04220420' + raw);
const rawKey = async raw => {
  const usable = await crypto.subtle.importKey('pkcs8', pkcs8(raw), X25519, true, ['deriveBits']);
  const {x} = await crypto.subtle.exportKey('jwk', usable);
  const bytes = atob(x.replaceAll('-', '+').replaceAll('_', '/'));
  return {
    privateKey: await crypto.subtle.importKey('pkcs8', pkcs8(raw), X25519, false, ['deriveBits']),
    public: Uint8Array.from(bytes, char => char.charCodeAt(0)),
  };
};
async function published(vector) {
  const i = await __testing.newHandshake(true, unhex(vector.init_prologue), await rawKey(vector.init_static), await rawKey(vector.init_ephemeral));
  const r = await __testing.newHandshake(false, unhex(vector.resp_prologue), await rawKey(vector.resp_static), await rawKey(vector.resp_ephemeral));
  for (const [index, message] of vector.messages.slice(0, 3).entries()) {
    const [from, to] = index % 2 === 0 ? [i, r] : [r, i];
    if (hex(await from.writeMessage(unhex(message.payload))) !== message.ciphertext) return false;
    if (hex(await to.readMessage(unhex(message.ciphertext))) !== message.payload) return false;
  }
  const at = await i.split();
  await r.split();
  if (vector.handshake_hash && hex(at.h) !== vector.handshake_hash) return false;
  for (const [offset, message] of vector.messages.slice(3).entries()) {
    if (offset % 2 === 1) {
      if (hex(await at.initiatorToResponder.encrypt(new Uint8Array(), unhex(message.payload))) !== message.ciphertext) return false;
    }
  }
  return true;
}
async function refusesEverything(vectors) {
  const identity = side => importIdentity(unhex(side.pkcs8));
  const ephemeralOf = side => async () => ({
    privateKey: await crypto.subtle.importKey('pkcs8', unhex(side.ephemeralPkcs8), X25519, false, ['deriveBits']),
    publicKey: await crypto.subtle.importKey('raw', unhex(side.ephemeralPublic), X25519, true, []),
  });
  const initiator = async () => createInitiator(await identity(vectors.initiator), vectors.responder.peerId, {ephemeral: ephemeralOf(vectors.initiator)});
  const responder = async () => createResponder(await identity(vectors.responder), {allowClient: async () => true, ephemeral: ephemeralOf(vectors.responder)});
  const accepted = [];
  const refused = async (name, work) => {
    try {
      await work();
      accepted.push(name);
    } catch {}
  };
  for (const entry of vectors.refused.first) {
    const r = await responder();
    await refused('first: ' + entry.name, () => r.challenge(unhex(entry.message)));
  }
  for (const entry of vectors.refused.second) {
    const i = await initiator();
    await i.hello();
    await refused('second: ' + entry.name, () => i.answer(unhex(entry.message)));
  }
  for (const entry of vectors.refused.third) {
    const r = await responder();
    await r.challenge(unhex(vectors.messages[0]));
    await refused('third: ' + entry.name, () => r.accept(unhex(entry.message)));
  }
  const i = await initiator();
  if (hex(await i.hello()) !== vectors.messages[0]) accepted.push('the first message differs');
  const {reply, session} = await i.answer(unhex(vectors.messages[1]));
  if (hex(reply) !== vectors.messages[2]) accepted.push('the third message differs');
  if (hex(session.id) !== vectors.session.id) accepted.push('the id differs');
  return accepted;
}
try {
  const report = {secure: isSecureContext, userAgent: navigator.userAgent};
  const {published: publishedVectors, session: sessionVectors} = await (await fetch('/vectors')).json();
  report.publishedVectors = (await Promise.all(publishedVectors.vectors.map(published))).every(Boolean);
  report.publishedCount = publishedVectors.vectors.length;
  report.vectorsAccepted = await refusesEverything(sessionVectors);
  const fresh = await generateIdentity();
  report.x25519 = fresh.privateKey.algorithm.name;
  report.extractable = fresh.privateKey.extractable;
  const name = 'coqui-test-' + hex(crypto.getRandomValues(new Uint8Array(8)));
  const first = await loadOrCreateIdentity(name);
  const second = await loadOrCreateIdentity(name);
  report.sameIdentity = first.peerId === second.peerId;
  report.storedExtractable = second.privateKey.extractable;
  let exported = false;
  try { await crypto.subtle.exportKey('pkcs8', second.privateKey); exported = true; } catch {}
  report.exported = exported;
  let lowOrder = 'accepted';
  try {
    const point = await crypto.subtle.importKey('raw', new Uint8Array(32), X25519, false, []);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({name: 'X25519', public: point}, fresh.privateKey, 256));
    lowOrder = bits.every(byte => byte === 0) ? 'all zeros returned' : 'other bytes returned';
  } catch (error) {
    lowOrder = 'deriveBits threw ' + error.name;
  }
  report.lowOrder = lowOrder;
  const peerId = await post('/start', second.peerId);
  const initiator = await createInitiator(second, peerId);
  const reply = await post('/send', hex(await initiator.hello()));
  const {reply: third, session} = await initiator.answer(unhex(reply));
  report.id = hex(session.id);
  report.peerId = peerId;
  await post('/last', hex(third));
  report.echo = new TextDecoder().decode(
    await session.open(unhex(await post('/send', hex(await session.seal('ping from a browser'))))),
  );
  const closing = await post('/send', hex(await session.close()));
  report.closed = (await session.open(unhex(closing))) === null;
  session.verifyEnd();
  session.destroy();
  report.ok = true;
  await post('/result', JSON.stringify(report));
} catch (error) {
  await post('/result', JSON.stringify({ok: false, error: String(error), stack: error?.stack}));
}
</script>`;

test('a browser keeps its key, reproduces the vectors and proves itself to a Rust responder', {timeout: 240_000}, async t => {
  if (!cargo) return unavailable(t, 'cargo');
  if (!browser) return unavailable(t, 'a browser');
  const module = readFileSync(new URL('../src/index.mjs', import.meta.url));
  const vectors = JSON.stringify({
    published: JSON.parse(readFileSync(new URL('../../../../tests/vectors/published.json', import.meta.url))),
    session: JSON.parse(readFileSync(new URL('../../../../tests/vectors/session.json', import.meta.url))),
  });
  let peer;
  let socket;
  let sessionId;
  let settle;
  const finished = new Promise(resolve => { settle = resolve; });
  const server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString();
    const answer = (type, text) => {
      response.writeHead(200, {'content-type': type});
      response.end(text);
    };
    if (request.url === '/') return answer('text/html', page);
    if (request.url === '/index.mjs') return answer('text/javascript', module);
    if (request.url === '/vectors') return answer('application/json', vectors);
    if (request.url === '/start') {
      peer = startPeer('responder');
      const {peerId} = JSON.parse(await peer.next());
      peer.send(body);
      socket = await dial(Number(await peer.next()));
      return answer('text/plain', peerId);
    }
    if (request.url === '/send') {
      socket.send(unhex(body));
      return answer('text/plain', toHex(await socket.next()));
    }
    if (request.url === '/last') {
      socket.send(unhex(body));
      sessionId = JSON.parse(await peer.next()).id;
      return answer('text/plain', '');
    }
    if (request.url === '/result') {
      settle(JSON.parse(body));
      return answer('text/plain', '');
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const profile = mkdtempSync(join(tmpdir(), 'coqui-browser-'));
  const running = spawn(browser, [
    '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    // A CI runner's kernel may forbid the sandbox's namespaces; this page is the test's own.
    ...(process.env.CI ? ['--no-sandbox'] : []),
    `--user-data-dir=${profile}`, `http://127.0.0.1:${server.address().port}/`,
  ], {stdio: 'ignore'});
  const closed = new Promise(resolve => running.once('close', resolve));
  try {
    // Node's own test timeout would leave the server and browser holding the process open.
    const report = await Promise.race([
      finished,
      closed.then(() => ({ok: false, error: 'the browser exited with no report'})),
      new Promise(resolve => {
        setTimeout(resolve, 200_000, {ok: false, error: 'the page sent no report'}).unref();
      }),
    ]);
    t.diagnostic(JSON.stringify(report));
    assert.equal(report.ok, true, `${report.error}\n${report.stack}`);
    assert.equal(report.secure, true);
    assert.equal(report.x25519, 'X25519');
    assert.equal(report.extractable, false);
    assert.equal(report.storedExtractable, false);
    assert.equal(report.exported, false);
    assert.equal(report.sameIdentity, true);
    assert.equal(report.publishedVectors, true);
    assert.equal(report.publishedCount, 2);
    assert.deepEqual(report.vectorsAccepted, []);
    assert.equal(report.echo, 'echo:ping from a browser');
    assert.equal(report.id, sessionId);
    assert.equal(report.closed, true);
    assert.equal(await peer.exit, 0, peer.errors());
  } finally {
    socket?.destroy();
    peer?.child.kill();
    running.kill();
    await closed;
    server.close();
    server.closeAllConnections();
    // Chrome's helpers can outlive its main process and still write here, and a directory left in
    // the temporary folder is no reason to fail a test whose assertions passed.
    await rm(profile, {recursive: true, force: true, maxRetries: 10, retryDelay: 200})
      .catch(error => t.diagnostic(`left ${profile} behind: ${error.code}`));
  }
});
