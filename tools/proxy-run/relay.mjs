// The relay behind the proxy, as a dishonest carrier would be: it pairs two WebSocket connections by run
// and passes whole messages between them, and on request alters one, repeats one, injects a plain one or
// cuts the connection. It also serves the page, and is the page's way to the driver: a line on stdin is
// the page's next scenario, and a report from the page is a line on stdout.
import {readFileSync} from 'node:fs';
import {createServer} from 'node:http';
import {createInterface} from 'node:readline';
import {accept} from './ws.mjs';

const port = Number(process.argv[2]);
const here = new URL('./', import.meta.url);
const files = {
  '/': ['text/html', readFileSync(new URL('page.html', here))],
  '/page.mjs': ['text/javascript', readFileSync(new URL('page.mjs', here))],
  '/index.mjs': ['text/javascript', readFileSync(new URL('../../bindings/js/coqui-peer-noise/src/index.mjs', here))],
};

const scenarios = [];
const waiting = [];
createInterface({input: process.stdin}).on('line', line => {
  const waiter = waiting.shift();
  if (waiter) waiter(line);
  else scenarios.push(line);
});
process.stdin.on('end', () => process.exit(0));

const say = (kind, body) => process.stdout.write(`${kind} ${JSON.stringify(body)}\n`);

const server = createServer(async (request, response) => {
  if (request.method === 'POST' && request.url === '/report') {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    say('REPORT', JSON.parse(Buffer.concat(chunks).toString()));
    response.writeHead(204);
    response.end();
    return;
  }
  if (request.url === '/next') {
    const line = scenarios.shift() ?? await new Promise(resolve => waiting.push(resolve));
    response.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(line);
    return;
  }
  const file = files[request.url];
  if (!file) {
    response.writeHead(404);
    response.end();
    return;
  }
  response.writeHead(200, {'content-type': file[0], 'cache-control': 'no-store'});
  response.end(file[1]);
});

const runs = new Map();

server.on('upgrade', (request, socket, head) => {
  const url = new URL(request.url, 'http://relay');
  const name = url.pathname.split('/').pop();
  const side = url.searchParams.get('side');
  if (side !== 'browser' && side !== 'rust') {
    socket.destroy();
    return;
  }
  const connection = accept(request, socket, head);
  let run = runs.get(name);
  if (!run) {
    run = {
      name,
      mode: url.searchParams.get('mode') ?? 'pass',
      to: url.searchParams.get('to'),
      at: Number(url.searchParams.get('at') ?? -1),
      ends: {},
      held: {browser: [], rust: []},
      counts: {browser: 0, rust: 0},
      bytes: {browser: 0, rust: 0},
      done: false,
    };
    runs.set(name, run);
  }
  // nginx ended TLS here: this connection is plain, from the proxy, whatever the browser dialled.
  say('RELAY', {run: name, side, encrypted: Boolean(socket.encrypted), from: socket.remoteAddress});
  run.ends[side] = connection;
  const other = side === 'browser' ? 'rust' : 'browser';
  const hand = (to, message) => {
    if (run.ends[to]) run.ends[to].send(message);
    else run.held[to].push(message);
  };
  const finish = how => {
    if (run.done) return;
    run.done = true;
    say('RELAY', {run: name, end: how, counts: run.counts, bytes: run.bytes});
    for (const end of Object.values(run.ends)) how === 'cut' ? end.destroy() : end.close();
  };
  for (const message of run.held[side].splice(0)) connection.send(message);
  connection.onMessage = message => {
    const index = run.counts[other];
    run.counts[other] += 1;
    run.bytes[other] += message.length;
    if (run.to === other && run.at === index) {
      if (run.mode === 'cut') return finish('cut');
      if (run.mode === 'tamper') message[message.length - 1] ^= 1;
      if (run.mode === 'replay') hand(other, message);
      if (run.mode === 'inject') hand(other, Buffer.from('{"jsonrpc":"2.0","method":"injected"}'));
    }
    hand(other, message);
  };
  connection.onClose = () => finish('closed');
});

server.listen(port, '127.0.0.1', () => say('LISTENING', {port}));
