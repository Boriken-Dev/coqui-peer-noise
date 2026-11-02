// RFC 6455 over a socket, both roles, with no dependency: enough for the relay and for the Rust side's
// connection through the proxy. Whole messages in and out; pings answered; no extensions.
import {createHash, randomBytes} from 'node:crypto';
import {connect as tlsConnect} from 'node:tls';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const BINARY = 2;
const CLOSE = 8;
const PING = 9;
const PONG = 10;

function frame(opcode, payload, masked) {
  const length = payload.length;
  const header = [0x80 | opcode];
  const mark = masked ? 0x80 : 0;
  if (length < 126) {
    header.push(mark | length);
  } else if (length < 65536) {
    header.push(mark | 126, length >> 8, length & 0xff);
  } else {
    const wide = Buffer.alloc(8);
    wide.writeBigUInt64BE(BigInt(length));
    header.push(mark | 127, ...wide);
  }
  if (!masked) return Buffer.concat([Buffer.from(header), payload]);
  const mask = randomBytes(4);
  const body = Buffer.from(payload);
  for (let index = 0; index < body.length; index += 1) body[index] ^= mask[index % 4];
  return Buffer.concat([Buffer.from(header), mask, body]);
}

/** `socket` as messages: `send`, `close`, `destroy`, `onMessage(bytes)` and `onClose()`. */
export function attach(socket, masked, initial = Buffer.alloc(0)) {
  let buffered = initial;
  let parts = [];
  let closed = false;
  const connection = {
    onMessage: () => {},
    onClose: () => {},
    send(bytes) {
      if (!closed) socket.write(frame(BINARY, Buffer.from(bytes), masked));
    },
    close() {
      if (!closed) socket.end(frame(CLOSE, Buffer.alloc(0), masked));
    },
    destroy() {
      socket.destroy();
    },
  };
  const parse = () => {
    for (;;) {
      if (buffered.length < 2) return;
      const fin = (buffered[0] & 0x80) !== 0;
      const opcode = buffered[0] & 0x0f;
      const isMasked = (buffered[1] & 0x80) !== 0;
      let length = buffered[1] & 0x7f;
      let offset = 2;
      if (length === 126) {
        if (buffered.length < 4) return;
        length = buffered.readUInt16BE(2);
        offset = 4;
      } else if (length === 127) {
        if (buffered.length < 10) return;
        length = Number(buffered.readBigUInt64BE(2));
        offset = 10;
      }
      const mask = isMasked ? offset : -1;
      if (isMasked) offset += 4;
      if (buffered.length < offset + length) return;
      const payload = Buffer.from(buffered.subarray(offset, offset + length));
      if (isMasked) {
        for (let index = 0; index < length; index += 1) payload[index] ^= buffered[mask + index % 4];
      }
      buffered = buffered.subarray(offset + length);
      if (opcode === CLOSE) {
        connection.close();
        return;
      }
      if (opcode === PING) {
        if (!closed) socket.write(frame(PONG, payload, masked));
      } else if (opcode !== PONG) {
        parts.push(payload);
        if (fin) {
          connection.onMessage(Buffer.concat(parts));
          parts = [];
        }
      }
    }
  };
  socket.on('data', chunk => {
    buffered = Buffer.concat([buffered, chunk]);
    parse();
  });
  const ended = () => {
    if (closed) return;
    closed = true;
    connection.onClose();
  };
  socket.on('close', ended);
  socket.on('end', ended);
  socket.on('error', ended);
  queueMicrotask(parse);
  return connection;
}

/** Answers an HTTP upgrade request as a server. */
export function accept(request, socket, head) {
  const key = createHash('sha1').update(request.headers['sec-websocket-key'] + GUID).digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${key}\r\n\r\n`,
  );
  socket.setNoDelay(true);
  return attach(socket, false, head);
}

/** A client over TLS that trusts only `ca`, checks the name, and refuses any other answer than 101. */
export function connect({host, port, path, ca, servername}) {
  return new Promise((resolve, reject) => {
    const socket = tlsConnect({host, port, ca, servername, ALPNProtocols: ['http/1.1']});
    socket.setNoDelay(true);
    socket.once('error', reject);
    socket.once('secureConnect', () => {
      const key = randomBytes(16).toString('base64');
      socket.write(
        `GET ${path} HTTP/1.1\r\nHost: ${servername}:${port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
        `Sec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
      );
      let answer = Buffer.alloc(0);
      const onData = chunk => {
        answer = Buffer.concat([answer, chunk]);
        const end = answer.indexOf('\r\n\r\n');
        if (end < 0) return;
        socket.off('data', onData);
        const status = answer.subarray(0, end).toString();
        const expected = createHash('sha1').update(key + GUID).digest('base64');
        if (!status.startsWith('HTTP/1.1 101') || !status.includes(expected)) {
          socket.destroy();
          reject(new Error(`the proxy answered: ${status.split('\r\n')[0]}`));
          return;
        }
        resolve({connection: attach(socket, true, answer.subarray(end + 4)), protocol: socket.getProtocol()});
      };
      socket.on('data', onData);
    });
  });
}

