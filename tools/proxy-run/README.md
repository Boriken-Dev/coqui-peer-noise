# A real reverse proxy between a real browser and the Rust side

`PROTOCOL.md` says this method works behind a TLS-terminating reverse proxy. This runs that: nginx ends TLS and passes
WebSocket to a small relay, a headless browser is one end, the Rust examples are the other, and the relay spoils the
stream in the ways a dishonest carrier would. It is not part of `npm test` or CI: it needs nginx, and a run takes a
minute. Nothing here is a runtime dependency, and nothing is installed.

```text
browser (module in a page) --wss--> nginx --ws--> relay <--ws-- nginx <--wss-- carrier <--tcp-- Rust example
                                    ends TLS      alters, cuts
```

**The Rust binary does not speak WebSocket or TLS.** The crate has neither, so `run.mjs` carries its frames to the proxy
over a connection of its own, with `ws.mjs` over `node:tls`, trusting only this run's certificate. That connection goes
through nginx as the browser's does. The Noise messages and records are the Rust side's and the module's.

## Running it

Everything binds to loopback, on two random ports. The certificate is made for the run and deleted with it, and the
browser trusts its one key through `--ignore-certificate-errors-spki-list`, so no certificate store changes.

```bash
# Once, in the place nginx will run: unpacks a package and prints the binary's path. Fedora and relatives.
bash tools/proxy-run/fetch-nginx.sh /tmp/coqui-nginx

COQUI_PROXY_NGINX=/tmp/coqui-nginx/usr/bin/nginx \
COQUI_TEST_BROWSER="/path/to/chrome-or-edge" \
node tools/proxy-run/run.mjs
```

| Variable | Meaning |
| --- | --- |
| `COQUI_PROXY_NGINX` | The nginx binary, as the place it runs names it. Any nginx with the SSL module will do. |
| `COQUI_TEST_BROWSER` | Chrome or Edge, as this process names it. |
| `COQUI_PROXY_WSL` | A WSL distribution to run nginx and the relay in, with the browser and the Rust side on Windows. Unset: all here. |
| `COQUI_PROXY_NODE` | The `node` beside nginx. Default `node`. |
| `COQUI_PROXY_IDLE` | The read timeout, in seconds, of the location that shows the proxy ending an idle stream. Default 2. |

It builds the examples with cargo, and exits 0 only when every scenario did what `run.mjs` writes beside it, the access log
shows upgraded connections and the relay saw none of them encrypted. `serve.sh` removes its directory and stops what it
started when its stdin ends, which is when `run.mjs` ends. Remove the directory `fetch-nginx.sh` unpacked into when done.

Only Windows with nginx in WSL has been run; see `PROTOCOL.md` for what ran.

## What it checks

- Both ends through the proxy in each role: records, a 700 KB record spanning several Noise messages, both closes.
- The relay altering, repeating or injecting a record in each direction: refused by the side receiving it.
- The relay cutting at a record boundary, including swallowing a close: a cut, on the side that lost the close. Clean
  WebSocket closes appear here too, with the module still saying truncated.
- nginx's own read timeout ending an idle stream: a cut on both sides.
- PIN pairing from the browser: a sealed record altered, a wrong PIN, the right PIN, and then the ordinary method under
  the key that was paired.

The nginx configuration is `nginx.conf.template`: what a WebSocket proxy needs, and nothing for this method.
