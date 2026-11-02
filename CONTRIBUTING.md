# Contributing to coqui-peer-noise

## Licence

This project is distributed under the **Mozilla Public License 2.0** (`LICENSE`). Its
copyleft is per file:

- **Using coqui-peer-noise imposes nothing on your code.** Depend on the crate and ship a
  closed-source application. The only obligation is that this crate's own source stays
  available to the people you ship it to, which it is, here.
- **Changing this crate's files does carry an obligation.** A modified file must be published
  under the MPL 2.0. Your files beside it are yours, under whatever licence you choose.
- A combined work may be distributed under terms of your choosing (MPL 2.0 section 3.3), and
  MPL 2.0 remains compatible with the GPL.

## Contributor licence agreement

A first pull request needs a one-time signature. The bot will comment with the exact sentence
to reply with; read [`CLA.md`](CLA.md) first. It exists so the project can be relicensed later
without tracking down every past contributor. You keep the copyright in everything you write.

## Before you open a pull request

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --no-default-features -- -D warnings
cargo test --all-features
cargo test --no-default-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cd bindings/js/coqui-peer-noise && npm test
```

All checks must pass. [`AGENTS.md`](AGENTS.md) is the crate's API header and ships in the package, as
`bindings/js/coqui-peer-noise/AGENTS.md` is the JavaScript module's; keep each current with its API
in the same commit. A change to the wire changes [`PROTOCOL.md`](PROTOCOL.md), both implementations and
`tests/vectors/session.json` together (`cargo test --test vectors -- --ignored regenerate`), and a change to pairing
`tests/vectors/pairing.json` (`cargo test --features pin --test pair_vectors -- --ignored regenerate`). Files are LF, on
every platform. The Rust version is 1.89, checked in CI beside stable.
