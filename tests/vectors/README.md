# Test vectors

## `published.json`

The entries for `Noise_XX_25519_AESGCM_SHA256`, copied unchanged from two published files of Noise test vectors, in the
format those files share. Each entry's `source` names its origin:

- `cacophony`: `vectors/cacophony.txt` of [cacophony](https://github.com/haskell-cryptography/cacophony), released into
  the public domain, as carried in the `snow` 0.10.0 crate (`tests/vectors/cacophony.txt`).
- `noise-c`: `tests/vector/noise-c-basic.txt` of [Noise-C](https://github.com/rweather/noise-c), copyright Southern Storm
  Software, Pty Ltd., under the MIT licence.

## `session.json`

This project's own, for its wire. Both implementations read it. Regenerate with
`cargo test --test vectors -- --ignored regenerate`; a change there is a change to the wire.

`pairing.json` is ours: a whole PIN pairing, right and wrong, from `tests/pair_vectors.rs`, which regenerates it with
`cargo test --features pin --test pair_vectors -- --ignored regenerate`. The JavaScript module reproduces it to the byte in
both roles.

`spake2.json` is copied from `test_asymmetric` and `test_password_to_scalar` of the `spake2` crate 0.4.0 (`src/lib.rs`), and is
never regenerated: it is that crate's answer, which the module's arithmetic is checked against.
