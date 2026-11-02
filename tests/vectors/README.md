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
