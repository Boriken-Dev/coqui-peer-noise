//! What the integration tests share: a run of the exchange, scripted random sources, and an attacker
//! that computes Noise for itself, apart from what `src/noise.rs` does.
#![allow(dead_code, reason = "each test binary uses a part of this")]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use coqui_peer::{Established, Handshake, Method};
use coqui_peer_noise::{Error, Identity, Noise, NoiseHandshake, Random, Session, Trust};
use hkdf::Hkdf;
use sha2::{Digest as _, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
];

/// An identity from its 32 private key bytes.
pub fn identity_of(raw: [u8; 32]) -> Identity {
    Identity::from_pkcs8_der(&pkcs8(raw)).unwrap()
}

pub fn pkcs8(raw: [u8; 32]) -> Vec<u8> {
    let mut der = PKCS8_PREFIX.to_vec();
    der.extend_from_slice(&raw);
    der
}

/// A pair of identities that pin each other, as methods.
pub fn pinned_pair() -> (Identity, Identity, Noise, Noise) {
    pinned_pair_with(coqui_peer_noise::random())
}

/// As [`pinned_pair`], both sides drawing from `random`.
pub fn pinned_pair_with(random: coqui_peer_noise::Random) -> (Identity, Identity, Noise, Noise) {
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = Noise::builder()
        .identity(client.clone())
        .responders(Trust::pinned([server.peer_id()]))
        .random(random.clone())
        .build()
        .unwrap();
    let listening = Noise::builder()
        .identity(server.clone())
        .initiators(Trust::pinned([client.peer_id()]))
        .random(random)
        .build()
        .unwrap();
    (client, server, dialing, listening)
}

/// Moves messages between the two sides until both finish or one fails.
pub fn exchange(a: &mut NoiseHandshake, b: &mut NoiseHandshake) -> Result<(), Error> {
    while !(a.is_complete() && b.is_complete()) {
        let mut moved = false;
        while let Some(message) = a.transmit()? {
            b.receive(&message)?;
            moved = true;
        }
        while let Some(message) = b.transmit()? {
            a.receive(&message)?;
            moved = true;
        }
        assert!(moved, "the exchange stalled");
    }
    Ok(())
}

/// A whole run between two configured methods.
pub fn run(
    dialing: &Noise,
    listening: &Noise,
) -> Result<(Established<Session>, Established<Session>), Error> {
    let (mut a, mut b) = (dialing.initiate()?, listening.respond(None)?);
    exchange(&mut a, &mut b)?;
    Ok((a.finish()?, b.finish()?))
}

/// Two sessions that pin each other.
pub fn sessions() -> (Session, Session) {
    let (_, _, dialing, listening) = pinned_pair();
    let (near, far) = run(&dialing, &listening).unwrap();
    (near.session, far.session)
}

/// The three messages of a run, each as sent.
pub fn messages(a: &mut NoiseHandshake, b: &mut NoiseHandshake) -> Result<[Vec<u8>; 3], Error> {
    let first = a.transmit()?.expect("the first message");
    b.receive(&first)?;
    let second = b.transmit()?.expect("the second message");
    a.receive(&second)?;
    let third = a.transmit()?.expect("the third message");
    b.receive(&third)?;
    Ok([first, second, third])
}

/// A source that hands out exactly `chunks`, for a reproducible run.
pub fn scripted(chunks: &[[u8; 32]]) -> Random {
    let queue: VecDeque<[u8; 32]> = chunks.iter().copied().collect();
    let queue = Arc::new(Mutex::new(queue));
    Random::from_fn(move |out| {
        let next = queue.lock().unwrap().pop_front().expect("a scripted draw");
        out.copy_from_slice(&next);
        Ok(())
    })
}

pub fn public_of(raw: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(raw)).to_bytes()
}

pub fn dh_of(raw: [u8; 32], peer: [u8; 32]) -> [u8; 32] {
    StaticSecret::from(raw)
        .diffie_hellman(&PublicKey::from(peer))
        .to_bytes()
}

/// The encoding of RFC 7748's p = 2^255 - 19, plus `add` (at most 18).
pub fn p_plus(add: u8) -> [u8; 32] {
    let mut p = [0xffu8; 32];
    p[0] = 0xed + add;
    p[31] = 0x7f;
    p
}

/// The canonical encodings of points of small order on Curve25519.
pub fn small_order() -> [[u8; 32]; 5] {
    let mut one = [0u8; 32];
    one[0] = 1;
    // p - 1, then two points of order 8. tests/identity.rs checks X25519 gives all zeros for each.
    let mut minus_one = p_plus(0);
    minus_one[0] = 0xec;
    [
        [0u8; 32],
        one,
        minus_one,
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
    ]
}

/// A Noise SymmetricState computed by the test, to make messages the code would never send.
#[derive(Clone)]
pub struct Attacker {
    pub ck: [u8; 32],
    pub h: [u8; 32],
    key: Option<[u8; 32]>,
    n: u64,
}

impl Attacker {
    pub fn new(prologue: &[u8]) -> Self {
        let mut h = [0u8; 32];
        h[..28].copy_from_slice(b"Noise_XX_25519_AESGCM_SHA256");
        let mut state = Self {
            ck: h,
            h,
            key: None,
            n: 0,
        };
        state.mix_hash(prologue);
        state
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hash = Sha256::new();
        hash.update(self.h);
        hash.update(data);
        self.h = hash.finalize().into();
    }

    pub fn mix_key(&mut self, input: &[u8]) {
        let mut okm = [0u8; 64];
        Hkdf::<Sha256>::new(Some(&self.ck), input)
            .expand(&[], &mut okm)
            .unwrap();
        self.ck.copy_from_slice(&okm[..32]);
        self.key = Some(okm[32..].try_into().unwrap());
        self.n = 0;
    }

    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let key = self.key.expect("a key is mixed in");
        let out = aead(&key, self.n, &self.h, plaintext);
        self.n += 1;
        self.mix_hash(&out);
        out
    }

    /// The transport keys and the export secret, as `Split` and the third output give them.
    pub fn split(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let mut okm = [0u8; 96];
        Hkdf::<Sha256>::new(Some(&self.ck), &[])
            .expand(&[], &mut okm)
            .unwrap();
        (
            okm[..32].try_into().unwrap(),
            okm[32..64].try_into().unwrap(),
            okm[64..].try_into().unwrap(),
        )
    }
}

/// AES-256-GCM as section 12.4 of the Noise specification has it.
pub fn aead(key: &[u8; 32], n: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut iv = [0u8; 12];
    iv[4..].copy_from_slice(&n.to_be_bytes());
    Aes256Gcm::new_from_slice(key)
        .unwrap()
        .encrypt(
            &iv.into(),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .unwrap()
}

/// REKEY of `key`.
pub fn rekeyed(key: &[u8; 32]) -> [u8; 32] {
    let out = aead(key, u64::MAX, &[], &[0u8; 32]);
    out[..32].try_into().unwrap()
}

/// One direction made by the test: Noise messages with any inner type, framed as records are.
pub struct Forger {
    pub key: [u8; 32],
    pub n: u64,
}

impl Forger {
    pub const fn new(key: [u8; 32]) -> Self {
        Self { key, n: 0 }
    }

    /// One framed Noise message holding this type and these contents.
    pub fn message(&mut self, kind: u8, contents: &[u8]) -> Vec<u8> {
        let mut inner = vec![kind];
        inner.extend_from_slice(contents);
        let sealed = aead(&self.key, self.n, &[], &inner);
        self.n += 1;
        let mut framed = u16::try_from(sealed.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(&sealed);
        framed
    }

    pub fn rekey(&mut self) {
        self.key = rekeyed(&self.key);
    }
}
