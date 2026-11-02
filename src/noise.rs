//! The objects of the Noise specification (revision 34, section 5), for the one pattern and the one
//! set of functions this method uses. Nothing here does I/O or decides trust.

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::{Digest as _, Sha256};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::identity::Identity;

/// The Noise protocol name this method runs. There is no other, and no negotiation of it.
pub const PROTOCOL_NAME: &str = "Noise_XX_25519_AESGCM_SHA256";

pub(crate) const DHLEN: usize = 32;
pub(crate) const TAGLEN: usize = 16;
const HASHLEN: usize = 32;
const KEYLEN: usize = 32;
/// Section 5.1 reserves this nonce: no message uses it, and REKEY does.
const RESERVED_NONCE: u64 = u64::MAX;

/// A CipherState holding a key. The cipher is on the heap, so moving this value copies no round
/// keys, and it is zeroed when replaced or dropped.
pub(crate) struct Cipher {
    cipher: Box<Aes256Gcm>,
    n: u64,
}

impl Cipher {
    pub(crate) fn new(key: &[u8]) -> Self {
        Self {
            cipher: Self::keyed(key),
            n: 0,
        }
    }

    fn keyed(key: &[u8]) -> Box<Aes256Gcm> {
        Box::new(Aes256Gcm::new_from_slice(key).expect("a cipher key is 32 bytes"))
    }

    /// Section 12.4: 32 zero bits, then the nonce big-endian.
    fn iv(n: u64) -> Nonce<U12> {
        let mut iv = Nonce::<U12>::default();
        iv[4..].copy_from_slice(&n.to_be_bytes());
        iv
    }

    /// `None` once the nonces are used up, which section 5 says ends the session.
    pub(crate) fn encrypt(&mut self, ad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
        if self.n == RESERVED_NONCE {
            return None;
        }
        let payload = Payload {
            msg: plaintext,
            aad: ad,
        };
        let out = self.cipher.encrypt(&Self::iv(self.n), payload).ok()?;
        self.n += 1;
        Some(out)
    }

    /// `None` when it does not authenticate, or once the nonces are used up.
    pub(crate) fn decrypt(&mut self, ad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        if self.n == RESERVED_NONCE {
            return None;
        }
        let payload = Payload {
            msg: ciphertext,
            aad: ad,
        };
        let out = self.cipher.decrypt(&Self::iv(self.n), payload).ok()?;
        self.n += 1;
        Some(out)
    }

    /// Section 4.2's REKEY: the first 32 bytes of encrypting 32 zero bytes at the reserved nonce.
    /// The nonce carries on, as section 11.3 says. `false` when the cipher refused.
    pub(crate) fn rekey(&mut self) -> bool {
        let zeros = [0u8; KEYLEN];
        let Ok(next) = self
            .cipher
            .encrypt(&Self::iv(RESERVED_NONCE), zeros.as_slice())
        else {
            return false;
        };
        let next = Zeroizing::new(next);
        self.cipher = Self::keyed(&next[..KEYLEN]);
        true
    }

    /// How many more messages this direction may still carry.
    pub(crate) const fn remaining(&self) -> u64 {
        RESERVED_NONCE - self.n
    }

    #[cfg(test)]
    pub(crate) const fn set_nonce(&mut self, n: u64) {
        self.n = n;
    }
}

/// What a finished handshake leaves. `h` is section 11.2's handshake hash.
pub(crate) struct Transport {
    pub(crate) h: [u8; HASHLEN],
    pub(crate) initiator_to_responder: Cipher,
    pub(crate) responder_to_initiator: Cipher,
    pub(crate) exporter: Zeroizing<Vec<u8>>,
}

/// The SymmetricState. It lives behind a `Box`, so `ck` is not copied by moves of what holds it.
pub(crate) struct SymmetricState {
    ck: Zeroizing<[u8; HASHLEN]>,
    h: [u8; HASHLEN],
    cipher: Option<Cipher>,
}

impl SymmetricState {
    /// InitializeSymmetric, then MixHash of the prologue.
    pub(crate) fn new(prologue: &[u8]) -> Box<Self> {
        // The name is shorter than HASHLEN, so section 5.2 pads it rather than hashing it.
        let mut h = [0u8; HASHLEN];
        h[..PROTOCOL_NAME.len()].copy_from_slice(PROTOCOL_NAME.as_bytes());
        let mut state = Box::new(Self {
            ck: Zeroizing::new(h),
            h,
            cipher: None,
        });
        state.mix_hash(prologue);
        state
    }

    pub(crate) fn mix_hash(&mut self, data: &[u8]) {
        let mut hash = Sha256::new();
        hash.update(self.h);
        hash.update(data);
        self.h.copy_from_slice(&hash.finalize());
    }

    pub(crate) fn mix_key(&mut self, input: &[u8]) {
        let mut okm = Zeroizing::new([0u8; 2 * HASHLEN]);
        // Section 4.3: Noise's HKDF is RFC 5869's with `ck` as salt and no info.
        Hkdf::<Sha256>::new(Some(&*self.ck), input)
            .expand(&[], &mut *okm)
            .expect("64 bytes is within what HKDF-SHA256 gives");
        self.ck.copy_from_slice(&okm[..HASHLEN]);
        self.cipher = Some(Cipher::new(&okm[HASHLEN..]));
    }

    pub(crate) fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let out = match self.cipher.as_mut() {
            Some(cipher) => cipher.encrypt(&self.h, plaintext).ok_or(Error::BadProof)?,
            None => plaintext.to_vec(),
        };
        self.mix_hash(&out);
        Ok(out)
    }

    pub(crate) fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let out = match self.cipher.as_mut() {
            Some(cipher) => cipher.decrypt(&self.h, ciphertext).ok_or(Error::BadProof)?,
            None => ciphertext.to_vec(),
        };
        self.mix_hash(ciphertext);
        Ok(out)
    }

    /// Split, and the third output of its HKDF, which section 5.2 leaves unused, as the secret of
    /// exports: it is independent of the two cipher keys and never touches a record.
    fn split(&self) -> Transport {
        let mut okm = Zeroizing::new([0u8; 3 * HASHLEN]);
        Hkdf::<Sha256>::new(Some(&*self.ck), &[])
            .expand(&[], &mut *okm)
            .expect("96 bytes is within what HKDF-SHA256 gives");
        let mut exporter = Zeroizing::new(Vec::with_capacity(HASHLEN));
        exporter.extend_from_slice(&okm[2 * HASHLEN..]);
        Transport {
            h: self.h,
            initiator_to_responder: Cipher::new(&okm[..HASHLEN]),
            responder_to_initiator: Cipher::new(&okm[HASHLEN..2 * HASHLEN]),
            exporter,
        }
    }
}

/// Whether `key` is the one encoding of a value. RFC 7748 section 5 has X25519 mask the top bit and
/// reduce modulo p, so without this one value would have several encodings, and so ids. It does not
/// make one private key one id: `PROTOCOL.md` says what a point of order 8 does.
pub(crate) fn is_canonical(key: &[u8; DHLEN]) -> bool {
    // At or above p = 2^255 - 19 with the top bit clear, the encoding is ed, ee or ef up to ff, then
    // 30 bytes of ff, then 7f. These are public values, so the branches reveal nothing secret.
    let at_or_above_p = key[31] == 0x7f && key[0] >= 0xed && key[1..31].iter().all(|b| *b == 0xff);
    key[31] & 0x80 == 0 && !at_or_above_p
}

fn public_key(bytes: &[u8]) -> Result<[u8; DHLEN], Error> {
    let key: [u8; DHLEN] = bytes.try_into().map_err(|_| Error::Malformed)?;
    if is_canonical(&key) {
        Ok(key)
    } else {
        Err(Error::Malformed)
    }
}

/// X25519, refusing a small-order peer key. Section 12.1 allows this. Without it a peer could prove
/// a static key it holds no private key for, since its DH output would be known to be all zeros.
fn dh(secret: &StaticSecret, peer: &[u8; DHLEN]) -> Result<SharedSecret, Error> {
    let shared = secret.diffie_hellman(&PublicKey::from(*peer));
    if shared.was_contributory() {
        Ok(shared)
    } else {
        Err(Error::Malformed)
    }
}

/// The HandshakeState of pattern XX. `next` is the message number, 0 to 2.
pub(crate) struct Xx {
    symmetric: Box<SymmetricState>,
    initiator: bool,
    local: Identity,
    ephemeral: Box<StaticSecret>,
    remote_ephemeral: Option<[u8; DHLEN]>,
    remote_static: Option<[u8; DHLEN]>,
    next: u8,
}

impl Xx {
    pub(crate) fn new(
        initiator: bool,
        prologue: &[u8],
        local: Identity,
        ephemeral: Box<StaticSecret>,
    ) -> Self {
        Self {
            symmetric: SymmetricState::new(prologue),
            initiator,
            local,
            ephemeral,
            remote_ephemeral: None,
            remote_static: None,
            next: 0,
        }
    }

    pub(crate) const fn remote_static(&self) -> Option<&[u8; DHLEN]> {
        self.remote_static.as_ref()
    }

    /// The test's way to go on from a real exchange as an attacker would.
    #[cfg(test)]
    pub(crate) fn symmetric_mut(&mut self) -> &mut SymmetricState {
        &mut self.symmetric
    }

    fn peer_ephemeral(&self) -> Result<[u8; DHLEN], Error> {
        self.remote_ephemeral.ok_or(Error::State)
    }

    fn peer_static(&self) -> Result<[u8; DHLEN], Error> {
        self.remote_static.ok_or(Error::State)
    }

    fn mix_ee(&mut self) -> Result<(), Error> {
        let shared = dh(&self.ephemeral, &self.peer_ephemeral()?)?;
        self.symmetric.mix_key(shared.as_bytes());
        Ok(())
    }

    /// `es` from the side that holds the ephemeral key of the pair, or the static one.
    fn mix_ephemeral_static(&mut self) -> Result<(), Error> {
        let shared = dh(&self.ephemeral, &self.peer_static()?)?;
        self.symmetric.mix_key(shared.as_bytes());
        Ok(())
    }

    fn mix_static_ephemeral(&mut self) -> Result<(), Error> {
        let shared = dh(self.local.secret(), &self.peer_ephemeral()?)?;
        self.symmetric.mix_key(shared.as_bytes());
        Ok(())
    }

    fn write_ephemeral(&mut self, out: &mut Vec<u8>) {
        let public = PublicKey::from(&*self.ephemeral).to_bytes();
        out.extend_from_slice(&public);
        self.symmetric.mix_hash(&public);
    }

    fn read_ephemeral<'a>(&mut self, message: &'a [u8]) -> Result<&'a [u8], Error> {
        let (key, rest) = message.split_at_checked(DHLEN).ok_or(Error::Malformed)?;
        let key = public_key(key)?;
        self.symmetric.mix_hash(&key);
        self.remote_ephemeral = Some(key);
        Ok(rest)
    }

    fn write_static(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        let sealed = self
            .symmetric
            .encrypt_and_hash(self.local.public_key().as_slice())?;
        out.extend_from_slice(&sealed);
        Ok(())
    }

    fn read_static<'a>(&mut self, message: &'a [u8]) -> Result<&'a [u8], Error> {
        let (sealed, rest) = message
            .split_at_checked(DHLEN + TAGLEN)
            .ok_or(Error::Malformed)?;
        let key = self.symmetric.decrypt_and_hash(sealed)?;
        self.remote_static = Some(public_key(&key)?);
        Ok(rest)
    }

    /// WriteMessage.
    pub(crate) fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(2 * DHLEN + 2 * TAGLEN + payload.len());
        match (self.next, self.initiator) {
            (0, true) => self.write_ephemeral(&mut out),
            (1, false) => {
                self.write_ephemeral(&mut out);
                self.mix_ee()?;
                self.write_static(&mut out)?;
                self.mix_static_ephemeral()?;
            }
            (2, true) => {
                self.write_static(&mut out)?;
                self.mix_static_ephemeral()?;
            }
            _ => return Err(Error::State),
        }
        out.extend_from_slice(&self.symmetric.encrypt_and_hash(payload)?);
        self.next += 1;
        Ok(out)
    }

    /// ReadMessage. Its result is the payload, and a static key read on the way is
    /// [`remote_static`](Xx::remote_static). The proof of that key is that this returned `Ok`: the
    /// payload's tag depends on the DH of the private key.
    pub(crate) fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let rest = match (self.next, self.initiator) {
            (0, false) => self.read_ephemeral(message)?,
            (1, true) => {
                let rest = self.read_ephemeral(message)?;
                self.mix_ee()?;
                let rest = self.read_static(rest)?;
                self.mix_ephemeral_static()?;
                rest
            }
            (2, false) => {
                let rest = self.read_static(message)?;
                self.mix_ephemeral_static()?;
                rest
            }
            _ => return Err(Error::State),
        };
        let payload = self.symmetric.decrypt_and_hash(rest)?;
        self.next += 1;
        Ok(payload)
    }

    /// Split, once all three messages went. `Error::State` before that.
    pub(crate) fn split(&self) -> Result<Transport, Error> {
        if self.next == 3 {
            Ok(self.symmetric.split())
        } else {
            Err(Error::State)
        }
    }
}

#[cfg(test)]
mod tests;
