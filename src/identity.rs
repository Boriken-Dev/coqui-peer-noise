use alloc::sync::Arc;
use core::fmt;
use std::io::{self, Read as _};
use std::path::Path;

use coqui_peer::file::{self, Access};
use coqui_peer::{KeyMaterial, PeerId, Random};
use data_encoding::BASE64;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::handshake::METHOD;
use crate::noise::DHLEN;

const PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_END: &str = "-----END PRIVATE KEY-----";
const PEM_LINE: usize = 64;
/// The label a [`KeyMaterial`] of this method carries, what standard tools read an SPKI under.
const KEY_LABEL: &str = "PUBLIC KEY";

pub(crate) const SPKI_LEN: usize = 44;
/// RFC 8410's SubjectPublicKeyInfo of an id-X25519 key is this prefix and the 32 key bytes, so
/// comparing it leaves no ASN.1 for two parsers to read differently.
const SPKI_PREFIX: [u8; SPKI_LEN - DHLEN] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
];
const PKCS8_LEN: usize = 48;
/// RFC 8410 section 7's OneAsymmetricKey of an id-X25519 key, with no attributes or public key.
const PKCS8_PREFIX: [u8; PKCS8_LEN - DHLEN] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
];

struct Inner {
    secret: StaticSecret,
    public: [u8; DHLEN],
    spki: [u8; SPKI_LEN],
}

/// A peer's long-term X25519 key: the Noise static key, and the identity itself. Cloning shares one
/// copy of the private key, which is zeroed when the last clone is dropped.
#[derive(Clone)]
pub struct Identity(Arc<Inner>);

/// A key's id and stored form hash this encoding, so that a store's file is readable by standard
/// tools and `openssl pkey -pubout -outform DER | sha256sum` gives the id.
pub(crate) fn spki_of(public: &[u8; DHLEN]) -> [u8; SPKI_LEN] {
    let mut der = [0u8; SPKI_LEN];
    der[..SPKI_PREFIX.len()].copy_from_slice(&SPKI_PREFIX);
    der[SPKI_PREFIX.len()..].copy_from_slice(public);
    der
}

/// The trust store's form of a proven key.
pub(crate) fn key_material(public: &[u8; DHLEN]) -> KeyMaterial {
    KeyMaterial {
        method: METHOD.to_owned(),
        label: KEY_LABEL.to_owned(),
        bytes: spki_of(public).to_vec(),
    }
}

impl Identity {
    fn from_secret(secret: StaticSecret) -> Self {
        let public = PublicKey::from(&secret).to_bytes();
        Self(Arc::new(Inner {
            secret,
            public,
            spki: spki_of(&public),
        }))
    }

    /// A new key from the operating system's generator.
    ///
    /// # Errors
    ///
    /// [`Error::Random`] when the generator fails.
    pub fn generate() -> Result<Self, Error> {
        Self::generate_with(&crate::random())
    }

    /// A new key from `random`, which must be cryptographically secure.
    ///
    /// # Errors
    ///
    /// [`Error::Random`] when the source fails.
    pub fn generate_with(random: &Random) -> Result<Self, Error> {
        let mut bytes = Zeroizing::new([0u8; DHLEN]);
        random.fill(&mut *bytes).map_err(|_| Error::Random)?;
        Ok(Self::from_secret(StaticSecret::from(*bytes)))
    }

    /// The key in a PKCS#8 DER document of RFC 8410's form: 48 bytes, no attributes, no public key.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] when it is not such a key.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        if der.len() != PKCS8_LEN || der[..PKCS8_PREFIX.len()] != PKCS8_PREFIX {
            return Err(Error::Key);
        }
        let mut bytes = Zeroizing::new([0u8; DHLEN]);
        bytes.copy_from_slice(&der[PKCS8_PREFIX.len()..]);
        Ok(Self::from_secret(StaticSecret::from(*bytes)))
    }

    /// The key in PKCS#8 PEM text (`-----BEGIN PRIVATE KEY-----`), as `openssl genpkey -algorithm
    /// x25519` writes it.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] when it is not such a key.
    pub fn from_pkcs8_pem(text: &str) -> Result<Self, Error> {
        let mut lines = text.lines().map(str::trim);
        if !lines.by_ref().any(|line| line == PEM_BEGIN) {
            return Err(Error::Key);
        }
        // Sized up front: a buffer that grew would leave copies of the key in what it freed.
        let mut body = Zeroizing::new(Vec::with_capacity(text.len()));
        let mut ended = false;
        for line in lines {
            if line == PEM_END {
                ended = true;
                break;
            }
            body.extend_from_slice(line.as_bytes());
        }
        if !ended {
            return Err(Error::Key);
        }
        let length = BASE64.decode_len(body.len()).map_err(|_| Error::Key)?;
        let mut der = Zeroizing::new(vec![0u8; length]);
        let written = BASE64.decode_mut(&body, &mut der).map_err(|_| Error::Key)?;
        Self::from_pkcs8_der(&der[..written])
    }

    /// The key as PKCS#8 PEM text, zeroed when dropped.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] when it cannot be encoded.
    pub fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>, Error> {
        let mut der = Zeroizing::new([0u8; PKCS8_LEN]);
        der[..PKCS8_PREFIX.len()].copy_from_slice(&PKCS8_PREFIX);
        der[PKCS8_PREFIX.len()..].copy_from_slice(self.0.secret.as_bytes());
        let mut body = Zeroizing::new(vec![0u8; BASE64.encode_len(PKCS8_LEN)]);
        BASE64.encode_mut(&*der, &mut body);
        let lines = body.len().div_ceil(PEM_LINE);
        let mut pem = Zeroizing::new(String::with_capacity(
            PEM_BEGIN.len() + PEM_END.len() + body.len() + lines + 2,
        ));
        pem.push_str(PEM_BEGIN);
        pem.push('\n');
        for line in body.chunks(PEM_LINE) {
            pem.push_str(core::str::from_utf8(line).map_err(|_| Error::Key)?);
            pem.push('\n');
        }
        pem.push_str(PEM_END);
        pem.push('\n');
        Ok(pem)
    }

    /// The key in the file at `path`, or `None` when there is no file.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when it cannot be read, [`Error::Key`] when it is not such a key.
    pub fn read(path: &Path) -> Result<Option<Self>, Error> {
        let mut file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let size = usize::try_from(file.metadata()?.len()).map_err(|_| Error::Key)?;
        // Room for one more byte, so reading to the end never has to grow the buffer.
        let mut bytes = Zeroizing::new(Vec::with_capacity(size.saturating_add(1)));
        file.read_to_end(&mut bytes)?;
        let text = core::str::from_utf8(&bytes).map_err(|_| Error::Key)?;
        Self::from_pkcs8_pem(text).map(Some)
    }

    /// Writes the key to a new file at `path`, creating its parents. It never replaces a file.
    /// The file is mode `0600` on Unix; on Windows it inherits its directory's ACL.
    ///
    /// # Errors
    ///
    /// [`Error::Io`], of kind `AlreadyExists` when the file exists.
    pub fn write_new(&self, path: &Path) -> Result<(), Error> {
        let pem = self.to_pkcs8_pem()?;
        file::write_new(path, pem.as_bytes(), Access::OwnerOnly)?;
        Ok(())
    }

    /// The key in the file at `path`, generating and writing one when there is none. Of concurrent
    /// creators one wins, and the others read its key.
    ///
    /// # Errors
    ///
    /// As [`read`](Identity::read), [`generate`](Identity::generate) and
    /// [`write_new`](Identity::write_new).
    pub fn open_or_create(path: &Path) -> Result<Self, Error> {
        if let Some(identity) = Self::read(path)? {
            return Ok(identity);
        }
        let identity = Self::generate()?;
        match identity.write_new(path) {
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                Self::read(path)?.ok_or(Error::Key)
            }
            Err(error) => Err(error),
            Ok(()) => Ok(identity),
        }
    }

    /// This peer's id: the SHA-256 of [`spki_der`](Identity::spki_der).
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        PeerId::of(&self.0.spki)
    }

    /// The public key, as RFC 8410's SubjectPublicKeyInfo DER: always 44 bytes.
    #[must_use]
    pub fn spki_der(&self) -> &[u8; SPKI_LEN] {
        &self.0.spki
    }

    /// The public key as the handshake sends it: 32 bytes, RFC 7748's encoding.
    #[must_use]
    pub fn public_key(&self) -> &[u8; DHLEN] {
        &self.0.public
    }

    /// The public key as a trust store holds it: method `noise`, label `PUBLIC KEY`.
    #[must_use]
    pub fn key_material(&self) -> KeyMaterial {
        key_material(&self.0.public)
    }

    pub(crate) fn secret(&self) -> &StaticSecret {
        &self.0.secret
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Identity")
            .field(&self.peer_id())
            .finish()
    }
}
