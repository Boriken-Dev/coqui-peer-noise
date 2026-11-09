use alloc::sync::Arc;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::Error;
use crate::handshake::{PROFILE, field};
use crate::noise::{Cipher, TAGLEN, Transport};

/// What one key may carry by default, before it changes: 2^38, against the 2^38.5 bytes of RFC 8446
/// section 5.5's 2^24.5 full-size AES-GCM records. Each Noise message counts its length and 32.
pub const DEFAULT_KEY_LIMIT: u64 = 1 << 38;

const INNER_DATA: u8 = 1;
const INNER_CLOSE: u8 = 2;
const INNER_KEY_CHANGE: u8 = 3;
const INNER_PART: u8 = 4;
/// Section 3 of the Noise specification: no message is longer.
const MAX_NOISE_MESSAGE: usize = 65535;
/// What one Noise message can hold of an application message: its length less the tag and the type.
const MAX_CONTENT: usize = MAX_NOISE_MESSAGE - TAGLEN - 1;
/// A Noise message with a type and no contents. It stays possible at the limit.
const BARE_MESSAGE: usize = 1 + TAGLEN;
/// A Noise message's blocks beyond its length: the counter block of the tag, and GHASH's length block.
const MESSAGE_OVERHEAD: u64 = 32;
const LENGTH_FIELD: usize = 2;

/// What a message of `length` bytes costs a key.
const fn cost(length: usize) -> u64 {
    (length as u64).saturating_add(MESSAGE_OVERHEAD)
}

/// The length of the record that carries a message of `message_length` bytes: 19 more up to
/// 65518 bytes, and 19 more for each further 65518. A change of key, which a sender makes only at
/// its key limit, adds 19 to the record that holds it.
#[must_use]
pub const fn record_length(message_length: usize) -> usize {
    let parts = message_length.div_ceil(MAX_CONTENT);
    let parts = if parts == 0 { 1 } else { parts };
    message_length.saturating_add(parts.saturating_mul(LENGTH_FIELD + BARE_MESSAGE))
}

/// The settings a session runs under, from the method that made it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) key_limit: u64,
    pub(crate) rekey: bool,
}

/// One direction: its cipher, and what its current key carried.
struct Direction {
    cipher: Cipher,
    charged: u64,
    limit: u64,
    /// Set by either half on a bad record: nothing more is sent or believed.
    failed: Arc<AtomicBool>,
}

impl Direction {
    fn new(cipher: Cipher, limit: u64, failed: Arc<AtomicBool>) -> Self {
        Self {
            cipher,
            charged: 0,
            limit,
            failed,
        }
    }

    fn check(&self) -> Result<(), Error> {
        if self.failed.load(Ordering::SeqCst) {
            return Err(Error::Record);
        }
        Ok(())
    }

    fn fail(&self) -> Error {
        self.failed.store(true, Ordering::SeqCst);
        Error::Record
    }
}

/// The sending half of a [`Session`].
pub struct Sealer {
    direction: Direction,
    rekey: bool,
    closed: bool,
}

impl Sealer {
    /// One message as one record, to send whole and in this order. The message may be of any length:
    /// a record holds as many Noise messages as it takes, each with its own length field and tag. The
    /// transport's frame limit is what bounds it, and a record the transport refuses has already used
    /// its nonces, so the session cannot go on after that.
    ///
    /// # Errors
    ///
    /// [`Error::Record`] after a bad record in either direction, [`Error::Closed`] after
    /// [`close`](Sealer::close). [`Error::LimitReached`] when a Noise message of this record costs
    /// more than [`key_limit`](crate::NoiseSettings::key_limit), or, with
    /// [`rekey(false)`](crate::NoiseSettings::rekey), when this record would pass the limit: nothing
    /// is sent, the session stays intact, and a close still passes. It is also what the last usable
    /// nonce gives, and that ends the session, as section 5 of the Noise specification says.
    pub fn seal(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.direction.check()?;
        if self.closed {
            return Err(Error::Closed);
        }
        self.admit(message.len())?;
        let parts = message.len().div_ceil(MAX_CONTENT).max(1);
        let mut record = Vec::with_capacity(
            message.len() + parts * (2 * LENGTH_FIELD + 2 * BARE_MESSAGE) + LENGTH_FIELD,
        );
        let mut chunks = message.chunks(MAX_CONTENT);
        for part in 0..parts {
            let chunk = chunks.next().unwrap_or_default();
            let cost = cost(chunk.len() + BARE_MESSAGE);
            if self.rekey && self.direction.charged.saturating_add(cost) > self.direction.limit {
                self.push(&mut record, INNER_KEY_CHANGE, &[])?;
                if !self.direction.cipher.rekey() {
                    return Err(self.direction.fail());
                }
                self.direction.charged = 0;
            }
            self.direction.charged = self.direction.charged.saturating_add(cost);
            let kind = if part + 1 == parts {
                INNER_DATA
            } else {
                INNER_PART
            };
            self.push(&mut record, kind, chunk)?;
        }
        Ok(record)
    }

    /// Whether a message of this length can go, before anything of it is sealed.
    fn admit(&self, length: usize) -> Result<(), Error> {
        let parts = length.div_ceil(MAX_CONTENT).max(1);
        let largest = cost(length.min(MAX_CONTENT) + BARE_MESSAGE);
        let total = cost(length + BARE_MESSAGE)
            .saturating_add(cost(BARE_MESSAGE).saturating_mul(parts as u64 - 1));
        let over = largest > self.direction.limit
            || (!self.rekey && self.direction.charged.saturating_add(total) > self.direction.limit);
        if over {
            return Err(Error::LimitReached);
        }
        // A key change may come before each part.
        if self.direction.cipher.remaining() < 2 * (parts as u64) {
            self.direction.fail();
            return Err(Error::LimitReached);
        }
        Ok(())
    }

    /// The record that ends this direction, to send as the last one. It says the stream was not
    /// cut: a peer that never gets it reports [`Error::Truncated`]. Receiving goes on.
    ///
    /// # Errors
    ///
    /// [`Error::Record`] after a bad record in either direction, [`Error::Closed`] when already
    /// closed.
    pub fn close(&mut self) -> Result<Vec<u8>, Error> {
        self.direction.check()?;
        if self.closed {
            return Err(Error::Closed);
        }
        self.closed = true;
        let mut record = Vec::with_capacity(LENGTH_FIELD + BARE_MESSAGE);
        self.push(&mut record, INNER_CLOSE, &[])?;
        Ok(record)
    }

    /// One Noise message, with its length, onto `record`.
    fn push(&mut self, record: &mut Vec<u8>, kind: u8, contents: &[u8]) -> Result<(), Error> {
        let mut inner = Vec::with_capacity(1 + contents.len());
        inner.push(kind);
        inner.extend_from_slice(contents);
        let Some(sealed) = self.direction.cipher.encrypt(&[], &inner) else {
            return Err(self.direction.fail());
        };
        let Ok(length) = u16::try_from(sealed.len()) else {
            return Err(self.direction.fail());
        };
        record.extend_from_slice(&length.to_be_bytes());
        record.extend_from_slice(&sealed);
        Ok(())
    }
}

/// The receiving half of a [`Session`].
pub struct Opener {
    direction: Direction,
    peer_closed: bool,
}

impl Opener {
    /// The message of the next record, or `None` when it is the peer's close record.
    ///
    /// # Errors
    ///
    /// [`Error::Record`] when the record was altered, replayed, reordered, made under other keys,
    /// not in its one shape, or came after the peer's close. [`Error::LimitReached`] when a peer
    /// passes the larger of this side's limit and [`DEFAULT_KEY_LIMIT`] on one key without changing it. Either way nothing after it is believed or
    /// sent, in either direction.
    pub fn open(&mut self, record: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.direction.check()?;
        if self.peer_closed {
            return Err(self.direction.fail());
        }
        let mut message = Vec::new();
        let mut rest = record;
        let mut first = true;
        let mut after_key_change = false;
        loop {
            let (sealed, after) = self.next_message(rest)?;
            rest = after;
            if sealed.len() > BARE_MESSAGE {
                let total = self.direction.charged.saturating_add(cost(sealed.len()));
                if total > self.direction.limit {
                    self.direction.fail();
                    return Err(Error::LimitReached);
                }
                self.direction.charged = total;
            }
            let Some(inner) = self.direction.cipher.decrypt(&[], sealed) else {
                return Err(self.direction.fail());
            };
            let (kind, contents) = inner.split_first().ok_or_else(|| self.direction.fail())?;
            match *kind {
                // A last part is empty only when it is the whole message.
                INNER_DATA if rest.is_empty() && (!contents.is_empty() || message.is_empty()) => {
                    message.extend_from_slice(contents);
                    return Ok(Some(message));
                }
                INNER_CLOSE if first && contents.is_empty() && rest.is_empty() => {
                    self.peer_closed = true;
                    return Ok(None);
                }
                INNER_KEY_CHANGE if contents.is_empty() && !after_key_change => {
                    if !self.direction.cipher.rekey() {
                        return Err(self.direction.fail());
                    }
                    self.direction.charged = 0;
                    after_key_change = true;
                }
                INNER_PART if sealed.len() == MAX_NOISE_MESSAGE => {
                    message.extend_from_slice(contents);
                    after_key_change = false;
                }
                _ => return Err(self.direction.fail()),
            }
            first = false;
        }
    }

    /// The next Noise message of a record and what follows it.
    fn next_message<'a>(&self, record: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), Error> {
        let parsed = record
            .split_first_chunk::<LENGTH_FIELD>()
            .and_then(|(length, rest)| {
                rest.split_at_checked(usize::from(u16::from_be_bytes(*length)))
            });
        match parsed {
            Some((sealed, rest)) if sealed.len() >= BARE_MESSAGE => Ok((sealed, rest)),
            _ => Err(self.direction.fail()),
        }
    }

    /// Call it when the transport ended: whether the stream ended where the peer meant it to.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] when the peer's close record never came, which is what a relay cutting
    /// the connection looks like, and [`Error::Record`] after a bad record.
    pub fn verify_end(&self) -> Result<(), Error> {
        self.direction.check()?;
        if self.peer_closed {
            Ok(())
        } else {
            Err(Error::Truncated)
        }
    }
}

impl fmt::Debug for Sealer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sealer")
    }
}

impl fmt::Debug for Opener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Opener")
    }
}

/// What a finished [`Noise`](crate::Noise) handshake yields: the id and the keys of this session with
/// a peer its [`Trust`](crate::Trust) admitted.
///
/// Only records made with it are tied to the peers that were proved. Anything sent beside them on
/// the same transport comes from whoever controls that transport: a reverse proxy, or a relay that
/// forwarded the whole handshake.
pub struct Session {
    id: [u8; 32],
    sealer: Sealer,
    opener: Opener,
    exporter: Zeroizing<Vec<u8>>,
}

impl Session {
    pub(crate) fn new(transport: Transport, initiator: bool, limits: Limits) -> Self {
        let Transport {
            h,
            initiator_to_responder,
            responder_to_initiator,
            exporter,
        } = transport;
        let (sending, receiving) = if initiator {
            (initiator_to_responder, responder_to_initiator)
        } else {
            (responder_to_initiator, initiator_to_responder)
        };
        let failed = Arc::new(AtomicBool::new(false));
        Self {
            id: h,
            sealer: Sealer {
                direction: Direction::new(sending, limits.key_limit, failed.clone()),
                rekey: limits.rekey,
                closed: false,
            },
            opener: Opener {
                // A peer may run to the default on a key, whatever this side's own sending limit.
                direction: Direction::new(
                    receiving,
                    limits.key_limit.max(DEFAULT_KEY_LIMIT),
                    failed,
                ),
                peer_closed: false,
            },
            exporter,
        }
    }

    /// The id both ends agreed on: Noise's handshake hash. It is not secret, since whoever carried
    /// the handshake and knows any outer binding can compute it; [`export`](Session::export) is.
    #[must_use]
    pub const fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// One message as one record, to send whole and in this order.
    ///
    /// # Errors
    ///
    /// See [`Sealer::seal`].
    pub fn seal(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.sealer.seal(message)
    }

    /// The record that ends this side's direction, to send as the last one.
    ///
    /// # Errors
    ///
    /// See [`Sealer::close`].
    pub fn close(&mut self) -> Result<Vec<u8>, Error> {
        self.sealer.close()
    }

    /// The message of the next record, or `None` when it is the peer's close record.
    ///
    /// # Errors
    ///
    /// See [`Opener::open`].
    pub fn open(&mut self, record: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.opener.open(record)
    }

    /// Call it when the transport ended: whether the stream ended where the peer meant it to.
    ///
    /// # Errors
    ///
    /// See [`Opener::verify_end`].
    pub fn verify_end(&self) -> Result<(), Error> {
        self.opener.verify_end()
    }

    /// The two directions apart, for a reader and a writer on different threads. A bad record at
    /// the opener still stops the sealer. Take any export first.
    #[must_use]
    pub fn split(self) -> (Sealer, Opener) {
        (self.sealer, self.opener)
    }

    /// Fills `out` with key material only this session's two peers can derive. The same `label`
    /// and the same length give the same bytes at both ends; another label or another length gives
    /// unrelated bytes.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] above 8160 bytes, what HKDF-SHA256 can give.
    pub fn export(&self, label: &str, out: &mut [u8]) -> Result<(), Error> {
        let mut info = Vec::with_capacity(128 + label.len());
        field(&mut info, format!("{PROFILE}/export").as_bytes());
        field(&mut info, &self.id);
        field(&mut info, label.as_bytes());
        let length = u32::try_from(out.len()).map_err(|_| Error::TooLong)?;
        info.extend_from_slice(&length.to_be_bytes());
        Hkdf::<Sha256>::new(None, &self.exporter)
            .expand(&info, out)
            .map_err(|_| Error::TooLong)
    }

    #[cfg(test)]
    pub(crate) const fn set_nonces(&mut self, n: u64) {
        self.sealer.direction.cipher.set_nonce(n);
        self.opener.direction.cipher.set_nonce(n);
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Session").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;

    fn session(limits: Limits) -> Session {
        Session::new(
            Transport {
                h: [0; 32],
                initiator_to_responder: Cipher::new(&[1; 32]),
                responder_to_initiator: Cipher::new(&[2; 32]),
                exporter: Zeroizing::new(vec![3; 32]),
            },
            true,
            limits,
        )
    }

    /// Both ends of one connection, the first the initiator.
    fn pair(first: Limits, second: Limits) -> (Session, Session) {
        let ends = |initiator, limits| {
            Session::new(
                Transport {
                    h: [0; 32],
                    initiator_to_responder: Cipher::new(&[1; 32]),
                    responder_to_initiator: Cipher::new(&[2; 32]),
                    exporter: Zeroizing::new(vec![3; 32]),
                },
                initiator,
                limits,
            )
        };
        (ends(true, first), ends(false, second))
    }

    const LIMITS: Limits = Limits {
        key_limit: DEFAULT_KEY_LIMIT,
        rekey: true,
    };

    #[test]
    fn the_last_nonces_of_a_direction_end_the_session_rather_than_reach_the_reserved_one() {
        let mut near = session(LIMITS);
        // The record needs one nonce, and a possible key change one more.
        near.set_nonces(u64::MAX - 2);
        near.seal(b"fits").unwrap();
        assert!(matches!(near.seal(b"no more"), Err(Error::LimitReached)));
        assert!(matches!(near.seal(b"over"), Err(Error::Record)));
        assert!(matches!(near.close(), Err(Error::Record)));
    }

    #[test]
    fn a_record_at_the_reserved_nonce_does_not_open() {
        let mut near = session(LIMITS);
        near.set_nonces(u64::MAX);
        let mut framed = 17u16.to_be_bytes().to_vec();
        framed.extend_from_slice(&[0; 17]);
        assert!(matches!(near.open(&framed), Err(Error::Record)));
        assert!(matches!(near.seal(b"x"), Err(Error::Record)));
    }

    #[test]
    fn a_close_at_the_last_nonce_goes_and_none_after_it() {
        let mut near = session(LIMITS);
        near.set_nonces(u64::MAX - 1);
        near.close().unwrap();
        assert!(matches!(near.close(), Err(Error::Closed)));
    }

    #[test]
    fn a_close_with_no_nonce_left_ends_the_session() {
        let mut near = session(LIMITS);
        near.set_nonces(u64::MAX);
        assert!(matches!(near.close(), Err(Error::Record)));
        assert!(matches!(near.verify_end(), Err(Error::Record)));
    }

    #[test]
    fn a_peer_past_the_default_limit_on_one_key_is_refused_and_the_session_ends() {
        let (mut near, mut far) = pair(LIMITS, LIMITS);
        // 100 bytes cost 117 and 32 more.
        far.opener.direction.charged = DEFAULT_KEY_LIMIT - 149;
        far.open(&near.seal(&[1; 100]).unwrap()).unwrap().unwrap();
        assert!(matches!(
            far.open(&near.seal(&[2; 100]).unwrap()),
            Err(Error::LimitReached)
        ));
        assert!(matches!(far.seal(b"x"), Err(Error::Record)));
    }

    #[test]
    fn a_receiver_limits_a_peer_to_no_less_than_the_default_and_no_more_than_its_own_above_it() {
        let low = Limits {
            key_limit: 10,
            rekey: true,
        };
        let high = Limits {
            key_limit: DEFAULT_KEY_LIMIT * 2,
            rekey: false,
        };
        assert_eq!(
            pair(LIMITS, low).1.opener.direction.limit,
            DEFAULT_KEY_LIMIT
        );
        assert_eq!(
            pair(LIMITS, high).1.opener.direction.limit,
            2 * DEFAULT_KEY_LIMIT
        );
        assert_eq!(pair(LIMITS, low).1.sealer.direction.limit, 10);
    }

    #[test]
    fn a_part_then_an_empty_last_part_is_not_a_message() {
        let (mut near, mut far) = pair(LIMITS, LIMITS);
        let mut record = Vec::new();
        near.sealer
            .push(&mut record, INNER_PART, &[7; MAX_CONTENT])
            .unwrap();
        near.sealer.push(&mut record, INNER_DATA, &[]).unwrap();
        assert!(matches!(far.open(&record), Err(Error::Record)));
        assert!(matches!(far.seal(b"x"), Err(Error::Record)));
    }
}
