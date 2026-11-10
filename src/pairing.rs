use core::fmt;
use core::net::SocketAddr;
use core::time::Duration;
use std::io;
use std::time::Instant;

use coqui_builder::NonDefault;
use coqui_peer::pair::{
    Channel, PairRefusal, Paired, Pairing, PairingDesk, PairingError, PairingJoiner,
    PairingResponder, Shown,
};
use coqui_peer::{
    Established, Framing, Handshake, KeyMaterial, MessageTransport, Method, PeerId, Random,
    TrustStore,
};

use crate::error::Error;
use crate::framed::CurrentReadTimeout;
use crate::handshake::{METHOD, Noise, NoiseHandshake, PURPOSE_PAIR, random_entry};
use crate::identity::Identity;
use crate::session::Session;
use crate::settings::PairingSettings;
use crate::trust::{Admit, Trust};

/// The export label [`PairingSession::pair_channel`] binds a pairing to.
pub const PAIR_EXPORT_LABEL: &str = "EXPORTER-coqui-pair";

/// The longest record a [`PairingSession`] exchanges: a device code or label of 255 bytes, its
/// message's 76 bytes around that, and the 19 bytes a message costs as a record. A
/// [`FramedStream`](crate::FramedStream) carrying the exchange takes it through
/// [`set_max_message`](crate::FramedStream::set_max_message).
pub const MAX_PAIRING_RECORD: usize = 350;

/// How long a responder waits for a joiner's first message, unless told otherwise: a stranger who
/// proved a key and says nothing holds a connection for this long, with no desk limit applying yet.
pub const DEFAULT_FIRST_MESSAGE_TIMEOUT: Duration = Duration::from_secs(60);

/// `PROTOCOL.md`'s refused message: version, kind, why (expired). A [`PairingResponder`] has a
/// deadline to refuse by only from the joiner's first message.
const EXPIRED_REFUSAL: [u8; 3] = [1, 8, 2];

/// How many reads in a row that time out with time left, and no record between, are taken as ended
/// early by the operating system. One more ends the exchange as expired.
const MAX_EARLY_TIMEOUTS: u32 = 3;

/// The method for a connection that only pairs: the responder admits whoever proves a key, since a
/// joiner is a stranger, and what it ends in is a [`PairingSession`], which carries the pairing
/// exchange and nothing else. No application message can pass over it.
///
/// A joiner that knows who it is reaching says so with
/// [`responders`](PairingMethodBuilder::responders); an invitation and the device flow need it.
#[derive(Clone)]
pub struct PairingMethod {
    noise: Noise,
    first_message_timeout: Option<Duration>,
}

/// What a [`PairingMethodBuilder`] collects: the settings and the inputs.
///
/// The identity is required. The random source is the operating system's unless given. Build the
/// method with [`PairingMethod::builder`]; `build` gives [`Error::Settings`] when the
/// first-message timeout is `Some(Duration::ZERO)`.
#[derive(coqui_builder::Builder, Debug)]
#[builder(build = PairingMethod, fallible)]
pub struct PairingMethodParts {
    settings: PairingSettings,
    /// The identity this method proves.
    #[builder(input)]
    identity: Identity,
    /// Whom a joiner accepts: a pin or a store. The session is then verified, which the device
    /// flow asks for; the key an invitation names must be the proved one in any case.
    #[builder(input)]
    responders: Option<Trust>,
    /// Where ephemeral keys come from, as [`NoiseParts`](crate::NoiseParts)'s `random`. The PAKE's
    /// own random source is the [`Pairing`]'s and the [`PairingDesk`]'s.
    #[builder(input)]
    random: Option<Random>,
}

impl TryFrom<PairingMethodParts> for PairingMethod {
    type Error = Error;

    /// The method, as a responder admitting any proved key, and as a joiner accepting any proved
    /// key unless `responders` is given.
    ///
    /// # Errors
    ///
    /// [`Error::Settings`] when the first-message timeout is `Some(Duration::ZERO)`.
    fn try_from(parts: PairingMethodParts) -> Result<Self, Error> {
        if parts.settings.first_message_timeout == Some(Duration::ZERO) {
            return Err(Error::Settings);
        }
        Ok(PairingMethod {
            noise: Noise::configured(
                parts.identity,
                PURPOSE_PAIR,
                parts.settings.noise(),
                Some(parts.responders.map_or(Admit::Any, Admit::Trust)),
                Some(Admit::Any),
                parts.random,
            ),
            first_message_timeout: parts.settings.first_message_timeout,
        })
    }
}

impl PairingMethod {
    /// This method's identity.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        self.noise.identity()
    }

    /// The settings it was built with.
    #[must_use]
    pub fn settings(&self) -> PairingSettings {
        let noise = self.noise.settings();
        PairingSettings {
            key_limit: noise.key_limit,
            rekey: noise.rekey,
            first_message_timeout: self.first_message_timeout,
        }
    }

    /// Every setting that differs from its default, named by key path, and `random` when the
    /// ephemeral keys do not come from the operating system. A pairing method admits any proved key
    /// by definition, so that is not listed.
    #[must_use]
    pub fn non_defaults(&self) -> Vec<NonDefault> {
        let mut non_defaults = coqui_builder::non_defaults(&self.settings());
        if self.noise.random_replaced() {
            non_defaults.push(random_entry());
        }
        non_defaults
    }
}

impl fmt::Debug for PairingMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingMethod")
            .field("noise", &self.noise)
            .field("first_message_timeout", &self.first_message_timeout)
            .finish()
    }
}

impl Method for PairingMethod {
    type Handshake = PairingHandshake;

    fn name(&self) -> &'static str {
        METHOD
    }

    /// Starts a handshake as the joiner; its first message is ready to
    /// [`transmit`](Handshake::transmit).
    ///
    /// # Errors
    ///
    /// [`Error::Random`] when the generator fails.
    fn initiate(&self) -> Result<PairingHandshake, Error> {
        Ok(PairingHandshake {
            handshake: self.noise.initiate()?,
            local: self.noise.identity().key_material(),
            verified: self.noise.verifies_responders(),
            first_message_timeout: self.first_message_timeout,
        })
    }

    /// Starts a handshake as the responder.
    ///
    /// # Errors
    ///
    /// None in practice: this role is always configured.
    fn respond(&self, source: Option<SocketAddr>) -> Result<PairingHandshake, Error> {
        Ok(PairingHandshake {
            handshake: self.noise.respond(source)?,
            local: self.noise.identity().key_material(),
            verified: false,
            first_message_timeout: self.first_message_timeout,
        })
    }
}

/// One run of the [`PairingMethod`], driven by the caller. `Output` is the [`PairingSession`].
pub struct PairingHandshake {
    handshake: NoiseHandshake,
    local: KeyMaterial,
    verified: bool,
    first_message_timeout: Option<Duration>,
}

impl fmt::Debug for PairingHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingHandshake")
            .field("complete", &self.handshake.is_complete())
            .finish_non_exhaustive()
    }
}

impl Handshake for PairingHandshake {
    type Output = PairingSession;
    type Error = Error;

    fn framing(&self) -> Framing {
        Framing::Message
    }

    fn receive(&mut self, input: &[u8]) -> Result<(), Error> {
        self.handshake.receive(input)
    }

    fn transmit(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.handshake.transmit()
    }

    fn is_complete(&self) -> bool {
        self.handshake.is_complete()
    }

    fn finish(self) -> Result<Established<PairingSession>, Error> {
        let Established { peer, key, session } = self.handshake.finish()?;
        let proved = key.ok_or(Error::State)?;
        Ok(Established {
            peer,
            key: Some(proved.clone()),
            session: PairingSession {
                session,
                local: self.local,
                peer: proved,
                verified: self.verified,
                first_message_timeout: self.first_message_timeout,
            },
        })
    }
}

/// What a [`PairingMethod`] handshake yields: a proved key that is nobody yet. It runs one
/// [`coqui_peer::pair`] exchange with its messages sealed, and offers nothing else: after the
/// exchange, both sides reconnect under [`Noise`].
///
/// It carries no application message:
///
/// ```compile_fail
/// fn send(session: &mut coqui_peer_noise::PairingSession) {
///     let _ = session.seal(b"anything");
/// }
/// ```
pub struct PairingSession {
    session: Session,
    local: KeyMaterial,
    peer: KeyMaterial,
    verified: bool,
    first_message_timeout: Option<Duration>,
}

impl fmt::Debug for PairingSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingSession")
            .field("peer", &self.peer.id())
            .field("verified", &self.verified)
            .finish_non_exhaustive()
    }
}

impl PairingSession {
    /// The id both ends agreed on, as [`Session::id`].
    #[must_use]
    pub const fn id(&self) -> &[u8; 32] {
        self.session.id()
    }

    /// The key the peer proved.
    #[must_use]
    pub const fn peer(&self) -> &KeyMaterial {
        &self.peer
    }

    /// The id of the key the peer proved.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.peer.id()
    }

    /// The [`Channel`] an exchange runs on: `local` this side's key, `remote` the key this handshake
    /// proved, which no caller can name instead, `verified` when a joiner's
    /// [`responders`](PairingMethodBuilder::responders) admitted the peer, and `binding` a 32-byte
    /// export under [`PAIR_EXPORT_LABEL`], tying the exchange to this session and not to any TLS
    /// connection beneath it.
    ///
    /// # Errors
    ///
    /// None in practice: 32 bytes are within what [`Session::export`] gives.
    pub fn pair_channel(&self) -> Result<Channel, Error> {
        let mut binding = vec![0u8; 32];
        self.session.export(PAIR_EXPORT_LABEL, &mut binding)?;
        Ok(Channel {
            local: self.local.clone(),
            remote: Some(self.peer.clone()),
            verified: self.verified,
            binding: Some(binding),
        })
    }

    /// Joins with `pairing`, each message sealed, until there is something to show a person
    /// ([`PairDial::shown`]) or the end. An invitation's secret is only ever sent sealed, and
    /// [`Pairing::join`] refuses unless the proved key is the inviter's.
    ///
    /// **A `WrongCode` spends the PIN: never join with it again, and get a new one.** Attempts are
    /// counted at the responder's desk, which a relay posing as the responder never reaches, so each
    /// run with the same PIN gives such a relay a new guess.
    ///
    /// # Errors
    ///
    /// [`Error::Pairing`] when refused, [`Error::Io`] from the transport, [`Error::Record`] for a
    /// bad record, [`Error::Truncated`] when the responder closed early.
    pub fn join<T: MessageTransport>(
        self,
        pairing: Pairing,
        transport: &mut T,
    ) -> Result<PairDial<'_, T>, Error> {
        let joiner = pairing.join(self.pair_channel()?)?;
        let mut dial = PairDial {
            session: self.session,
            joiner,
            transport,
        };
        dial.run(true)?;
        Ok(dial)
    }

    /// Runs the responder until the end, each message sealed: redeeming an invitation, taking the
    /// shown PIN, or blocking in [`PairingDesk::wait`] for the operator. On success the joiner's key
    /// is accepted in `store`. `source` is what the desk throttles by; behind a reverse proxy, pass
    /// the client's address from a header you trust, or every joiner counts as the proxy.
    ///
    /// The joiner has until the smaller of the transport's own timeout, as
    /// [`CurrentReadTimeout`] reports it, and [`PairingMethodBuilder::first_message_timeout`] to send
    /// its first message. From that message each read waits at most until the exchange's deadline,
    /// the desk's. When either runs out the joiner is told, and this is
    /// `Error::Pairing(PairingError::Refused(PairRefusal::Expired))`. A time already spent is expired
    /// at once, with nothing read, and so are more than three reads in a row that time out with
    /// time left and no record between: a transport whose own deadline passed. These bounds hold against a slow peer only if a whole `recv` obeys
    /// the timeout, as [`FramedStream`](crate::FramedStream)'s does. `coqui_peer::drive_messages_until`
    /// clears the timeout it used, so set a timeout of your own after the handshake. This sets the
    /// transport's read timeout, and leaves it at what it last needed.
    ///
    /// # Errors
    ///
    /// As [`join`](PairingSession::join).
    pub fn respond<T: MessageTransport + CurrentReadTimeout>(
        mut self,
        store: &TrustStore,
        desk: &PairingDesk,
        source: Option<SocketAddr>,
        transport: &mut T,
    ) -> Result<Paired, Error> {
        let mut responder = PairingResponder::new(self.pair_channel()?, store, desk, source);
        let first_message = match (self.first_message_timeout, transport.current_read_timeout()) {
            (Some(ours), Some(theirs)) => Some(ours.min(theirs)),
            (ours, theirs) => ours.or(theirs),
        }
        .and_then(|wait| Instant::now().checked_add(wait));
        let mut early = 0_u32;
        loop {
            while let Some(message) = responder.transmit() {
                transport.send(&self.session.seal(&message)?)?;
            }
            if responder.is_complete() {
                break;
            }
            let step = match responder.awaiting() {
                Some(ticket) => responder.resume(desk.wait(ticket)),
                None => {
                    let left = responder.time_left().or_else(|| {
                        first_message.map(|until| until.saturating_duration_since(Instant::now()))
                    });
                    let read = match left {
                        // A spent time, which a `TcpStream` refuses as a timeout.
                        Some(left) if left.is_zero() => Err(io::ErrorKind::TimedOut.into()),
                        Some(left) => transport
                            .set_read_timeout(Some(left))
                            .and_then(|()| transport.recv()),
                        None => transport.recv(),
                    };
                    match read {
                        Ok(record) => {
                            early = 0;
                            let message = open_record(&mut self.session, &record)?;
                            responder.receive(&message)
                        }
                        Err(error) if timed_out(&error) => {
                            early += 1;
                            // An operating system may end a timed read a little early, and a
                            // transport whose own deadline passed ends every read at once: only
                            // a few reads in a row with no record between are believed early.
                            let early_read = early <= MAX_EARLY_TIMEOUTS;
                            let in_time = if responder.deadline().is_some() {
                                responder.check_deadline().map(|()| early_read)
                            } else {
                                Ok(early_read
                                    && first_message.is_some_and(|until| Instant::now() < until))
                            };
                            match in_time {
                                Ok(true) => continue,
                                Ok(false) => {
                                    let record = self.session.seal(&EXPIRED_REFUSAL)?;
                                    let _ = transport.send(&record);
                                    Err(PairingError::Refused(PairRefusal::Expired))
                                }
                                Err(refused) => Err(refused),
                            }
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            };
            if let Err(error) = step {
                // The joiner is told why, as far as the transport still takes it.
                while let Some(message) = responder.transmit() {
                    let record = self.session.seal(&message)?;
                    let _ = transport.send(&record);
                }
                return Err(error.into());
            }
        }
        let close = self.session.close()?;
        let _ = transport.send(&close);
        Ok(responder.finish()?)
    }
}

/// The message of a record of the exchange. What is too long to be one is not opened: a stranger's
/// record costs a decryption only if it can be what it should.
fn open_record(session: &mut Session, record: &[u8]) -> Result<Vec<u8>, Error> {
    if record.len() > MAX_PAIRING_RECORD {
        return Err(PairingError::Protocol.into());
    }
    session.open(record)?.ok_or(Error::Truncated)
}

fn timed_out(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

/// A joiner's exchange in progress: what to show a person, then the rest.
pub struct PairDial<'t, T> {
    session: Session,
    joiner: PairingJoiner,
    transport: &'t mut T,
}

impl<T> fmt::Debug for PairDial<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PairDial").finish_non_exhaustive()
    }
}

impl<T: MessageTransport> PairDial<'_, T> {
    fn run(&mut self, stop_when_shown: bool) -> Result<(), Error> {
        loop {
            while let Some(message) = self.joiner.transmit() {
                self.transport.send(&self.session.seal(&message)?)?;
            }
            if self.joiner.is_complete() || (stop_when_shown && self.joiner.shown().is_some()) {
                return Ok(());
            }
            let record = self.transport.recv()?;
            let message = open_record(&mut self.session, &record)?;
            if let Err(error) = self.joiner.receive(&message) {
                // The responder is told why, as far as the transport still takes it.
                while let Some(message) = self.joiner.transmit() {
                    let record = self.session.seal(&message)?;
                    let _ = self.transport.send(&record);
                }
                return Err(error.into());
            }
        }
    }

    /// What to show a person now: a PIN with its slot, or a device flow's user code.
    #[must_use]
    pub fn shown(&self) -> Option<&Shown> {
        self.joiner.shown()
    }

    /// Runs the rest of the exchange. The caller stores [`Paired::peer`], and reconnects under
    /// [`Noise`].
    ///
    /// # Errors
    ///
    /// As [`PairingSession::join`].
    pub fn finish(mut self) -> Result<Paired, Error> {
        self.run(false)?;
        let close = self.session.close()?;
        let _ = self.transport.send(&close);
        Ok(self.joiner.finish()?)
    }
}
