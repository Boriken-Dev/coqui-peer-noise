use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::fmt;
use core::net::SocketAddr;

use coqui_peer::{Established, Framing, Handshake, KeyMaterial, Method, NonDefault, Random};
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use crate::error::Error;
use crate::identity::{Identity, key_material};
use crate::noise::{DHLEN, TAGLEN, Xx};
use crate::session::{Limits, Session};
use crate::settings::NoiseSettings;
use crate::trust::{Admit, Trust};

/// The method name: the `<method>` of `coqui-peer-<method>`, under which a trust store keeps the
/// keys of this method.
pub const METHOD: &str = "noise";

/// This wire's name, first in the Noise prologue, so a run under another profile fails.
pub const PROFILE: &str = "dev.boriken.coqui.peer-noise/v1";

/// What a run is for, second in the Noise prologue, so a run for one fails against the other at its
/// second message and a relay cannot pick which a peer gets.
const PURPOSE_ORDINARY: &[u8] = b"ordinary";
const PURPOSE_PAIR: &[u8] = b"pair";

const FIRST_LEN: usize = DHLEN;
const SECOND_LEN: usize = DHLEN + (DHLEN + TAGLEN) + TAGLEN;
const THIRD_LEN: usize = (DHLEN + TAGLEN) + TAGLEN;

/// The operating system's generator as a [`Random`].
#[must_use]
pub fn random() -> Random {
    Random::from_fn(|out| getrandom::fill(out).map_err(|_| coqui_peer::Error::Random))
}

/// A field of the prologue or an export's info: four big-endian length bytes, then the bytes.
pub(crate) fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
}

#[derive(Debug, Clone)]
struct Config {
    identity: Identity,
    purpose: &'static [u8],
    responders: Option<Admit>,
    initiators: Option<Admit>,
    settings: NoiseSettings,
    random: Random,
    random_replaced: bool,
}

/// The Noise method: an [`Identity`], and whom it admits in each role. Cloning shares it.
///
/// ```
/// use coqui_peer::{Handshake, Method};
/// use coqui_peer_noise::{Identity, Noise, Trust};
///
/// # fn main() -> Result<(), coqui_peer_noise::Error> {
/// let (dialer, listener) = (Identity::generate()?, Identity::generate()?);
/// let client = Noise::builder(dialer.clone()).responders(Trust::pinned([listener.peer_id()])).build();
/// let server = Noise::builder(listener).initiators(Trust::pinned([dialer.peer_id()])).build();
///
/// let (mut dialing, mut listening) = (client.initiate()?, server.respond(None)?);
/// while !(dialing.is_complete() && listening.is_complete()) {
///     while let Some(message) = dialing.transmit()? {
///         listening.receive(&message)?;
///     }
///     while let Some(message) = listening.transmit()? {
///         dialing.receive(&message)?;
///     }
/// }
/// let mut at_client = dialing.finish()?.session;
/// let mut at_server = listening.finish()?.session;
/// assert_eq!(at_client.id(), at_server.id());
/// let record = at_client.seal(b"over the proven keys")?;
/// assert_eq!(at_server.open(&record)?.as_deref(), Some(&b"over the proven keys"[..]));
/// assert_eq!(at_server.open(&at_client.close()?)?, None);
/// at_server.verify_end()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Noise(Arc<Config>);

/// Builds a [`Noise`]: [`Noise::builder`], the settings, then [`build`](Self::build).
#[derive(Debug, Clone)]
#[must_use]
pub struct NoiseBuilder(Config);

impl NoiseBuilder {
    /// The method a [`PairingMethod`](crate::PairingMethod) runs: any proved key, in both roles.
    pub(crate) fn admitting_anyone(identity: Identity) -> Self {
        let mut builder = Noise::builder(identity);
        builder.0.purpose = PURPOSE_PAIR;
        builder.0.responders = Some(Admit::Any);
        builder.0.initiators = Some(Admit::Any);
        builder
    }

    /// Whom [`initiate`](Method::initiate) admits as the responder.
    pub fn responders(mut self, trust: Trust) -> Self {
        self.0.responders = Some(Admit::Trust(trust));
        self
    }

    /// Whom [`respond`](Method::respond) admits as the initiator.
    pub fn initiators(mut self, trust: Trust) -> Self {
        self.0.initiators = Some(Admit::Trust(trust));
        self
    }

    /// What one key may carry in one direction; see [`NoiseSettings::key_limit`].
    pub fn key_limit(mut self, bytes: u64) -> Self {
        self.0.settings.key_limit = bytes;
        self
    }

    /// Whether this side changes its sending key by itself at the key limit; see
    /// [`NoiseSettings::rekey`].
    pub fn rekey(mut self, rekey: bool) -> Self {
        self.0.settings.rekey = rekey;
        self
    }

    /// Where ephemeral keys come from; the operating system by default. It must be cryptographically
    /// secure: section 14 of the Noise specification calls a reused ephemeral key catastrophic. A
    /// fixed source is for test vectors. It is reported by [`Noise::non_defaults`].
    pub fn random(mut self, random: Random) -> Self {
        self.0.random = random;
        self.0.random_replaced = true;
        self
    }

    /// The key limit and rekeying from `settings`. Replaces what [`key_limit`](Self::key_limit)
    /// and [`rekey`](Self::rekey) set before, and is replaced by what they set after it.
    pub fn settings(mut self, settings: NoiseSettings) -> Self {
        self.0.settings = settings;
        self
    }

    /// The method.
    pub fn build(self) -> Noise {
        Noise(Arc::new(self.0))
    }
}

impl Noise {
    /// A builder for a method for `identity`, configured for neither role until
    /// [`responders`](NoiseBuilder::responders) or [`initiators`](NoiseBuilder::initiators).
    pub fn builder(identity: Identity) -> NoiseBuilder {
        NoiseBuilder(Config {
            identity,
            purpose: PURPOSE_ORDINARY,
            responders: None,
            initiators: None,
            settings: NoiseSettings::default(),
            random: crate::random(),
            random_replaced: false,
        })
    }

    /// Whether an initiator's peer is admitted by a pin or a store, and not as any proved key.
    pub(crate) fn verifies_responders(&self) -> bool {
        matches!(self.0.responders, Some(Admit::Trust(_)))
    }

    /// This method's identity.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.0.identity
    }

    /// The key limit and rekeying it was built with.
    #[must_use]
    pub fn settings(&self) -> NoiseSettings {
        self.0.settings
    }

    /// Every setting that differs from its default, named by key path, and `random` when the
    /// ephemeral keys do not come from the operating system.
    #[must_use]
    pub fn non_defaults(&self) -> Vec<NonDefault> {
        let mut non_defaults = NonDefault::of_settings(&self.0.settings);
        if self.0.random_replaced {
            non_defaults.push(NonDefault::new("random", "caller's", "operating system's"));
        }
        non_defaults
    }
}

impl Noise {
    /// Whether the ephemeral keys come from a caller's random source.
    pub(crate) fn random_replaced(&self) -> bool {
        self.0.random_replaced
    }
}

impl fmt::Debug for Noise {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Noise")
            .field("identity", &self.0.identity)
            .field("responders", &self.0.responders)
            .field("initiators", &self.0.initiators)
            .field("settings", &self.0.settings)
            .finish_non_exhaustive()
    }
}

impl Method for Noise {
    type Handshake = NoiseHandshake;

    fn name(&self) -> &'static str {
        METHOD
    }

    /// Starts a handshake as the side that dials; its first message is ready to
    /// [`transmit`](Handshake::transmit).
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] without [`responders`](NoiseBuilder::responders),
    /// [`Error::Random`] when the generator fails.
    fn initiate(&self) -> Result<NoiseHandshake, Error> {
        if self.0.responders.is_none() {
            return Err(Error::Unsupported);
        }
        let ephemeral = ephemeral(&self.0.random)?;
        Ok(NoiseHandshake::new(
            self.0.clone(),
            None,
            State::Start(ephemeral),
        ))
    }

    /// Starts a handshake as the side that accepts. `source` goes with a waiting entry.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] without [`initiators`](NoiseBuilder::initiators).
    fn respond(&self, source: Option<SocketAddr>) -> Result<NoiseHandshake, Error> {
        if self.0.initiators.is_none() {
            return Err(Error::Unsupported);
        }
        Ok(NoiseHandshake::new(
            self.0.clone(),
            source,
            State::AwaitFirst,
        ))
    }
}

/// A fresh ephemeral key, on the heap so that moving it copies no secret; its `Drop` zeroes it.
fn ephemeral(random: &Random) -> Result<Box<StaticSecret>, Error> {
    let mut bytes = Zeroizing::new([0u8; DHLEN]);
    random.fill(&mut *bytes).map_err(|_| Error::Random)?;
    Ok(Box::new(StaticSecret::from(*bytes)))
}

/// Secrets sit behind pointers here, so `mem::replace` on the state moves none of their bytes.
enum State {
    Start(Box<StaticSecret>),
    AwaitFirst,
    AwaitSecond(Box<Xx>),
    AwaitThird(Box<Xx>),
    Done,
    Failed,
}

/// One run of the [`Noise`] method, driven by the caller. `Output` is the [`Session`].
pub struct NoiseHandshake {
    config: Arc<Config>,
    source: Option<SocketAddr>,
    binding: Vec<u8>,
    state: State,
    outbound: VecDeque<Vec<u8>>,
    result: Option<(KeyMaterial, Session)>,
}

impl NoiseHandshake {
    const fn new(config: Arc<Config>, source: Option<SocketAddr>, state: State) -> Self {
        Self {
            config,
            source,
            binding: Vec::new(),
            state,
            outbound: VecDeque::new(),
            result: None,
        }
    }

    /// Also binds this run to `binding`, a value of the outer channel both ends can read: a TLS
    /// exporter, when each end really terminates that TLS connection itself.
    ///
    /// It goes into the Noise prologue and is never sent, so two ends holding different values (a
    /// relay terminating TLS between them) fail with [`Error::BadProof`]. Leave it out for a
    /// connection through a TLS-terminating reverse proxy or from a browser, where no end can read
    /// the same value: the [`Session`] protects itself either way.
    ///
    /// # Errors
    ///
    /// [`Error::State`] after the first [`transmit`](Handshake::transmit) or
    /// [`receive`](Handshake::receive): the prologue is fixed by then.
    pub fn bind(mut self, binding: &[u8]) -> Result<Self, Error> {
        if !matches!(self.state, State::Start(_) | State::AwaitFirst) {
            return Err(Error::State);
        }
        self.binding = binding.to_vec();
        Ok(self)
    }

    fn prologue(&self) -> Vec<u8> {
        let purpose = self.config.purpose;
        let mut prologue =
            Vec::with_capacity(12 + PROFILE.len() + purpose.len() + self.binding.len());
        field(&mut prologue, PROFILE.as_bytes());
        field(&mut prologue, purpose);
        field(&mut prologue, &self.binding);
        prologue
    }

    fn limits(&self) -> Limits {
        Limits {
            key_limit: self.config.settings.key_limit,
            rekey: self.config.settings.rekey,
        }
    }

    /// What every static key read must pass, then whether the peer is admitted. Trust is only ever
    /// asked about a key the handshake just proved.
    fn admit(&self, xx: &Xx, trust: Option<&Admit>, waiting: bool) -> Result<KeyMaterial, Error> {
        let key = xx.remote_static().ok_or(Error::State)?;
        let trust = trust.ok_or(Error::Unsupported)?;
        let material = key_material(key);
        if trust.admits(&material, waiting.then_some(self.source)) {
            Ok(material)
        } else {
            Err(Error::Untrusted)
        }
    }

    fn step(&mut self, input: &[u8]) -> Result<(), Error> {
        let config = self.config.clone();
        let identity = &config.identity;
        match core::mem::replace(&mut self.state, State::Failed) {
            State::AwaitFirst => {
                if input.len() != FIRST_LEN {
                    return Err(Error::Malformed);
                }
                let own = ephemeral(&config.random)?;
                let mut xx = Box::new(Xx::new(false, &self.prologue(), identity.clone(), own));
                xx.read_message(input)?;
                self.outbound.push_back(xx.write_message(&[])?);
                self.state = State::AwaitThird(xx);
            }
            State::AwaitSecond(mut xx) => {
                if input.len() != SECOND_LEN {
                    return Err(Error::Malformed);
                }
                xx.read_message(input)?;
                refuse_own_key(&xx, identity)?;
                let material = self.admit(&xx, config.responders.as_ref(), false)?;
                let third = xx.write_message(&[])?;
                let session = Session::new(xx.split()?, true, self.limits());
                self.outbound.push_back(third);
                self.result = Some((material, session));
                self.state = State::Done;
            }
            State::AwaitThird(mut xx) => {
                if input.len() != THIRD_LEN {
                    return Err(Error::Malformed);
                }
                xx.read_message(input)?;
                refuse_own_key(&xx, identity)?;
                let material = self.admit(&xx, config.initiators.as_ref(), true)?;
                let session = Session::new(xx.split()?, false, self.limits());
                self.result = Some((material, session));
                self.state = State::Done;
            }
            State::Start(_) | State::Done | State::Failed => return Err(Error::State),
        }
        Ok(())
    }

    /// The first message, which waits for this call so that a binding set before it is in the
    /// prologue.
    fn start(&mut self) -> Result<(), Error> {
        if matches!(self.state, State::Start(_)) {
            let State::Start(own) = core::mem::replace(&mut self.state, State::Failed) else {
                return Err(Error::State);
            };
            let prologue = self.prologue();
            let mut xx = Box::new(Xx::new(true, &prologue, self.config.identity.clone(), own));
            self.outbound.push_back(xx.write_message(&[])?);
            self.state = State::AwaitSecond(xx);
        }
        Ok(())
    }
}

/// A peer presenting this side's own key is a reflection, or this side dialling itself.
fn refuse_own_key(xx: &Xx, identity: &Identity) -> Result<(), Error> {
    if xx.remote_static() == Some(identity.public_key()) {
        Err(Error::Malformed)
    } else {
        Ok(())
    }
}

impl fmt::Debug for NoiseHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NoiseHandshake")
            .field("complete", &self.is_complete())
            .finish_non_exhaustive()
    }
}

impl Handshake for NoiseHandshake {
    type Output = Session;
    type Error = Error;

    fn framing(&self) -> Framing {
        Framing::Message
    }

    fn receive(&mut self, input: &[u8]) -> Result<(), Error> {
        let result = self.step(input);
        if result.is_err() {
            // Nothing queued for a failed exchange leaves, and no key stays behind.
            self.outbound.clear();
            self.result = None;
        }
        result
    }

    fn transmit(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.start()?;
        if matches!(self.state, State::Failed) {
            return Err(Error::State);
        }
        Ok(self.outbound.pop_front())
    }

    fn is_complete(&self) -> bool {
        matches!(self.state, State::Done) && self.outbound.is_empty()
    }

    fn finish(self) -> Result<Established<Session>, Error> {
        if !self.is_complete() {
            return Err(Error::State);
        }
        let (key, session) = self.result.ok_or(Error::State)?;
        Ok(Established {
            peer: key.id(),
            key: Some(key),
            session,
        })
    }
}
