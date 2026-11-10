//! Each builder setter reaches what it builds, `fill` takes the whole, the last write of a key
//! wins, and the settings are read from text.

mod support;

use std::time::Duration;

use coqui_builder::{NonDefault, Partial};
use coqui_peer::Method;
use coqui_peer_noise::{
    DEFAULT_FIRST_MESSAGE_TIMEOUT, DEFAULT_KEY_LIMIT, Identity, Noise, NoiseSettings,
    PairingMethod, PairingSettings, Trust,
};

/// Each entry as (setting, value, default) in the text a report shows.
fn lines(found: &[NonDefault]) -> Vec<(String, String, String)> {
    found
        .iter()
        .map(|found| {
            (
                found.setting.clone(),
                found.value.to_string(),
                found.default.to_string(),
            )
        })
        .collect()
}

fn line(setting: &str, value: &str, default: &str) -> (String, String, String) {
    (setting.to_owned(), value.to_owned(), default.to_owned())
}

#[test]
fn every_noise_setter_reaches_the_method() {
    let identity = Identity::generate().unwrap();
    let method = Noise::builder()
        .identity(identity.clone())
        .key_limit(1000)
        .rekey(false)
        .build()
        .unwrap();
    assert_eq!(method.settings().key_limit, 1000);
    assert!(!method.settings().rekey);
    assert_eq!(method.identity().peer_id(), identity.peer_id());
    assert_eq!(
        lines(&method.non_defaults()),
        [
            line(
                "key_limit",
                "u64(1000)",
                &format!("u64({DEFAULT_KEY_LIMIT})")
            ),
            line("rekey", "bool(false)", "bool(true)"),
        ]
    );
}

#[test]
fn a_builder_without_an_identity_names_it() {
    let missing = Noise::builder().build().unwrap_err();
    assert!(missing.to_string().contains("identity"), "{missing}");
    let missing = PairingMethod::builder().build().err().unwrap();
    assert!(missing.to_string().contains("identity"), "{missing}");
}

#[test]
fn the_roles_are_set_by_name_and_each_side_proves_the_other() {
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = Noise::builder()
        .identity(client.clone())
        .responders(Trust::pinned([server.peer_id()]))
        .build()
        .unwrap();
    let listening = Noise::builder()
        .identity(server)
        .initiators(Trust::pinned([client.peer_id()]))
        .build()
        .unwrap();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    support::exchange(&mut a, &mut b).unwrap();
}

#[test]
fn fill_takes_the_whole_and_the_last_write_of_a_key_wins() {
    let mut settings = NoiseSettings::default();
    settings.key_limit = 77;
    let method = Noise::builder()
        .identity(Identity::generate().unwrap())
        .rekey(false)
        .fill(Partial::from(settings))
        .key_limit(88)
        .build()
        .unwrap();
    assert_eq!(method.settings().key_limit, 88);
    assert!(method.settings().rekey, "fill replaced the earlier rekey");
}

#[test]
fn every_pairing_setter_reaches_the_method() {
    let method = PairingMethod::builder()
        .identity(Identity::generate().unwrap())
        .key_limit(2000)
        .rekey(false)
        .first_message_timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let settings = method.settings();
    assert_eq!(settings.key_limit, 2000);
    assert!(!settings.rekey);
    assert_eq!(settings.first_message_timeout, Some(Duration::from_secs(5)));
    assert_eq!(method.non_defaults().len(), 3);

    let unbounded = PairingMethod::builder()
        .identity(Identity::generate().unwrap())
        .first_message_timeout(None::<Duration>)
        .build()
        .unwrap();
    assert_eq!(unbounded.settings().first_message_timeout, None);

    let mut whole = PairingSettings::default();
    whole.first_message_timeout = Some(Duration::from_secs(9));
    let method = PairingMethod::builder()
        .identity(Identity::generate().unwrap())
        .first_message_timeout(Duration::from_secs(1))
        .fill(Partial::from(whole))
        .build()
        .unwrap();
    assert_eq!(method.settings(), whole);
}

#[test]
fn the_defaults_report_nothing() {
    let identity = Identity::generate().unwrap();
    assert!(
        Noise::builder()
            .identity(identity.clone())
            .build()
            .unwrap()
            .non_defaults()
            .is_empty()
    );
    assert!(
        PairingMethod::builder()
            .identity(identity)
            .build()
            .unwrap()
            .non_defaults()
            .is_empty()
    );
    assert_eq!(
        PairingMethod::builder()
            .identity(Identity::generate().unwrap())
            .build()
            .unwrap()
            .settings()
            .first_message_timeout,
        Some(DEFAULT_FIRST_MESSAGE_TIMEOUT)
    );
}

fn read<T: coqui_builder::Describe>(text: &str) -> Result<T, String> {
    toml::from_str::<Partial<T>>(text)
        .map_err(|error| error.to_string())?
        .build()
        .map_err(|error| error.to_string())
}

#[test]
fn settings_read_from_toml() {
    let settings: NoiseSettings = read("key_limit = 5\n").unwrap();
    assert_eq!(settings.key_limit, 5);
    assert!(settings.rekey);
    assert_eq!(read::<NoiseSettings>("").unwrap(), NoiseSettings::default());

    let pairing: PairingSettings =
        read("key_limit = 6\nrekey = false\nfirst_message_timeout = \"1500ms\"\n").unwrap();
    assert_eq!(pairing.key_limit, 6);
    assert!(!pairing.rekey);
    assert_eq!(
        pairing.first_message_timeout,
        Some(Duration::from_millis(1500))
    );
}

#[test]
fn settings_refuse_unknown_keys_and_bad_values() {
    assert!(read::<NoiseSettings>("keylimit = 1").is_err());
    assert!(read::<PairingSettings>("responders = []").is_err());
    assert!(read::<NoiseSettings>("rekey = \"maybe\"").is_err());
}

#[test]
fn a_first_message_timeout_reads_a_duration_or_never() {
    for (text, expected) in [
        (
            "first_message_timeout = 30\n",
            Some(Duration::from_secs(30)),
        ),
        (
            "first_message_timeout = 0.25\n",
            Some(Duration::from_millis(250)),
        ),
        (
            "first_message_timeout = \"250ms\"\n",
            Some(Duration::from_millis(250)),
        ),
        ("first_message_timeout = \"never\"\n", None),
        ("", Some(DEFAULT_FIRST_MESSAGE_TIMEOUT)),
    ] {
        let settings: PairingSettings = read(text).unwrap();
        assert_eq!(settings.first_message_timeout, expected, "{text}");
    }
    assert!(read::<PairingSettings>("first_message_timeout = \"soon\"").is_err());
    assert!(read::<PairingSettings>("first_message_timeout = [30, 0]").is_err());
}

#[test]
fn a_first_message_timeout_is_reported_under_its_key_when_it_differs() {
    let method = PairingMethod::builder()
        .identity(Identity::generate().unwrap())
        .first_message_timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    assert_eq!(
        lines(&method.non_defaults()),
        [line(
            "first_message_timeout",
            "Duration(30s)",
            "Duration(60s)"
        )]
    );
}

#[test]
fn no_first_message_timeout_is_reported_as_never_against_the_default() {
    let method = PairingMethod::builder()
        .identity(Identity::generate().unwrap())
        .first_message_timeout(None::<Duration>)
        .build()
        .unwrap();
    assert_eq!(method.settings().first_message_timeout, None);
    assert_eq!(
        lines(&method.non_defaults()),
        [line(
            "first_message_timeout",
            "Duration(never)",
            "Duration(60s)"
        )]
    );
}

#[test]
fn a_replaced_random_source_is_listed_beside_the_settings() {
    let method = Noise::builder()
        .identity(Identity::generate().unwrap())
        .random(support::scripted(&[]))
        .build()
        .unwrap();
    assert_eq!(
        lines(&method.non_defaults()),
        [line(
            "random",
            "Random(caller's)",
            "Random(operating system's)"
        )]
    );
}
