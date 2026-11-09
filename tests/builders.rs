//! Each builder setter reaches what it builds, `settings` takes the whole, the last setter wins,
//! and the settings are values a file fills.

mod support;

use std::time::Duration;

use coqui_peer::{Method, NonDefault};
use coqui_peer_noise::{
    DEFAULT_FIRST_MESSAGE_TIMEOUT, DEFAULT_KEY_LIMIT, Identity, Noise, NoiseSettings,
    PairingMethod, PairingSettings, Trust,
};
use guatiao_serde::Presentation;
use guatiao_serde::text::{json, toml};

fn plain() -> Presentation {
    Presentation::new()
}

#[test]
fn every_noise_setter_reaches_the_method() {
    let identity = Identity::generate().unwrap();
    let method = Noise::builder(identity.clone())
        .key_limit(1000)
        .rekey(false)
        .build();
    assert_eq!(method.settings().key_limit, 1000);
    assert!(!method.settings().rekey);
    assert_eq!(method.identity().peer_id(), identity.peer_id());
    assert_eq!(
        method.non_defaults(),
        [
            NonDefault::new("key_limit", "1000", DEFAULT_KEY_LIMIT.to_string()),
            NonDefault::new("rekey", "false", "true"),
        ]
    );
}

#[test]
fn the_roles_are_set_by_name_and_each_side_proves_the_other() {
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = Noise::builder(client.clone())
        .responders(Trust::pinned([server.peer_id()]))
        .build();
    let listening = Noise::builder(server)
        .initiators(Trust::pinned([client.peer_id()]))
        .build();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    support::exchange(&mut a, &mut b).unwrap();
}

#[test]
fn settings_take_the_whole_and_the_last_setter_wins() {
    let mut settings = NoiseSettings::default();
    settings.key_limit = 77;
    let method = Noise::builder(Identity::generate().unwrap())
        .rekey(false)
        .settings(settings)
        .key_limit(88)
        .build();
    assert_eq!(method.settings().key_limit, 88);
    assert!(
        method.settings().rekey,
        "settings replaced the earlier rekey"
    );
}

#[test]
fn every_pairing_setter_reaches_the_method() {
    let method = PairingMethod::builder(Identity::generate().unwrap())
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

    let unbounded = PairingMethod::builder(Identity::generate().unwrap())
        .first_message_timeout(None)
        .build()
        .unwrap();
    assert_eq!(unbounded.settings().first_message_timeout, None);

    let mut whole = PairingSettings::default();
    whole.first_message_timeout = Some(Duration::from_secs(9));
    let method = PairingMethod::builder(Identity::generate().unwrap())
        .first_message_timeout(Duration::from_secs(1))
        .settings(whole)
        .build()
        .unwrap();
    assert_eq!(method.settings(), whole);
}

#[test]
fn the_defaults_report_nothing() {
    let identity = Identity::generate().unwrap();
    assert!(
        Noise::builder(identity.clone())
            .build()
            .non_defaults()
            .is_empty()
    );
    assert!(
        PairingMethod::builder(identity)
            .build()
            .unwrap()
            .non_defaults()
            .is_empty()
    );
    assert_eq!(
        PairingMethod::builder(Identity::generate().unwrap())
            .build()
            .unwrap()
            .settings()
            .first_message_timeout,
        Some(DEFAULT_FIRST_MESSAGE_TIMEOUT)
    );
}

#[test]
fn settings_read_from_toml_and_json_and_round_trip() {
    let settings: NoiseSettings = toml::from_str_as("key_limit = 5\n", plain()).unwrap();
    assert_eq!(settings.key_limit, 5);
    assert!(settings.rekey);
    assert_eq!(
        toml::from_str_as::<NoiseSettings>("", plain()).unwrap(),
        NoiseSettings::default()
    );

    let mut pairing = PairingSettings::default();
    pairing.key_limit = 6;
    pairing.rekey = false;
    pairing.first_message_timeout = Some(Duration::from_millis(1500));
    let text = toml::to_string_of(&pairing, plain()).unwrap();
    assert_eq!(
        toml::from_str_as::<PairingSettings>(&text, plain()).unwrap(),
        pairing
    );
    let text = json::to_string_pretty_of(&pairing, plain()).unwrap();
    assert_eq!(
        json::from_str_as::<PairingSettings>(&text, plain()).unwrap(),
        pairing
    );
}

#[test]
fn settings_refuse_unknown_keys() {
    assert!(toml::from_str_as::<NoiseSettings>("keylimit = 1", plain()).is_err());
    assert!(toml::from_str_as::<PairingSettings>("responders = []", plain()).is_err());
    assert!(toml::from_str_as::<NoiseSettings>("rekey = \"yes\"", plain()).is_err());
}

#[test]
fn a_first_message_timeout_reads_seconds_and_round_trips() {
    for (text, expected) in [
        (
            "first_message_timeout = 30
",
            Some(Duration::from_secs(30)),
        ),
        (
            "first_message_timeout = 0.25
",
            Some(Duration::from_millis(250)),
        ),
        ("", None),
    ] {
        let settings: PairingSettings = toml::from_str_as(text, plain()).unwrap();
        assert_eq!(settings.first_message_timeout, expected, "{text}");
        let written = toml::to_string_of(&settings, plain()).unwrap();
        assert_eq!(
            toml::from_str_as::<PairingSettings>(&written, plain()).unwrap(),
            settings,
            "{text}"
        );
    }
    assert!(
        toml::from_str_as::<PairingSettings>("first_message_timeout = \"soon\"", plain()).is_err()
    );
}

#[test]
fn a_first_message_timeout_is_reported_under_its_key_when_it_differs() {
    let method = PairingMethod::builder(Identity::generate().unwrap())
        .first_message_timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    assert_eq!(
        method.non_defaults(),
        [NonDefault::new("first_message_timeout", "[30,0]", "[60,0]")]
    );
}

#[test]
fn no_first_message_timeout_is_reported_as_unset_against_the_default() {
    let method = PairingMethod::builder(Identity::generate().unwrap())
        .first_message_timeout(None)
        .build()
        .unwrap();
    assert_eq!(method.settings().first_message_timeout, None);
    let listed = method.non_defaults();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].setting, "first_message_timeout");
    assert_eq!(listed[0].default, "[60,0]");
}
