//! What a message becomes on the wire: `record_length` against the real sealer.

mod support;

use coqui_peer_noise::record_length;
use support::sessions;

#[test]
fn the_record_length_is_what_the_sealer_makes_across_every_boundary() {
    const PART: usize = 65_518;
    let (mut near, mut far) = sessions();
    let lengths = [
        0,
        1,
        PART - 1,
        PART,
        PART + 1,
        2 * PART - 1,
        2 * PART,
        2 * PART + 1,
        3 * PART,
        1 << 20,
        1 << 24,
    ];
    for length in lengths {
        let message = vec![0x5a; length];
        let record = near.seal(&message).unwrap();
        assert_eq!(record.len(), record_length(length), "a message of {length}");
        assert_eq!(far.open(&record).unwrap().unwrap(), message);
    }
}

#[test]
fn the_overhead_is_19_bytes_for_each_part() {
    let overhead = |length: usize| record_length(length) - length;
    assert_eq!(overhead(0), 19);
    assert_eq!(overhead(65_518), 19);
    assert_eq!(overhead(65_519), 38);
    assert_eq!(overhead(1 << 20), 323);
    assert_eq!(overhead(1 << 24), 4_883);
    assert_eq!(record_length(usize::MAX), usize::MAX);
}
