//! Prove that a zcashd emergency recovery phrase, on its own, reproduces
//! the keys zcashd derived — with no `wallet.dat` involved.
//!
//! This is the test the phrase-only recovery feature exists to pass.
//! `zcashd_phrase`'s unit tests show the derivation is internally
//! consistent and that it matches librustzcash on the path they share, but
//! neither shows it matches *zcashd*, and zcashd is the only authority on
//! where zcashd put its addresses.
//!
//! ## The oracle
//!
//! `crates/argos-wallet-import/tests/fixtures/zcashd-phrase-regtest.export`
//! is a `z_exportwallet` dump written by a real `zcashd:v6.20.0` on a
//! private regtest chain — see `tests/regtest/fixtures/generate-zcashd-phrase.sh`.
//! It contains, in one file:
//!
//! * the emergency recovery phrase, and
//! * every key zcashd derived from it, each labelled with its HD path.
//!
//! Those paths are zcashd's own record of what it did:
//!
//! ```text
//! …  m/32'/1'/2147483647'/4'   # zaddr=zregtestsapling1q8jc9gmus…
//! …  hdkeypath=m/44'/1'/2147483647'/1/13  addr=tm9qBKRVvdkvaqA3…
//! ```
//!
//! `2147483647` is `0x7FFFFFFF`, zcashd's `ZCASH_LEGACY_ACCOUNT`. So the
//! fixture is not a transcription of zcashd's source — it is the producer's
//! output, and a wrong path here fails against bytes Argos did not write.
//!
//! ## Why key material rather than addresses
//!
//! The comparison is on raw key bytes, not encoded addresses, for two
//! reasons. Encoded forms carry regtest HRPs and version bytes that Argos
//! has no production reason to understand, and matching them would test the
//! encoder rather than the derivation. And a spending key is strictly more
//! than an address: matching it proves the whole key, not just the default
//! diversified address it happens to produce.
//!
//! ## What this does not prove
//!
//! That a scan finds funds at these addresses, or that a sweep spends them.
//! Nothing here touches a chain. This proves the derivation half of
//! recovery — that the phrase alone regenerates the right keys. The scan
//! and sweep halves need the regtest stack in `tests/regtest/`.

use std::collections::BTreeMap;

use argos_core::{
    zcashd_phrase::{legacy_sapling_spending_key, legacy_transparent_account_key},
    models::{AddressScope, ZeckNetwork},
};
use secrecy::SecretString;

/// The export is a regtest dump, and regtest shares testnet's coin type
/// (1) — visible in the fixture's own paths, `m/32'/1'/…`.
const NETWORK: ZeckNetwork = ZeckNetwork::Testnet;

fn fixture() -> String {
    let path = format!(
        "{}/../argos-wallet-import/tests/fixtures/zcashd-phrase-regtest.export",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"))
}

/// The emergency recovery phrase, from the export's header comment.
fn recovery_phrase(export: &str) -> SecretString {
    let line = export
        .lines()
        .find(|l| l.contains("recovery_phrase=\""))
        .expect("the export must carry a recovery_phrase line");
    let start = line.find('"').expect("opening quote") + 1;
    let end = line.rfind('"').expect("closing quote");
    SecretString::new(line[start..end].to_owned())
}

/// Decode a bech32 string to its payload bytes, ignoring the HRP.
///
/// HRP-agnostic on purpose: the fixture's keys are `secret-extended-key-regtest1…`,
/// a prefix Argos does not carry constants for, and the payload is the same
/// 169 bytes regardless of which network label was wrapped around it.
fn bech32_payload(encoded: &str) -> Vec<u8> {
    use bech32::primitives::decode::CheckedHrpstring;
    use bech32::Bech32;

    CheckedHrpstring::new::<Bech32>(encoded)
        .expect("fixture key is valid bech32")
        .byte_iter()
        .collect()
}

/// The 32-byte secret from a base58check WIF, ignoring the version byte.
///
/// Layout: `[version][32-byte secret][0x01 if compressed][4-byte checksum]`.
/// The version byte is regtest's, which again is not something Argos needs
/// to know to compare the secret itself.
fn wif_secret(wif: &str) -> [u8; 32] {
    let raw = bs58::decode(wif)
        .into_vec()
        .expect("fixture WIF is valid base58");
    // 1 version + 32 key + 1 compression flag + 4 checksum
    assert!(
        raw.len() >= 37,
        "WIF is too short to hold a key: {} bytes",
        raw.len()
    );
    raw[1..33].try_into().expect("32 bytes")
}

/// Every Sapling key in the export, keyed by its legacy address index.
///
/// Lines look like:
/// `secret-extended-key-regtest1… <time> m/32'/1'/2147483647'/4' <fp> # zaddr=…`
fn sapling_keys_by_index(export: &str) -> BTreeMap<u32, Vec<u8>> {
    let mut out = BTreeMap::new();
    for line in export.lines() {
        if line.starts_with('#') {
            continue;
        }
        let Some(key) = line.split_whitespace().next() else {
            continue;
        };
        if !key.starts_with("secret-extended-key-") {
            continue;
        }
        let path = line
            .split_whitespace()
            .find(|f| f.starts_with("m/32'/"))
            .unwrap_or_else(|| panic!("Sapling line carries no m/32' path: {line}"));

        // m/32'/1'/2147483647'/<index>'
        let index: u32 = path
            .rsplit('/')
            .next()
            .and_then(|s| s.strip_suffix('\''))
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("unparseable Sapling index in {path}"));

        assert!(
            path.contains("/2147483647'/"),
            "a Sapling key was derived outside the legacy account: {path}"
        );

        out.insert(index, bech32_payload(key));
    }
    out
}

/// Every transparent key in the export, keyed by `(change, index)`.
///
/// Lines look like:
/// `<wif> <time> reserve=1 # addr=tm… hdkeypath=m/44'/1'/2147483647'/1/13 seedfp=…`
fn transparent_keys_by_path(export: &str) -> BTreeMap<(u32, u32), [u8; 32]> {
    let mut out = BTreeMap::new();
    for line in export.lines() {
        if line.starts_with('#') {
            continue;
        }
        let Some(path) = line
            .split_whitespace()
            .find_map(|f| f.strip_prefix("hdkeypath="))
        else {
            continue;
        };
        if !path.starts_with("m/44'/") {
            continue;
        }
        assert!(
            path.contains("/2147483647'/"),
            "a transparent key was derived outside the legacy account: {path}"
        );

        let parts: Vec<&str> = path.split('/').collect();
        // m / 44' / 1' / 2147483647' / change / index
        assert_eq!(parts.len(), 6, "unexpected transparent path shape: {path}");
        let change: u32 = parts[4].parse().expect("change index");
        let index: u32 = parts[5].parse().expect("address index");

        let wif = line.split_whitespace().next().expect("a WIF");
        out.insert((change, index), wif_secret(wif));
    }
    out
}

/// Every Sapling key zcashd derived is reproduced by the phrase alone.
#[test]
fn the_phrase_alone_reproduces_every_sapling_key_zcashd_derived() {
    let export = fixture();
    let phrase = recovery_phrase(&export);
    let expected = sapling_keys_by_index(&export);

    assert!(
        expected.len() >= 8,
        "the fixture must carry several Sapling keys, found {}",
        expected.len()
    );
    // A wallet that only ever used index 0 would let a broken index
    // derivation pass. The fixture assigns eight addresses precisely so
    // this is not the case.
    assert!(
        expected.keys().any(|i| *i > 0),
        "the fixture must include a non-zero address index"
    );

    let seed = argos_core::zcashd_phrase::bip39_seed(&phrase).expect("fixture phrase is valid");
    use secrecy::ExposeSecret;

    for (index, zcashd_key) in &expected {
        let ours = legacy_sapling_spending_key(seed.expose_secret(), NETWORK, *index)
            .unwrap_or_else(|e| panic!("deriving Sapling index {index}: {e}"));
        assert_eq!(
            ours.to_bytes().as_slice(),
            zcashd_key.as_slice(),
            "Sapling key at m/32'/1'/2147483647'/{index}' does not match zcashd's"
        );
    }
}

/// Every transparent key zcashd derived is reproduced by the phrase alone,
/// on both the external and internal branches.
#[test]
fn the_phrase_alone_reproduces_every_transparent_key_zcashd_derived() {
    let export = fixture();
    let phrase = recovery_phrase(&export);
    let expected = transparent_keys_by_path(&export);

    assert!(
        expected.len() >= 8,
        "the fixture must carry several transparent keys, found {}",
        expected.len()
    );

    let seed = argos_core::zcashd_phrase::bip39_seed(&phrase).expect("fixture phrase is valid");
    use secrecy::ExposeSecret;

    let account = legacy_transparent_account_key(seed.expose_secret(), NETWORK)
        .expect("legacy transparent account key");

    for ((change, index), zcashd_secret) in &expected {
        let scope = match change {
            0 => AddressScope::External,
            1 => AddressScope::Internal,
            other => panic!("zcashd used an unexpected change branch: {other}"),
        };

        let child = zcash_transparent::keys::NonHardenedChildIndex::from_index(*index)
            .expect("fixture index is in range");
        let ours = account
            .derive_secret_key(scope.into(), child)
            .unwrap_or_else(|e| panic!("deriving transparent {change}/{index}: {e}"));

        assert_eq!(
            &ours.secret_bytes(),
            zcashd_secret,
            "transparent key at m/44'/1'/2147483647'/{change}/{index} does not match zcashd's"
        );
    }
}

/// Both change branches are covered.
///
/// A fixture that only exercised one would leave the other's derivation
/// unchecked, and zcashd puts change addresses on branch 1 — so missing it
/// would mean missing every change output a swept wallet ever made.
#[test]
fn the_fixture_covers_both_transparent_change_branches() {
    let export = fixture();
    let keys = transparent_keys_by_path(&export);

    let external = keys.keys().filter(|(c, _)| *c == 0).count();
    let internal = keys.keys().filter(|(c, _)| *c == 1).count();

    assert!(external > 0, "no external (change=0) keys in the fixture");
    assert!(internal > 0, "no internal (change=1) keys in the fixture");
}

/// The whole key set the CLI would scan must contain what zcashd derived,
/// at a gap limit wide enough to reach it.
///
/// The per-key tests above prove each path derives correctly in isolation.
/// This proves the *product* — the `ImportedKeys` handed to Argos's scan
/// pipeline — actually contains them, which is what determines whether a
/// user's funds are found.
#[test]
fn the_scanned_key_set_contains_every_key_zcashd_derived() {
    use argos_core::{GapLimits, KeySource, ZcashdPhraseKeySource};
    use secrecy::ExposeSecret;

    let export = fixture();
    let phrase = recovery_phrase(&export);
    let expected_sapling = sapling_keys_by_index(&export);
    let expected_transparent = transparent_keys_by_path(&export);

    // zcashd fills a keypool well past the addresses actually assigned —
    // this fixture reaches index ~50 — so the gap has to be wide enough to
    // cover the whole file rather than the default 20.
    let widest = expected_transparent
        .keys()
        .map(|(_, i)| *i)
        .chain(expected_sapling.keys().copied())
        .max()
        .expect("the fixture has keys");
    let gaps = GapLimits::uniform(widest + 1);

    let source = ZcashdPhraseKeySource::new(
        phrase,
        NETWORK,
        argos_core::ZcashdSeedKind::Bip39,
        gaps,
    )
    .expect("deriving from the fixture phrase");

    let keys = source
        .imported_keys()
        .expect("a phrase source always carries derived keys");

    let derived_sapling: Vec<&[u8]> = keys
        .sapling
        .iter()
        .map(|k| k.extsk.expose_secret().as_slice())
        .collect();
    for (index, zcashd_key) in &expected_sapling {
        assert!(
            derived_sapling.contains(&zcashd_key.as_slice()),
            "the scanned key set is missing zcashd's Sapling key at index {index}"
        );
    }

    let derived_transparent: Vec<[u8; 32]> = keys
        .transparent
        .iter()
        .map(|k| *k.secret.expose_secret())
        .collect();
    for ((change, index), zcashd_secret) in &expected_transparent {
        assert!(
            derived_transparent.contains(zcashd_secret),
            "the scanned key set is missing zcashd's transparent key at {change}/{index}"
        );
    }
}
