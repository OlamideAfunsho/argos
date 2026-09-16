//! The `--zcashd-phrase` surface, exercised end to end against the real
//! binary.
//!
//! Like `wallet_file_cli.rs`, these run the built binary rather than
//! calling library functions, because what breaks here is wiring: a flag
//! that never reaches the key source, a prompt that fires when it should
//! not, a conflict that is declared but not enforced. None of that is
//! visible from inside `argos-core`, whose own tests already cover the
//! derivation itself.
//!
//! Every test here is offline. `show-keys` needs no network, and the
//! argument-rejection paths fail before any connection is attempted, so
//! nothing in this file depends on lightwalletd being reachable.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// The BIP-39 test vector used throughout Argos. No real funds.
const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon art";

/// Run `argos` with stdin closed.
///
/// Closing stdin is load-bearing rather than tidiness: a test that
/// accidentally reaches an interactive prompt then fails with a terminal
/// error instead of hanging CI forever.
fn argos(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_argos"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("argos binary should run")
}

/// Write the test phrase to a file inside a fresh temp directory.
///
/// Returns the directory too — dropping it would delete the file before
/// the binary could read it.
fn phrase_file() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("phrase.txt");
    let mut f = std::fs::File::create(&path).expect("create phrase file");
    writeln!(f, "{TEST_PHRASE}").expect("write phrase");
    drop(f);

    // `load_phrase` refuses a group- or world-readable file on Unix, and
    // a freshly created file honours the process umask, which in CI is
    // often 022. Set the mode the CLI demands rather than hoping.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 600");
    }

    (dir, path)
}

fn stderr_of(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The flag must be rejected alongside every source it cannot combine
/// with. A phrase and a wallet file are two different recoveries; silently
/// preferring one would scan a wallet the user did not ask about.
#[test]
fn the_zcashd_phrase_flag_conflicts_with_every_other_key_source() {
    for (flag, value) in [
        ("--wallet-file", "wallet.dat"),
        ("--sapling-key-file", "keys.txt"),
        ("--sprout-key-file", "sprout.txt"),
    ] {
        let out = argos(&["--zcashd-phrase", flag, value, "scan"]);
        assert!(
            !out.status.success(),
            "--zcashd-phrase must conflict with {flag}"
        );
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains("cannot be used with") || stderr.contains("conflict"),
            "expected a clap conflict error for {flag}, got: {stderr}"
        );
    }
}

/// `--zcashd-era` without `--zcashd-phrase` is meaningless, and accepting
/// it silently would let a user believe they had selected an era when they
/// were running an ordinary ZecWallet Lite recovery.
#[test]
fn the_era_flag_requires_the_phrase_flag() {
    let out = argos(&["--zcashd-era", "pre47", "scan"]);
    assert!(
        !out.status.success(),
        "--zcashd-era must require --zcashd-phrase"
    );
}

/// All three era values must parse. A typo in the `ValueEnum` derive would
/// otherwise surface only when a user tried the variant.
#[test]
fn every_era_value_is_accepted() {
    let (_dir, path) = phrase_file();
    for era in ["auto", "post47", "pre47"] {
        let out = argos(&[
            "--zcashd-phrase",
            "--zcashd-era",
            era,
            "--seed-file",
            path.to_str().expect("utf-8 path"),
            "show-keys",
        ]);
        let stderr = stderr_of(&out);
        assert!(
            !stderr.contains("invalid value"),
            "era {era} was rejected as an invalid value: {stderr}"
        );
    }
}

/// The limits statement must reach the user on the way past, not sit in a
/// doc comment.
///
/// A phrase-only recovery cannot see Sprout keys, imported keys, or
/// anything else that lived only in `wallet.dat`. Someone who has already
/// lost a wallet file and then sees an empty result needs to have been
/// told which of "there was nothing there" and "this route cannot see it"
/// they are looking at.
#[test]
fn the_limits_statement_is_printed_before_any_scan_work() {
    let (_dir, path) = phrase_file();
    let out = argos(&[
        "--zcashd-phrase",
        "--seed-file",
        path.to_str().expect("utf-8 path"),
        "show-keys",
    ]);

    let stderr = stderr_of(&out);
    for needle in ["Sprout", "z_importkey", "wallet.dat"] {
        assert!(
            stderr.contains(needle),
            "the limits statement must reach stderr and mention {needle}; got: {stderr}"
        );
    }
}

/// The derivation summary must say what was derived, and must not echo the
/// phrase while doing it.
#[test]
fn the_run_reports_what_it_derived_without_echoing_the_phrase() {
    let (_dir, path) = phrase_file();
    let out = argos(&[
        "--zcashd-phrase",
        "--gap-limit",
        "5",
        "--seed-file",
        path.to_str().expect("utf-8 path"),
        "show-keys",
    ]);

    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("zcashd recovery phrase"),
        "expected a derivation summary, got: {stderr}"
    );

    let combined = format!("{}{}", stderr, String::from_utf8_lossy(&out.stdout));
    assert!(
        !combined.contains("abandon"),
        "the phrase must never be echoed back"
    );
}

/// `--gap-limit` must actually change the derived key count, or the
/// "configurable gap limit" claim is decoration.
#[test]
fn the_gap_limit_changes_how_many_keys_are_derived() {
    let (_dir, path) = phrase_file();
    let p = path.to_str().expect("utf-8 path");

    let narrow = stderr_of(&argos(&[
        "--zcashd-phrase", "--gap-limit", "3", "--seed-file", p, "show-keys",
    ]));
    let wide = stderr_of(&argos(&[
        "--zcashd-phrase", "--gap-limit", "9", "--seed-file", p, "show-keys",
    ]));

    // `derive_all` yields `2 * gap` Sapling keys (both eras) and
    // `2 * gap` transparent (external + internal).
    assert!(
        narrow.contains("6 sapling") && narrow.contains("6 transparent"),
        "gap 3 should derive 6 of each; got: {narrow}"
    );
    assert!(
        wide.contains("18 sapling") && wide.contains("18 transparent"),
        "gap 9 should derive 18 of each; got: {wide}"
    );
}

/// A single era derives half of what `auto` does — proof the era flag
/// selects rather than being ignored.
#[test]
fn selecting_one_era_derives_fewer_keys_than_auto() {
    let (_dir, path) = phrase_file();
    let p = path.to_str().expect("utf-8 path");

    let auto = stderr_of(&argos(&[
        "--zcashd-phrase", "--gap-limit", "4", "--seed-file", p, "show-keys",
    ]));
    let post = stderr_of(&argos(&[
        "--zcashd-phrase", "--zcashd-era", "post47", "--gap-limit", "4", "--seed-file", p,
        "show-keys",
    ]));

    assert!(auto.contains("8 sapling"), "auto/gap 4 → 8 sapling: {auto}");
    assert!(post.contains("4 sapling"), "post47/gap 4 → 4 sapling: {post}");
}

/// Pre-4.7 derives Sapling only.
///
/// Not an omission: pre-4.7 zcashd did not derive transparent keys from
/// the Sapling HD seed — `getnewaddress` produced independent random keys
/// that lived only in `wallet.dat` — so deriving any here would invent
/// addresses the wallet never had.
#[test]
fn the_pre47_era_derives_no_transparent_keys() {
    let (_dir, path) = phrase_file();
    let out = argos(&[
        "--zcashd-phrase",
        "--zcashd-era",
        "pre47",
        "--gap-limit",
        "4",
        "--seed-file",
        path.to_str().expect("utf-8 path"),
        "show-keys",
    ]);

    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("4 sapling") && stderr.contains("0 transparent"),
        "pre-4.7 must derive Sapling only; got: {stderr}"
    );
}

/// An invalid phrase must be refused before any network work, and the
/// refusal must not quote the phrase back.
#[test]
fn an_invalid_phrase_is_refused_without_echoing_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("bad.txt");
    std::fs::write(&path, "zebra zebra zebra zebra\n").expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }

    let out = argos(&[
        "--zcashd-phrase",
        "--seed-file",
        path.to_str().expect("utf-8 path"),
        "show-keys",
    ]);

    assert!(!out.status.success(), "an invalid phrase must be refused");
    let stderr = stderr_of(&out);
    assert!(
        !stderr.contains("zebra"),
        "the refusal must not echo phrase material: {stderr}"
    );
}

/// The phrase must never be accepted as a flag value.
///
/// T-S6: an argument lands in shell history and in `ps` output for every
/// user on the box. `--zcashd-phrase` is a boolean switch, so a phrase
/// following it must be parsed as something else and rejected — never
/// silently consumed as the phrase.
#[test]
fn the_phrase_cannot_be_passed_as_a_flag_value() {
    let out = argos(&["--zcashd-phrase", TEST_PHRASE, "scan"]);
    assert!(
        !out.status.success(),
        "a phrase supplied as an argument must not be accepted"
    );
}
