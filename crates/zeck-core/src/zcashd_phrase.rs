//! A zcashd emergency recovery phrase, with no `wallet.dat`.
//!
//! zcashd 4.7.0 gave every wallet an "emergency recovery phrase". A user
//! who kept the phrase but lost `wallet.dat` currently has no route into
//! Argos: [`crate::key_source::ImportedKeySource`] needs the file, and
//! [`crate::key_source::SeedKeySource`] walks the *standard* ZIP-32
//! account path, which is not where zcashd put its legacy addresses.
//! This module is that missing route.
//!
//! # The two seeds a single phrase can mean
//!
//! This is the whole reason the module is delicate. One phrase yields two
//! entirely different byte strings, and choosing wrong produces a
//! successful, empty scan rather than an error:
//!
//! * **Post-4.7 wallets.** The phrase is an ordinary BIP-39 mnemonic and
//!   the wallet seed is its PBKDF2 output — `Mnemonic::to_seed("")`, 64
//!   bytes. This is what [`crate::derivation::mnemonic_seed`] already does.
//!
//! * **Wallets upgraded from before 4.7.** These already had a randomly
//!   generated Sapling HD seed, and 4.7 did not throw it away: it
//!   *encoded those seed bytes as the mnemonic's entropy*. Recovering
//!   those keys means reversing the phrase back to its raw entropy —
//!   `Mnemonic::entropy()` — and using it directly as the seed. The
//!   4.7.0 release notes say so in capitals:
//!
//!   > THIS RECONSTRUCTION DOES NOT FOLLOW THE NORMAL PROCESS OF
//!   > DERIVATION FROM THE EMERGENCY RECOVERY PHRASE.
//!
//! The two are unrelated byte strings. [`legacy_entropy_seed`] and
//! [`bip39_seed`] are deliberately separate functions with names that say
//! which is which, and [`ZcashdSeedKind`] forces every caller to choose.
//! `a_phrase_yields_two_different_seeds` pins the distinction: if that
//! test ever passes trivially, this module has silently stopped working.
//!
//! # Derivation paths
//!
//! All three are transcribed from archived zcashd v5.4.2 source rather
//! than from memory, and each is pinned by a test naming its origin.
//!
//! | What | Path | Seed |
//! |---|---|---|
//! | Legacy Sapling, post-4.7 (`z_getnewaddress`) | `m/32'/coin_type'/0x7FFFFFFF'/address_index'` | BIP-39 |
//! | Legacy Sapling, pre-4.7 (`ForAccount`) | `m/32'/coin_type'/account'` | entropy |
//! | Legacy transparent (`getnewaddress`) | `m/44'/coin_type'/0x7FFFFFFF'/change/index` | BIP-39 |
//!
//! # Why these arrive as *imported* keys
//!
//! [`ZcashdPhraseKeySource::wallet_seed`] returns `None` even though a
//! seed plainly exists, and that is not an oversight. Handing the seed to
//! `zcash_client_sqlite` would make it enumerate standard ZIP-32 accounts
//! at `m/32'/coin_type'/account'` — a path zcashd's legacy addresses are
//! not on. The scan would succeed and find nothing.
//!
//! So the legacy keys are derived here, eagerly, and presented through
//! [`KeySource::imported_keys`]. That routes them to
//! [`crate::key_source::RecoveryRoute::ImportedAccounts`], which already
//! scans and sweeps a fixed key set — reusing the existing scan, balance,
//! sweep, fee and confirmation machinery without changing any of it.
//!
//! # What a phrase cannot recover
//!
//! [`PHRASE_CANNOT_RECOVER`] is the user-facing statement of this, and is
//! tested for naming each limit. Randomly generated Sprout keys, keys
//! brought in with `z_importkey` or `importprivkey`, and watch-only
//! material existed only inside `wallet.dat`. They are not derived from
//! any seed, so no phrase reproduces them and no gap limit finds them.

use argos_wallet_import::{
    keys::{Provenance, SaplingKey, TransparentKey},
    ImportedKeys,
};
use bip0039::{English, Mnemonic};
use sapling_crypto::zip32::ExtendedSpendingKey;
use secrecy::{ExposeSecret, Secret, SecretString};
use sha2::{Digest, Sha256};
use zcash_keys::encoding::AddressCodec;
use zcash_protocol::consensus::{MAIN_NETWORK, TEST_NETWORK};
use zcash_transparent::keys::AccountPrivKey;
use zip32::{AccountId, ChildIndex};

use crate::{
    derivation::mnemonic_seed,
    error::{ZeckError, ZeckResult},
    key_source::{KeySource, KeySourceFingerprint, FINGERPRINT_DOMAIN},
    models::{AddressScope, ZeckNetwork},
};

/// zcashd's `ZCASH_LEGACY_ACCOUNT`, defined there as
/// `HARDENED_KEY_LIMIT - 1`.
///
/// zcashd's own comment calls this "not a standard path, but instead is a
/// predictable location for legacy zcashd-derived keys", chosen so legacy
/// addresses cannot collide with ZIP-316 accounts. It is the largest
/// index a hardened derivation accepts, which is why
/// [`hardened`] can take it without a range check failing.
pub const ZCASH_LEGACY_ACCOUNT: u32 = 0x7FFF_FFFF;

/// ZIP-32's purpose index for shielded key derivation: `m/32'/...`.
const ZIP32_SHIELDED_PURPOSE: u32 = 32;

/// Default number of consecutive unused addresses to tolerate before
/// concluding a derivation branch is exhausted.
///
/// zcashd's own address counters are in `wallet.dat`, which is precisely
/// what a phrase-only recovery does not have, so the index a user reached
/// is unknowable and must be searched for. 20 matches the BIP-44 default
/// and the gap Argos already uses elsewhere; [`GapLimits`] makes it
/// configurable because a heavy zcashd user can easily have exceeded it.
pub const DEFAULT_GAP_LIMIT: u32 = 20;

/// What a recovery phrase provably cannot bring back.
///
/// Stated as a constant, and tested for naming every category, because a
/// user who has already lost a wallet file is owed an explicit boundary
/// rather than an empty result they must interpret. Any silence here
/// reads as "there was nothing there", which is a different and much
/// worse claim than "this route cannot see it".
pub const PHRASE_CANNOT_RECOVER: &str = "\
A recovery phrase reproduces only keys that were derived from the wallet \
seed. It cannot recover randomly generated Sprout keys, keys imported with \
z_importkey or importprivkey, watch-only addresses, or any other secret \
that existed only inside wallet.dat. Those are not derived from the seed, \
so no phrase and no gap limit can find them. Recovering them requires the \
wallet.dat file itself.";

/// Which of the two byte strings a phrase should be reduced to.
///
/// Deliberately not defaulted. A caller that does not know which era of
/// wallet it is recovering should search both — see
/// [`ZcashdPhraseKeySource::derive_all`] — rather than guess, because the
/// wrong choice yields an empty scan and no error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZcashdSeedKind {
    /// zcashd 4.7.0 or later: the phrase is an ordinary BIP-39 mnemonic.
    Bip39,
    /// A wallet upgraded from before 4.7.0: the phrase encodes the bytes
    /// of the pre-existing random Sapling HD seed as its entropy.
    LegacyEntropy,
}

/// How far to search each derivation branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapLimits {
    /// Legacy Sapling `address_index` values to derive.
    pub sapling: u32,
    /// Legacy transparent `index` values to derive, per change branch.
    pub transparent: u32,
    /// Standard ZIP-32 accounts to try on the pre-4.7 path.
    ///
    /// Separate from `sapling` because it walks a different level of the
    /// tree: pre-4.7 zcashd incremented the *account*, whereas post-4.7
    /// legacy derivation fixes the account and increments the address.
    pub pre47_accounts: u32,
}

impl Default for GapLimits {
    fn default() -> Self {
        Self {
            sapling: DEFAULT_GAP_LIMIT,
            transparent: DEFAULT_GAP_LIMIT,
            pre47_accounts: DEFAULT_GAP_LIMIT,
        }
    }
}

impl GapLimits {
    /// Every branch searched to the same depth.
    pub fn uniform(limit: u32) -> Self {
        Self {
            sapling: limit,
            transparent: limit,
            pre47_accounts: limit,
        }
    }
}

/// The 64-byte BIP-39 seed: `PBKDF2(phrase, "mnemonic")`.
///
/// Correct for any wallet created by zcashd 4.7.0 or later. Wrong, and
/// silently so, for the legacy keys of a wallet upgraded into 4.7 —
/// see [`legacy_entropy_seed`].
pub fn bip39_seed(phrase: &SecretString) -> ZeckResult<Secret<[u8; 64]>> {
    mnemonic_seed(phrase)
}

/// The pre-4.7 Sapling HD seed, recovered from the phrase's raw entropy.
///
/// Not a BIP-39 seed and not 64 bytes: these are the literal bytes of the
/// randomly generated seed the wallet held before it was upgraded, which
/// zcashd 4.7 re-encoded as the mnemonic's entropy specifically so this
/// reconstruction would be possible. A 24-word phrase yields 32 bytes.
///
/// Returns the entropy even for phrase lengths that a pre-4.7 wallet
/// could not have produced; whether a given phrase *is* an encoded legacy
/// seed is unknowable from the phrase alone, and the only way to find out
/// is to derive and scan.
pub fn legacy_entropy_seed(phrase: &SecretString) -> ZeckResult<Secret<Vec<u8>>> {
    // The error is discarded rather than wrapped: `bip0039`'s `UnknownWord`
    // Display embeds the offending word, and that word is phrase material.
    // `crate::derivation` redacts this for the same reason.
    let mnemonic = Mnemonic::<English>::from_phrase(phrase.expose_secret()).map_err(|_| {
        ZeckError::InvalidMnemonic("the recovery phrase is not a valid BIP-39 mnemonic".to_owned())
    })?;
    Ok(Secret::new(mnemonic.entropy().to_vec()))
}

/// `ChildIndex::hardened`, with the range check surfaced as an error
/// rather than a panic.
///
/// `zip32` panics on an out-of-range index. Every index this module
/// derives is either a constant or a user-supplied gap position, and a
/// user-supplied one reaching a panic in a recovery tool is not an
/// acceptable failure mode.
fn hardened(index: u32) -> ZeckResult<ChildIndex> {
    // `ChildIndex::hardened` asserts rather than returning an Option, so
    // the bound is checked here instead of catching a panic.
    if index >= (1 << 31) {
        return Err(ZeckError::InvalidConfig(format!(
            "derivation index {index} is out of range for hardened derivation"
        )));
    }
    Ok(ChildIndex::hardened(index))
}

/// Legacy Sapling spending key at
/// `m/32'/coin_type'/0x7FFFFFFF'/address_index'`.
///
/// The path zcashd's `SaplingExtendedSpendingKey::Legacy` walks, which is
/// where every address from `z_getnewaddress` lands on 4.7.0 and later.
/// All four levels are hardened.
pub fn legacy_sapling_spending_key(
    seed: &[u8],
    network: ZeckNetwork,
    address_index: u32,
) -> ZeckResult<ExtendedSpendingKey> {
    Ok(ExtendedSpendingKey::master(seed)
        .derive_child(hardened(ZIP32_SHIELDED_PURPOSE)?)
        .derive_child(hardened(network.coin_type())?)
        .derive_child(hardened(ZCASH_LEGACY_ACCOUNT)?)
        .derive_child(hardened(address_index)?))
}

/// Pre-4.7 Sapling spending key at `m/32'/coin_type'/account'`.
///
/// zcashd's `SaplingExtendedSpendingKey::ForAccount`. Three levels, not
/// four: the legacy-account marker did not exist yet. `seed` must be the
/// output of [`legacy_entropy_seed`], not a BIP-39 seed.
pub fn pre47_sapling_spending_key(
    seed: &[u8],
    network: ZeckNetwork,
    account: u32,
) -> ZeckResult<ExtendedSpendingKey> {
    Ok(ExtendedSpendingKey::master(seed)
        .derive_child(hardened(ZIP32_SHIELDED_PURPOSE)?)
        .derive_child(hardened(network.coin_type())?)
        .derive_child(hardened(account)?))
}

/// Legacy transparent account key at `m/44'/coin_type'/0x7FFFFFFF'`.
///
/// zcashd derives `getnewaddress` keys through
/// `transparent::AccountKey::KeyPath(BIP44CoinType(), ZCASH_LEGACY_ACCOUNT,
/// external, index)`. Note the account: the legacy marker, *not* account
/// 0. Argos's existing [`crate::derivation`] helper uses
/// `AccountId::ZERO`, which is correct for ZecWallet Lite and wrong here.
pub fn legacy_transparent_account_key(
    seed: &[u8; 64],
    network: ZeckNetwork,
) -> ZeckResult<AccountPrivKey> {
    let account = AccountId::try_from(ZCASH_LEGACY_ACCOUNT).map_err(|_| {
        ZeckError::Internal("ZCASH_LEGACY_ACCOUNT is not a valid ZIP 32 account id".to_owned())
    })?;

    match network {
        ZeckNetwork::Mainnet => AccountPrivKey::from_seed(&MAIN_NETWORK, seed, account),
        ZeckNetwork::Testnet => AccountPrivKey::from_seed(&TEST_NETWORK, seed, account),
    }
    .map_err(|err| ZeckError::Internal(err.to_string()))
}

/// A zcashd emergency recovery phrase, with no wallet file.
///
/// Derives the legacy key set eagerly at construction time and presents
/// it through [`KeySource::imported_keys`], so the existing imported-scan
/// and sweep paths handle it unchanged. See the module docs for why this
/// is not routed as a seed.
pub struct ZcashdPhraseKeySource {
    network: ZeckNetwork,
    gaps: GapLimits,
    keys: ImportedKeys,
    /// Retained for [`KeySource::fingerprint`], which must stay stable
    /// across the lifetime of a resume and must not depend on how many
    /// keys a given gap limit happened to derive.
    phrase: SecretString,
    /// Which eras were derived. Affects the fingerprint, because two
    /// searches of the same phrase covering different eras are different
    /// key sets and must not share a workspace.
    kinds: Vec<ZcashdSeedKind>,
}

impl ZcashdPhraseKeySource {
    /// Derive one era's key material.
    ///
    /// Use this when the wallet's era is known. When it is not — the
    /// common case, since a user rarely recalls which zcashd version
    /// created the wallet — prefer [`Self::derive_all`].
    pub fn new(
        phrase: SecretString,
        network: ZeckNetwork,
        kind: ZcashdSeedKind,
        gaps: GapLimits,
    ) -> ZeckResult<Self> {
        Self::build(phrase, network, vec![kind], gaps)
    }

    /// Derive both the post-4.7 and pre-4.7 key sets.
    ///
    /// The recommended entry point. The eras are cheap to derive and
    /// mutually exclusive in practice, so searching both costs a little
    /// scan time and removes the one question a user cannot reliably
    /// answer. Guessing wrong is not an error the scan can report — it is
    /// an empty result.
    pub fn derive_all(
        phrase: SecretString,
        network: ZeckNetwork,
        gaps: GapLimits,
    ) -> ZeckResult<Self> {
        Self::build(
            phrase,
            network,
            vec![ZcashdSeedKind::Bip39, ZcashdSeedKind::LegacyEntropy],
            gaps,
        )
    }

    fn build(
        phrase: SecretString,
        network: ZeckNetwork,
        kinds: Vec<ZcashdSeedKind>,
        gaps: GapLimits,
    ) -> ZeckResult<Self> {
        let mut keys = ImportedKeys::default();

        for kind in &kinds {
            match kind {
                ZcashdSeedKind::Bip39 => {
                    let seed = bip39_seed(&phrase)?;
                    Self::derive_post47(seed.expose_secret(), network, gaps, &mut keys)?;
                }
                ZcashdSeedKind::LegacyEntropy => {
                    let seed = legacy_entropy_seed(&phrase)?;
                    Self::derive_pre47(seed.expose_secret(), network, gaps, &mut keys)?;
                }
            }
        }

        Ok(Self {
            network,
            gaps,
            keys,
            phrase,
            kinds,
        })
    }

    /// Post-4.7: legacy Sapling at the fixed legacy account, plus legacy
    /// transparent on both change branches.
    fn derive_post47(
        seed: &[u8; 64],
        network: ZeckNetwork,
        gaps: GapLimits,
        into: &mut ImportedKeys,
    ) -> ZeckResult<()> {
        for index in 0..gaps.sapling {
            let extsk = legacy_sapling_spending_key(seed, network, index)?;
            push_sapling(into, &extsk);
        }

        let account = legacy_transparent_account_key(seed, network)?;
        for scope in [AddressScope::External, AddressScope::Internal] {
            for index in 0..gaps.transparent {
                let child = zcash_transparent::keys::NonHardenedChildIndex::from_index(index)
                    .ok_or_else(|| {
                        ZeckError::InvalidConfig(format!(
                            "transparent index {index} is out of range"
                        ))
                    })?;
                let secret = account
                    .derive_secret_key(scope.into(), child)
                    .map_err(|err| ZeckError::Internal(err.to_string()))?;
                into.transparent.push(TransparentKey {
                    secret: Secret::new(secret.secret_bytes()),
                    provenance: Provenance::HdDerived,
                });
            }
        }

        Ok(())
    }

    /// Pre-4.7: standard-path Sapling accounts over the *entropy* seed.
    ///
    /// No transparent branch. Pre-4.7 zcashd did not derive transparent
    /// keys from the Sapling HD seed — `getnewaddress` produced
    /// independent random keys that lived only in `wallet.dat` — so
    /// deriving any here would invent addresses the wallet never had.
    fn derive_pre47(
        seed: &[u8],
        network: ZeckNetwork,
        gaps: GapLimits,
        into: &mut ImportedKeys,
    ) -> ZeckResult<()> {
        for account in 0..gaps.pre47_accounts {
            let extsk = pre47_sapling_spending_key(seed, network, account)?;
            push_sapling(into, &extsk);
        }
        Ok(())
    }

    pub fn network(&self) -> ZeckNetwork {
        self.network
    }

    pub fn gap_limits(&self) -> GapLimits {
        self.gaps
    }

    /// Re-derive with wider gaps, preserving the phrase.
    ///
    /// The resume path: a scan that found funds at the edge of its window
    /// should widen rather than restart. The fingerprint changes with the
    /// gaps, so the widened search correctly gets its own workspace
    /// instead of resuming into a narrower one's partial state.
    pub fn widen(&self, gaps: GapLimits) -> ZeckResult<Self> {
        Self::build(self.phrase.clone(), self.network, self.kinds.clone(), gaps)
    }
}

/// The default Sapling address of every key in `keys`, encoded for
/// `network`.
///
/// Exists so a user can see *which addresses will be searched* before
/// committing to a scan. For a phrase-only recovery that is the only
/// offline check available: there is no wallet file to compare against, so
/// the addresses themselves are the evidence that the right derivation ran.
///
/// Encoding goes through `consensus_network` for the same reason
/// [`crate::imported::encode_transparent_address`] does — a regtest harness
/// installs its own parameters process-wide, and matching on
/// [`ZeckNetwork`] here would emit a testnet-prefixed address that the
/// regtest node rejects.
pub fn sapling_addresses(keys: &ImportedKeys, network: ZeckNetwork) -> ZeckResult<Vec<String>> {
    let params = crate::workspace::consensus_network(network);
    keys.sapling
        .iter()
        .map(|key| {
            let extsk = ExtendedSpendingKey::from_bytes(key.extsk.expose_secret()).map_err(|_| {
                ZeckError::Internal("a derived Sapling key failed to round-trip".to_owned())
            })?;
            let address = extsk
                .to_diversifiable_full_viewing_key()
                .default_address()
                .1;
            Ok(address.encode(&params))
        })
        .collect()
}

fn push_sapling(into: &mut ImportedKeys, extsk: &ExtendedSpendingKey) {
    into.sapling.push(SaplingKey {
        extsk: Secret::new(extsk.to_bytes().to_vec()),
        provenance: Provenance::HdDerived,
    });
}

impl KeySource for ZcashdPhraseKeySource {
    /// Hashes the phrase, network, era set and gap limits — not the
    /// derived keys.
    ///
    /// The keys are a pure function of those inputs, so hashing the
    /// inputs is equivalent and much cheaper. It also keeps the
    /// fingerprint stable if key *ordering* is ever changed, which would
    /// otherwise silently orphan every existing workspace.
    fn fingerprint(&self) -> ZeckResult<KeySourceFingerprint> {
        let mut h = Sha256::new();
        h.update(FINGERPRINT_DOMAIN);
        // Distinct label from "seed" and "imported": the same phrase typed
        // as a ZecWallet Lite seed is a different recovery and must not
        // share a workspace with this one.
        h.update(b"zcashd-phrase");

        let mut inner = Sha256::new();
        inner.update(b"argos-zcashd-phrase-id-v1");
        inner.update(self.phrase.expose_secret().as_bytes());
        h.update(inner.finalize());

        h.update(self.network.coin_type().to_le_bytes());
        h.update(self.gaps.sapling.to_le_bytes());
        h.update(self.gaps.transparent.to_le_bytes());
        h.update(self.gaps.pre47_accounts.to_le_bytes());
        for kind in &self.kinds {
            h.update([match kind {
                ZcashdSeedKind::Bip39 => 0u8,
                ZcashdSeedKind::LegacyEntropy => 1u8,
            }]);
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        Ok(KeySourceFingerprint::from_digest(out))
    }

    /// Always `None`, deliberately.
    ///
    /// A seed here would make `zcash_client_sqlite` enumerate standard
    /// ZIP-32 accounts, which is not where zcashd's legacy addresses
    /// live. The scan would succeed and report nothing. See the module
    /// docs.
    fn wallet_seed(&self) -> ZeckResult<Option<[u8; 64]>> {
        Ok(None)
    }

    fn workspace_path_component(&self) -> ZeckResult<String> {
        // Domain-separated so it can never collide with a bech32 seed
        // fingerprint or an `imported-` component.
        Ok(format!("zcashd-phrase-{}", self.fingerprint()?.to_hex()))
    }

    fn imported_keys(&self) -> Option<&ImportedKeys> {
        Some(&self.keys)
    }

    fn describe(&self) -> String {
        format!(
            "zcashd recovery phrase ({} sapling, {} transparent; gap {}/{})",
            self.keys.sapling.len(),
            self.keys.transparent.len(),
            self.gaps.sapling,
            self.gaps.transparent,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The BIP-39 test vector already used across this crate. No real funds.
    const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon art";

    fn phrase() -> SecretString {
        SecretString::new(SEED.to_owned())
    }

    /// The single most important property in this module.
    ///
    /// If these ever coincide, the pre-4.7 and post-4.7 routes have
    /// collapsed into one and an entire class of wallet silently stops
    /// being recoverable — with no error, just an empty scan.
    #[test]
    fn a_phrase_yields_two_different_seeds() {
        let bip39 = bip39_seed(&phrase()).unwrap();
        let entropy = legacy_entropy_seed(&phrase()).unwrap();

        assert_eq!(bip39.expose_secret().len(), 64, "BIP-39 seed is 64 bytes");
        assert_eq!(
            entropy.expose_secret().len(),
            32,
            "a 24-word phrase encodes 32 bytes of entropy"
        );
        assert_ne!(
            &bip39.expose_secret()[..32],
            entropy.expose_secret().as_slice(),
            "the entropy must not be a prefix of the BIP-39 seed"
        );
    }

    /// zcashd defines `ZCASH_LEGACY_ACCOUNT = HARDENED_KEY_LIMIT - 1`,
    /// where `HARDENED_KEY_LIMIT` is 2^31. Pinned as a literal so a
    /// refactor cannot drift it.
    #[test]
    fn the_legacy_account_is_the_constant_zcashd_defines() {
        assert_eq!(ZCASH_LEGACY_ACCOUNT, (1u32 << 31) - 1);
        assert_eq!(ZCASH_LEGACY_ACCOUNT, 0x7FFF_FFFF);
        assert!(
            hardened(ZCASH_LEGACY_ACCOUNT).is_ok(),
            "the legacy account must be a valid hardened index"
        );

        // Independent corroboration: `zip32` reserves the same index as
        // its private-use subtree, which is exactly the property zcashd
        // relied on when it chose this value to avoid colliding with
        // ZIP-316 accounts. Two unrelated sources agreeing on the
        // constant is worth more than either alone.
        assert_eq!(
            hardened(ZCASH_LEGACY_ACCOUNT).unwrap(),
            ChildIndex::PRIVATE_USE
        );
    }

    /// The four-level legacy path must not equal the three-level standard
    /// path at the same trailing index. If it did, Argos's existing seed
    /// derivation would already have covered this case and the whole
    /// module would be redundant — so this is also the test that proves
    /// the feature is necessary.
    #[test]
    fn the_legacy_sapling_path_differs_from_the_standard_path() {
        let seed = bip39_seed(&phrase()).unwrap();

        let legacy = legacy_sapling_spending_key(seed.expose_secret(), ZeckNetwork::Mainnet, 0)
            .unwrap();
        let standard = zcash_keys::keys::sapling::spending_key(
            seed.expose_secret(),
            ZeckNetwork::Mainnet.coin_type(),
            AccountId::ZERO,
        );

        assert_ne!(legacy.to_bytes(), standard.to_bytes());
    }

    /// The strongest check in this module.
    ///
    /// [`pre47_sapling_spending_key`] walks `m/32'/coin_type'/account'`,
    /// which is exactly the path `zcash_keys::keys::sapling::spending_key`
    /// implements. So the two must agree *byte for byte* — and if they do,
    /// this module's `master` + `derive_child` chain is not merely
    /// plausible, it is identical to librustzcash's own ZIP-32
    /// implementation, which is itself tested against the ZIP-32 vectors.
    ///
    /// [`legacy_sapling_spending_key`] is then that same verified chain
    /// plus one further documented level, which is the only part taken on
    /// the authority of the zcashd source rather than proven here.
    ///
    /// Note the seed: the *entropy* seed, since that is what the pre-4.7
    /// path takes. The equality holds for any seed; using the entropy one
    /// keeps the test honest about how the function is actually called.
    #[test]
    fn the_pre47_path_is_byte_identical_to_librustzcash() {
        let seed = legacy_entropy_seed(&phrase()).unwrap();

        for account in 0..4u32 {
            let ours =
                pre47_sapling_spending_key(seed.expose_secret(), ZeckNetwork::Mainnet, account)
                    .unwrap();
            let theirs = zcash_keys::keys::sapling::spending_key(
                seed.expose_secret(),
                ZeckNetwork::Mainnet.coin_type(),
                AccountId::try_from(account).unwrap(),
            );

            assert_eq!(
                ours.to_bytes(),
                theirs.to_bytes(),
                "path construction diverged from librustzcash at account {account}"
            );
        }
    }

    /// The legacy key must be the standard key's *child* at the legacy
    /// account, not something else entirely. This pins the structural
    /// relationship between the two paths: same first two levels, then
    /// `0x7FFFFFFF'` then the address index.
    #[test]
    fn the_legacy_path_is_the_standard_path_extended_by_two_levels() {
        let seed = bip39_seed(&phrase()).unwrap();

        let expected = ExtendedSpendingKey::master(seed.expose_secret())
            .derive_child(ChildIndex::hardened(32))
            .derive_child(ChildIndex::hardened(ZeckNetwork::Mainnet.coin_type()))
            .derive_child(ChildIndex::hardened(ZCASH_LEGACY_ACCOUNT))
            .derive_child(ChildIndex::hardened(3));

        let actual =
            legacy_sapling_spending_key(seed.expose_secret(), ZeckNetwork::Mainnet, 3).unwrap();

        assert_eq!(actual.to_bytes(), expected.to_bytes());
    }

    #[test]
    fn legacy_sapling_derivation_is_deterministic() {
        let seed = bip39_seed(&phrase()).unwrap();
        let a = legacy_sapling_spending_key(seed.expose_secret(), ZeckNetwork::Mainnet, 7).unwrap();
        let b = legacy_sapling_spending_key(seed.expose_secret(), ZeckNetwork::Mainnet, 7).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn each_address_index_yields_a_distinct_key() {
        let seed = bip39_seed(&phrase()).unwrap();
        let mut seen = std::collections::HashSet::new();
        for index in 0..8 {
            let k =
                legacy_sapling_spending_key(seed.expose_secret(), ZeckNetwork::Mainnet, index)
                    .unwrap();
            assert!(seen.insert(k.to_bytes()), "index {index} collided");
        }
    }

    /// Mainnet is coin type 133 and testnet 1, so the same phrase must
    /// never produce the same key on both. A network mix-up would show a
    /// user someone else's empty address and call it theirs.
    #[test]
    fn networks_do_not_share_keys() {
        let seed = bip39_seed(&phrase()).unwrap();
        let main =
            legacy_sapling_spending_key(seed.expose_secret(), ZeckNetwork::Mainnet, 0).unwrap();
        let test =
            legacy_sapling_spending_key(seed.expose_secret(), ZeckNetwork::Testnet, 0).unwrap();
        assert_ne!(main.to_bytes(), test.to_bytes());
    }

    /// The pre-4.7 path over the entropy seed must differ from the
    /// post-4.7 path over the BIP-39 seed, at every level.
    #[test]
    fn the_two_eras_derive_different_keys() {
        let bip39 = bip39_seed(&phrase()).unwrap();
        let entropy = legacy_entropy_seed(&phrase()).unwrap();

        let post =
            legacy_sapling_spending_key(bip39.expose_secret(), ZeckNetwork::Mainnet, 0).unwrap();
        let pre =
            pre47_sapling_spending_key(entropy.expose_secret(), ZeckNetwork::Mainnet, 0).unwrap();

        assert_ne!(post.to_bytes(), pre.to_bytes());
    }

    /// The transparent account must be the legacy marker, not account 0.
    /// Argos's existing helper uses `AccountId::ZERO`; using it here would
    /// be a plausible-looking bug that finds nothing.
    #[test]
    fn the_transparent_account_is_the_legacy_marker_not_zero() {
        let seed = bip39_seed(&phrase()).unwrap();

        let legacy = legacy_transparent_account_key(seed.expose_secret(), ZeckNetwork::Mainnet)
            .unwrap()
            .to_account_pubkey();
        let zero = AccountPrivKey::from_seed(&MAIN_NETWORK, seed.expose_secret(), AccountId::ZERO)
            .unwrap()
            .to_account_pubkey();

        assert_ne!(
            legacy.serialize(),
            zero.serialize(),
            "legacy transparent derivation must not use account 0"
        );
    }

    #[test]
    fn a_hardened_index_out_of_range_is_an_error_not_a_panic() {
        assert!(hardened(1u32 << 31).is_err());
        assert!(hardened(u32::MAX).is_err());
    }

    #[test]
    fn deriving_all_eras_produces_both_key_sets() {
        let source = ZcashdPhraseKeySource::derive_all(
            phrase(),
            ZeckNetwork::Mainnet,
            GapLimits::uniform(4),
        )
        .unwrap();

        let keys = source.imported_keys().expect("phrase source is imported");
        // 4 post-4.7 legacy + 4 pre-4.7 accounts.
        assert_eq!(keys.sapling.len(), 8);
        // 4 external + 4 internal, post-4.7 only.
        assert_eq!(keys.transparent.len(), 8);
        assert!(keys.sprout.is_empty(), "a phrase never yields Sprout keys");
    }

    /// Every derived key must be distinct. A duplicate would mean the
    /// gap search is walking the same address repeatedly and reporting
    /// coverage it does not have.
    #[test]
    fn the_derived_key_set_has_no_duplicates() {
        let source = ZcashdPhraseKeySource::derive_all(
            phrase(),
            ZeckNetwork::Mainnet,
            GapLimits::uniform(6),
        )
        .unwrap();
        let keys = source.imported_keys().unwrap();

        let mut sapling = std::collections::HashSet::new();
        for k in &keys.sapling {
            assert!(
                sapling.insert(k.extsk.expose_secret().clone()),
                "duplicate sapling key"
            );
        }
        let mut transparent = std::collections::HashSet::new();
        for k in &keys.transparent {
            assert!(
                transparent.insert(*k.secret.expose_secret()),
                "duplicate transparent key"
            );
        }
    }

    /// A phrase source must never be handed a wallet seed — that is what
    /// routes it down the wrong derivation path. See the module docs.
    #[test]
    fn a_phrase_source_reports_no_wallet_seed() {
        let source =
            ZcashdPhraseKeySource::derive_all(phrase(), ZeckNetwork::Mainnet, GapLimits::uniform(2))
                .unwrap();
        assert!(source.wallet_seed().unwrap().is_none());
    }

    /// The same phrase used as a ZecWallet Lite seed is a different
    /// recovery of a different wallet. Sharing a workspace would let one
    /// resume into the other's partial state.
    #[test]
    fn a_zcashd_phrase_never_collides_with_the_same_phrase_as_a_zwl_seed() {
        use crate::key_source::SeedKeySource;

        let zcashd =
            ZcashdPhraseKeySource::derive_all(phrase(), ZeckNetwork::Mainnet, GapLimits::default())
                .unwrap();
        let zwl = SeedKeySource::new(phrase());

        assert_ne!(zcashd.fingerprint().unwrap(), zwl.fingerprint().unwrap());
        assert_ne!(
            zcashd.workspace_path_component().unwrap(),
            zwl.workspace_path_component().unwrap()
        );
    }

    /// Widening the gap must start a new workspace rather than resume
    /// into the narrower search's state.
    #[test]
    fn a_wider_gap_is_a_different_key_source() {
        let narrow =
            ZcashdPhraseKeySource::derive_all(phrase(), ZeckNetwork::Mainnet, GapLimits::uniform(4))
                .unwrap();
        let wide = narrow.widen(GapLimits::uniform(40)).unwrap();

        assert_ne!(narrow.fingerprint().unwrap(), wide.fingerprint().unwrap());
        assert!(
            wide.imported_keys().unwrap().sapling.len()
                > narrow.imported_keys().unwrap().sapling.len()
        );
    }

    /// Widening must extend the existing search, not shift it: every key
    /// the narrow search found must still be present, at the same index.
    /// Otherwise a resume would rescan different addresses and could
    /// report a previously-found balance as gone.
    #[test]
    fn widening_extends_rather_than_shifts_the_search() {
        let narrow =
            ZcashdPhraseKeySource::derive_all(phrase(), ZeckNetwork::Mainnet, GapLimits::uniform(3))
                .unwrap();
        let wide = narrow.widen(GapLimits::uniform(9)).unwrap();

        let narrow_keys = narrow.imported_keys().unwrap();
        let wide_keys = wide.imported_keys().unwrap();

        let wide_set: std::collections::HashSet<_> = wide_keys
            .sapling
            .iter()
            .map(|k| k.extsk.expose_secret().clone())
            .collect();
        for k in &narrow_keys.sapling {
            assert!(
                wide_set.contains(k.extsk.expose_secret()),
                "widening dropped a key the narrower search had found"
            );
        }
    }

    #[test]
    fn the_fingerprint_is_stable_across_calls() {
        let source =
            ZcashdPhraseKeySource::derive_all(phrase(), ZeckNetwork::Mainnet, GapLimits::uniform(2))
                .unwrap();
        assert_eq!(source.fingerprint().unwrap(), source.fingerprint().unwrap());
    }

    #[test]
    fn networks_do_not_share_a_workspace() {
        let main =
            ZcashdPhraseKeySource::derive_all(phrase(), ZeckNetwork::Mainnet, GapLimits::uniform(2))
                .unwrap();
        let test =
            ZcashdPhraseKeySource::derive_all(phrase(), ZeckNetwork::Testnet, GapLimits::uniform(2))
                .unwrap();
        assert_ne!(main.fingerprint().unwrap(), test.fingerprint().unwrap());
    }

    /// `describe` reaches logs and the resume UI.
    #[test]
    fn describe_never_leaks_the_phrase() {
        let source =
            ZcashdPhraseKeySource::derive_all(phrase(), ZeckNetwork::Mainnet, GapLimits::uniform(2))
                .unwrap();
        let described = source.describe();
        for word in SEED.split_whitespace() {
            assert!(
                !described.contains(word),
                "describe() leaked a phrase word: {word}"
            );
        }
    }

    /// The limits statement is the user's only signal that an empty
    /// result may mean "not visible from a phrase" rather than "not
    /// there". It must keep naming each category explicitly.
    #[test]
    fn the_limits_statement_names_every_category_it_must() {
        for needle in [
            "Sprout",
            "z_importkey",
            "importprivkey",
            "watch-only",
            "wallet.dat",
        ] {
            assert!(
                PHRASE_CANNOT_RECOVER.contains(needle),
                "the limits statement must mention {needle}"
            );
        }
    }

    #[test]
    fn an_invalid_phrase_is_rejected_by_both_seed_routes() {
        let bad = SecretString::new("not a valid bip39 mnemonic at all".to_owned());
        assert!(bip39_seed(&bad).is_err());
        assert!(legacy_entropy_seed(&bad).is_err());
    }

    /// A rejected phrase must not echo the phrase back. Argos redacts
    /// mnemonic errors elsewhere for this reason; the entropy route is a
    /// second path to the same failure and must redact too.
    #[test]
    fn a_rejected_phrase_does_not_appear_in_the_error() {
        let bad = SecretString::new(
            "zebra zebra zebra zebra zebra zebra zebra zebra zebra zebra zebra zebra".to_owned(),
        );
        // Deliberately not `unwrap_err()`: that needs `Debug` on the Ok
        // type, and `Secret<Vec<u8>>` does not implement it — `secrecy`
        // is refusing to let a recovered seed reach a panic message. The
        // compiler enforcing that is the property this module wants, so
        // the test matches rather than defeating it.
        let err = match legacy_entropy_seed(&bad) {
            Ok(_) => panic!("an invalid phrase must be rejected"),
            Err(err) => err.to_string(),
        };
        assert!(!err.contains("zebra"), "error leaked phrase material: {err}");
    }
}
