#!/usr/bin/env bash
# Generate a golden fixture for phrase-only zcashd recovery.
#
# Unlike `generate.sh`, which captures `wallet.dat` files, this captures the
# *other* half of a zcashd wallet: the emergency recovery phrase, and the
# legacy addresses zcashd derived from it. That pairing is the fixture —
# given the phrase alone, Argos must reproduce every one of those addresses.
#
# Run with:
#     docker compose --profile fixtures up zcashd-phrase-fixtures
#
# ## Why the phrase is not fixed
#
# zcashd has no `-mnemonic` option: it generates the phrase itself and will
# not accept one. So the fixture cannot pin a chosen phrase — it records
# whichever phrase zcashd produced, and that becomes the constant once this
# file is committed.
#
# That is better than a pinned phrase would have been. The BIP-39 test vector
# used elsewhere in Argos (`abandon abandon … art`) encodes all-zero entropy,
# so the pre-4.7 derivation path — which uses the phrase's *entropy* as the
# seed — would derive from a zero seed and could pass for the wrong reason.
# A zcashd-generated phrase carries real entropy.
#
# ## What is captured
#
# The whole `z_exportwallet` dump, verbatim. It carries, in one file:
#
#   * `# - recovery_phrase="…"` — the emergency recovery phrase
#   * every legacy transparent key, with `addr=` and
#     `hdkeypath=m/44'/1'/2147483647'/change/index`
#   * every legacy Sapling key, with `addr=` and its `hdkeypath`
#
# `2147483647` is `0x7FFFFFFF` — zcashd's `ZCASH_LEGACY_ACCOUNT`. The paths
# in this file are therefore the specification, written by the producer,
# rather than a transcription of its source.
#
# The dump contains spending keys. That is fine and deliberate: this is a
# regtest chain that exists for eight seconds and holds no value, exactly as
# the `wallet.dat` goldens next to it do.
set -euo pipefail

OUT=/fixtures
NAME=zcashd-phrase-regtest
DATADIR=/tmp/zc-phrase

# How many of each address type to assign. Enough that a fixture address
# sits at a non-zero child index — recovering only index 0 would pass
# against a wallet that never generated a second address, which is not the
# case this fixture exists to cover.
SAPLING_COUNT=8
TRANSPARENT_COUNT=8

rm -rf "$DATADIR"
mkdir -p "$DATADIR/export" "$OUT"

# Consensus branch IDs, verified against zcash/zcash v6.20.0
# src/consensus/upgrades.cpp. Everything is activated at height 1: unlike
# the Sprout goldens, nothing here needs Canopy held back.
#
# `walletrequirebackup=false` is required. zcashd otherwise refuses to
# derive any spending key until the emergency phrase has been confirmed
# through `zcashd-wallet-tool`, which is interactive and cannot be scripted.
cat > "$DATADIR/zcash.conf" <<'EOF'
i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025=1
allowdeprecated=getnewaddress
allowdeprecated=getrawchangeaddress
allowdeprecated=z_getnewaddress
allowdeprecated=z_getbalance
allowdeprecated=z_gettotalbalance
allowdeprecated=z_listaddresses
allowdeprecated=legacy_privacy
regtest=1
nuparams=5ba81b19:1
nuparams=76b809bb:1
nuparams=2bb40e60:1
nuparams=f5b9230b:1
nuparams=e9ff75a6:1
rpcuser=fixture
rpcpassword=fixture
walletrequirebackup=false
exportdir=/tmp/zc-phrase/export
EOF

cli() { zcash-cli -datadir="$DATADIR" "$@"; }

echo "starting zcashd"
zcashd -datadir="$DATADIR" -daemon
up=no
for _ in $(seq 1 120); do
  if cli getblockcount >/dev/null 2>&1; then up=yes; break; fi
  sleep 1
done
if [ "$up" != yes ]; then
  echo "FATAL: zcashd did not come up within 120s" >&2
  tail -40 "$DATADIR/regtest/debug.log" 2>/dev/null || true
  exit 1
fi

# Address generation is blocked during initial block download, so leave it.
cli generate 3 >/dev/null

echo "assigning $SAPLING_COUNT legacy Sapling addresses"
for _ in $(seq 1 "$SAPLING_COUNT"); do cli z_getnewaddress sapling >/dev/null; done

echo "assigning $TRANSPARENT_COUNT legacy transparent addresses"
for _ in $(seq 1 "$TRANSPARENT_COUNT"); do cli getnewaddress >/dev/null; done

echo "exporting wallet"
# z_exportwallet rejects anything but alphanumerics in the filename
# ("Filename is invalid as only alphanumeric characters are allowed"), so
# the export is written under a flattened name and renamed on the way out.
EXPORT_NAME=zcashdphraseregtest
cli z_exportwallet "$EXPORT_NAME" >/dev/null

EXPORT="$DATADIR/export/$EXPORT_NAME"
if [ ! -s "$EXPORT" ]; then
  echo "FATAL: z_exportwallet produced nothing" >&2
  exit 1
fi

# Refuse to ship a fixture that does not contain the one thing it exists
# for. A dump with no phrase line would make the downstream test silently
# assert nothing.
if ! grep -q 'recovery_phrase="' "$EXPORT"; then
  echo "FATAL: the export carries no recovery_phrase line; refusing to write" >&2
  echo "a fixture the phrase-recovery test cannot use." >&2
  exit 1
fi

# Likewise the legacy account marker: if zcashd ever stopped deriving at
# 0x7FFFFFFF, this fixture would encode the new behaviour and the test
# would happily confirm Argos matched it, hiding the change.
if ! grep -q "hdkeypath=m/44'/1'/2147483647'/" "$EXPORT"; then
  echo "FATAL: no transparent key was derived at the legacy account" >&2
  echo "(m/44'/1'/2147483647'/...); refusing to write the fixture." >&2
  exit 1
fi

cli stop >/dev/null 2>&1 || true
for _ in $(seq 1 30); do
  cli getblockcount >/dev/null 2>&1 || break
  sleep 1
done

cp "$EXPORT" "$OUT/$NAME.export"
echo "wrote $OUT/$NAME.export"

echo
echo "phrase: $(grep -o 'recovery_phrase="[^"]*"' "$OUT/$NAME.export")"
echo "sapling keys:     $(grep -c "m/32'/1'/2147483647'" "$OUT/$NAME.export" || true)"
echo "transparent keys: $(grep -c "hdkeypath=m/44'/1'/2147483647'" "$OUT/$NAME.export" || true)"
echo "fixture generation complete"
