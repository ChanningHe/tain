#!/usr/bin/env bash
# Regenerate the subkey fixtures. Run from this directory:
#   nix shell nixpkgs#gnupg -c ./regen.sh
set -euo pipefail
cd "$(dirname "$0")"

GNUPGHOME=$(mktemp -d)
export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT
T='20240101T000000!'
g() { gpg --batch --yes --quiet --faked-system-time "$T" --pinentry-mode loopback --passphrase '' "$@"; }
fpr_last() { gpg --list-keys --with-colons "$1" | awk -F: '/^fpr/{f=$10} END{print f}'; }

# A: certify-only primary + RSA signing subkey S. B: unrelated signing key.
g --quick-gen-key 'Tain Subkey Test <subkey@tain.test>' ed25519 cert never
A=$(fpr_last subkey@tain.test)
g --quick-add-key "$A" rsa2048 sign never
S=$(fpr_last subkey@tain.test)
g --quick-gen-key 'Tain Rogue Key <rogue@tain.test>' ed25519 sign never

printf 'Origin: Tain\nLabel: subkey fixture\n' > body.txt
gpg --armor --export subkey@tain.test > keyring.asc
g --local-user "$S!" --detach-sign --armor --output good.sig body.txt
g --local-user "$S!" --digest-algo SHA1 --detach-sign --armor --output sha1.sig body.txt
g --local-user "$S!" --digest-algo RIPEMD160 --detach-sign --armor --output ripemd160.sig body.txt
g --local-user "$S!" --digest-algo MD5 --detach-sign --armor --output md5.sig body.txt
g --local-user rogue@tain.test --detach-sign --armor --output rogue.sig body.txt

# forged.gpg: A's primary + user ID + self-sig, then B's primary key packet
# re-tagged as a subkey (tag 6 -> 14), then S's genuine binding signature,
# which does not cover B.
work=$(mktemp -d)
gpg --export subkey@tain.test > "$work/a.gpg"
gpg --export rogue@tain.test > "$work/b.gpg"
(cd "$work" && mkdir a b && (cd a && gpgsplit ../a.gpg) && (cd b && gpgsplit ../b.gpg))
a_pkts=("$work"/a/*)
b_key=$(ls "$work"/b/*-006.public_key)
ctb=$(od -An -tu1 -N1 "$b_key" | tr -d ' ')
if ((ctb & 0x40)); then new=$((ctb + 8)); else new=$((ctb + 32)); fi
printf "\\$(printf '%03o' "$new")" > "$work/subkey"
tail -c +2 "$b_key" >> "$work/subkey"
# a_pkts: public_key, user_id, signature, public_subkey, signature (binding).
cat "${a_pkts[0]}" "${a_pkts[1]}" "${a_pkts[2]}" "$work/subkey" "${a_pkts[4]}" > forged.gpg

# trust.gpg: A + S in a legacy (pre-keybox) keyring, which interleaves GnuPG
# trust packets (tag 12) the way ubuntu-archive-keyring.gpg does.
: > "$work/trust.gpg"
gpg --batch --quiet --no-default-keyring --keyring "$work/trust.gpg" --import keyring.asc
cp "$work/trust.gpg" trust.gpg
rm -rf "$work"

# C: sign-capable primary, revoked after signing (gpg's auto-made revocation cert).
g --quick-gen-key 'Tain Revoked Primary <revoked@tain.test>' ed25519 sign never
C=$(fpr_last revoked@tain.test)
g --local-user revoked@tain.test --detach-sign --armor --output revoked-primary.sig body.txt
sed 's/^:-----BEGIN/-----BEGIN/' "$GNUPGHOME/openpgp-revocs.d/$C.rev" | g --import
gpg --armor --export revoked@tain.test > revoked-primary.asc

# D: created 2024-01-02, signature dated 2024-01-01 (before the key existed).
T='20240102T000000!'
g --quick-gen-key 'Tain Late Key <late@tain.test>' ed25519 sign never
gpg --armor --export late@tain.test > late.asc
T='20240101T000000!'
g --ignore-time-conflict --local-user late@tain.test --detach-sign --armor --output early.sig body.txt

# E1 + E2: one detached signature block carrying two signature packets (E1
# first), like security.debian.org's Release.gpg; the keyring holds only E2.
g --quick-gen-key 'Tain Dual One <dual1@tain.test>' ed25519 sign never
g --quick-gen-key 'Tain Dual Two <dual2@tain.test>' ed25519 sign never
gpg --armor --export dual2@tain.test > dual-second.asc
g --local-user dual1@tain.test --local-user dual2@tain.test --detach-sign --armor --output dual.sig body.txt
g --local-user dual1@tain.test --local-user dual2@tain.test --detach-sign --output dual.sig.bin body.txt

# Concatenated armor blocks (`cat a.asc b.asc`): keys and detached signatures.
{ cat keyring.asc; gpg --armor --export rogue@tain.test; } > concat.asc
cat rogue.sig good.sig > concat.sig

# revoked.asc: A with S revoked after good.sig was made.
T='20240102T000000!'
printf 'key 1\nrevkey\ny\n0\n\ny\nsave\n' |
  gpg --batch --yes --faked-system-time "$T" --pinentry-mode loopback --passphrase '' \
    --command-fd 0 --edit-key "$A"
gpg --armor --export subkey@tain.test > revoked.asc
