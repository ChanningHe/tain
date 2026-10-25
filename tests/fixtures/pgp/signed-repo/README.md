# Signed-repo PGP fixture

A complete one-package APT repo (`bookworm`, `main`, `amd64`) signed by a
throwaway non-expiring RSA-2048 key, `Tain Signed Repo Test Key
<signed-repo@tain.test>`. Used by `tests/metadata_integrity.rs` for
end-to-end `verify.pgp` runs (sibling vetting, if-present downgrade).

- `keyring.asc` — the public key (the secret key was discarded).
- `dists/bookworm/{Release,InRelease,Release.gpg}` — `InRelease` is
  `gpg --clearsign Release`, `Release.gpg` is `gpg --detach-sign --armor Release`.
- `dists/bookworm/main/binary-amd64/Packages`, `pool/main/h/hello/…` — content
  the Release checksums cover.
- `next/{Release,InRelease,Release.gpg}` — the same suite one day later
  (`Date: Sun, 04 Feb 2024 09:15:38 UTC`, same Packages), signed by the same
  key: a second upstream generation. Not served by default.

## Reproducing

```bash
GNUPGHOME=$(mktemp -d) && export GNUPGHOME
cat > "$GNUPGHOME/keygen" <<'EOF'
%no-protection
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign
Name-Real: Tain Signed Repo Test Key
Name-Email: signed-repo@tain.test
Expire-Date: 0
%commit
EOF
gpg --batch --gen-key "$GNUPGHOME/keygen"
gpg --armor --export signed-repo@tain.test > keyring.asc
for DIR in dists/bookworm next; do
  gpg --batch --digest-algo SHA256 --clearsign --output "$DIR/InRelease" "$DIR/Release"
  gpg --batch --digest-algo SHA256 --detach-sign --armor --output "$DIR/Release.gpg" "$DIR/Release"
done
```

(`next/Release` is `dists/bookworm/Release` with the later `Date`.)

Regenerating changes the key, so the whole directory must be replaced together.
