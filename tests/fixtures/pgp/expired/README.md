# Expired-key PGP fixture

Files:

- `keyring.asc` — RSA-2048 public key `2DBD4CAB72E1092E46B1C6AFFA21CDCF696569E0`,
  `Tain Expired Test Key <expired@tain.test>`. Created 2020-01-01, expired 2020-01-02.
- `body.txt` — small deb822-style payload signed by that key.
- `InRelease` — clearsigned `body.txt` under the expired key.
- `Release.gpg` — armored detached signature over `body.txt` under the expired key.

## Reproducing

Requires GnuPG with `--faked-system-time` support (GnuPG 2.x).

```bash
GNUPGHOME=$(mktemp -d) && export GNUPGHOME
cat > "$GNUPGHOME/keygen" <<'EOF'
%no-protection
Key-Type: RSA
Key-Length: 2048
Name-Real: Tain Expired Test Key
Name-Email: expired@tain.test
Expire-Date: 1d
%commit
EOF
gpg --batch --faked-system-time '20200101T000000!' --gen-key "$GNUPGHOME/keygen"
gpg --armor --export expired@tain.test > keyring.asc
gpg --batch --faked-system-time '20200101T000000!' --clearsign --output InRelease body.txt
gpg --batch --faked-system-time '20200101T000000!' --detach-sign --armor --output Release.gpg body.txt
```

The signature itself is valid at signing time; verification today rejects because
the key expired 2020-01-02.
