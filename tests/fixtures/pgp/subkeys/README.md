# Subkey / digest PGP fixtures

Keys (minted with `--faked-system-time 2024-01-01`):

- **A** — `Tain Subkey Test <subkey@tain.test>`: ed25519 certify-only primary
  plus an RSA-2048 signing subkey **S** with a genuine binding signature
  (and embedded back-signature).
- **B** — `Tain Rogue Key <rogue@tain.test>`: unrelated ed25519 signing key.
- **C** — `Tain Revoked Primary <revoked@tain.test>`: ed25519 signing primary,
  revoked after signing.
- **D** — `Tain Late Key <late@tain.test>`: ed25519 signing primary created
  2024-01-02.

Files:

- `body.txt` — payload every signature covers.
- `keyring.asc` — A + S.
- `trust.gpg` — A + S in a legacy (pre-keybox) binary keyring, which carries
  GnuPG trust packets (tag 12) like `ubuntu-archive-keyring.gpg`.
- `revoked-primary.asc` / `revoked-primary.sig` — C with its revocation; a
  signature by C made before the revocation.
- `late.asc` / `early.sig` — D; a signature by D dated 2024-01-01, before D existed
  (made with `--ignore-time-conflict`).
- `dual.sig` / `dual.sig.bin` — one detached signature (armored / binary) with two
  signature packets, by keys E1 then E2 (`Tain Dual One/Two`), like
  security.debian.org's `Release.gpg`; `dual-second.asc` holds only E2.
- `concat.asc` — `keyring.asc` followed by a second armor block holding B.
- `concat.sig` — `rogue.sig` followed by `good.sig` as a second armor block.
- `revoked.asc` — A + S, with S revoked on 2024-01-02.
- `forged.gpg` — A's primary, user ID and self-signature, then B's key packet
  re-tagged as a subkey, followed by S's binding signature (which does not cover B).
  A verifier that trusts subkeys without checking their binding accepts `rogue.sig`.
- `good.sig` — detached signature by S (SHA-256).
- `md5.sig`, `sha1.sig`, `ripemd160.sig` — detached signatures by S with weak digests.
- `rogue.sig` — detached signature by B.

## Expected results

| keyring       | signature              | result                          |
|---------------|------------------------|---------------------------------|
| `keyring.asc` | `good.sig`             | verified                        |
| `trust.gpg`   | `good.sig`             | verified                        |
| `revoked-primary.asc` | `revoked-primary.sig` | rejected (`REVKEYSIG`)   |
| `late.asc`    | `early.sig`            | rejected (key newer than sig)   |
| `dual-second.asc` | `dual.sig[.bin]`   | verified (second packet)        |
| `keyring.asc` | `dual.sig[.bin]`       | rejected                        |
| `concat.asc`  | `rogue.sig`            | verified (key in 2nd block)     |
| `keyring.asc` | `concat.sig`           | verified (sig in 2nd block)     |
| `keyring.asc` | `md5/sha1/ripemd160`   | rejected (weak digest, as apt)  |
| `keyring.asc` | `rogue.sig`            | rejected                        |
| `revoked.asc` | `good.sig`             | rejected (apt: `REVKEYSIG`)     |
| `forged.gpg`  | `rogue.sig`            | rejected (`gpgv` agrees)        |

## Reproducing

```bash
nix shell nixpkgs#gnupg -c ./regen.sh
```

`regen.sh` mints fresh keys each run, so every file changes together.
