# Configuration reference

This page documents every configuration key that `tain` 0.1.1 understands.
Run `tain check` at any time to see the fully resolved configuration (all
defaults filled in, all environment overrides applied). It makes no
network requests and writes nothing.

- [Configuration sources](#configuration-sources)
- [Value formats](#value-formats)
- [TOML file](#toml-file)
  - [`[global]`](#global)
  - [`[global.retry]`](#globalretry)
  - [`[defaults]`](#defaults)
  - [`[[mirror]]`](#mirror)
  - [`[mirror.indexes]`](#mirrorindexes)
  - [`[mirror.verify]`](#mirrorverify)
  - [`[mirror.gc]`](#mirrorgc)
  - [Not supported: flat repositories](#not-supported-flat-repositories)
  - [Complete example](#complete-example)
- [Environment variables](#environment-variables)
  - [Global overrides](#global-overrides)
  - [Single-mirror mode](#single-mirror-mode)
  - [`TAIN_DISTS` syntax](#tain_dists-syntax)
  - [`TAIN_INDEXES` syntax](#tain_indexes-syntax)
- [Security behaviour](#security-behaviour)
- [Logging](#logging)
- [Importing a `mirror.list`](#importing-a-mirrorlist)
- [On-disk layout](#on-disk-layout)
- [Exit codes](#exit-codes)

## Configuration sources

`tain` builds one configuration from exactly one primary source, then
applies environment overrides on top. The primary source is the first of
these that applies:

1. `--config <path>` on the command line.
2. `TAIN_CONFIG=<path>` in the environment.
3. `/etc/tain/config.toml`, if that file exists.
4. Single-mirror mode, if `TAIN_URL` is set (see [below](#single-mirror-mode)).
5. Otherwise `tain` exits with code 2.

A path given through `--config` or `TAIN_CONFIG` is always used: if the file
cannot be read, `tain` fails (exit 4) instead of falling through to the next
source.

After the primary source is loaded, the [global override](#global-overrides)
variables (`TAIN_TARGET`, `TAIN_PARALLEL`, `TAIN_SCHEDULE`, ...) replace the
corresponding `[global]` values. This holds in both TOML and single-mirror
mode. Mirror-level variables (`TAIN_GC`, `TAIN_VERIFY_PGP`, `TAIN_INDEXES`,
...) are only read in single-mirror mode and are ignored when a TOML file
is in use.

Only `TAIN_*` variables are read. `RUST_LOG` is not consulted. Some
variable names from older mirror scripts (`APTSYNC_URL`, `APTSYNC_DISTS`,
`APTSYNC_UNLINK`, `APTSYNC_USER_AGENT`, `TO`, `CRON`, `PARALLEL_DOWNLOADS`)
are detected and produce a warning naming the `TAIN_*` replacement; they
have no effect. `TAIN_LOG_FILE` is not supported either (logs always go to
stderr); setting it only produces a warning.

`tain daemon` re-reads the configuration from the same source on `SIGHUP`.
If the new configuration fails to load, has no valid `schedule` or defines
no mirrors, the daemon logs a warning and keeps running with the previous
one.

Loading validates the whole configuration, including the backend's rules
(at least one component, safe suite names, `pgp = "required"` only in a
build with signature support). Every command except `import` runs this
validation; a failure exits 2. `tain check` also validates `schedule`. It does not
read keyring files (a missing or unreadable keyring fails the suite at
sync time) and accepts a configuration with no mirrors, which every other
command rejects with exit code 2.

## Value formats

| Kind | Format | Examples |
|---|---|---|
| Duration | [humantime](https://docs.rs/humantime) syntax | `"30s"`, `"72h"`, `"1h 30m"`, `"3d"` |
| Size | number of bytes, or a string with a unit | `268435456`, `"256MiB"`, `"1GiB"` |
| Ratio | float in `0.0..=1.0` | `0.3` |
| Cron | five-field cron expression | `"0 2,8,14,20 * * *"` |

Cron schedules are evaluated in the system's local time zone. In the
container image this is UTC unless you set `TZ` (the image ships tzdata).

## TOML file

The file has the tables below. Unknown keys are rejected, so a typo
fails `tain check` instead of being silently ignored.

```toml
[global]          # process-wide settings
[global.retry]    # retry budgets
[defaults]        # values inherited by every [[mirror]]
[[mirror]]        # one per upstream repository (repeat as needed)
[mirror.indexes]  # which index families to mirror
[mirror.verify]   # signature and checksum policy
[mirror.gc]       # garbage collection
```

For every mirror-level key, the precedence is: value in the `[[mirror]]`
block, then `[defaults]`, then the built-in default.

### `[global]`

| Key | Type | Default | Description |
|---|---|---|---|
| `target` | absolute path | `"/data"` | Root directory. Each mirror lives in `<target>/<mirror.path>`. An empty or relative value is rejected. |
| `parallel` | integer > 0 | `32` | Maximum concurrent requests across all mirrors in a run. |
| `host_connections` | integer > 0 | `8` | Maximum concurrent requests to one upstream host. Mirrors that share a host share this budget. On HTTP 429/503 the host's limit is halved and the host is paused for `Retry-After` (at most 300 s; 30 s if absent). |
| `connect_timeout` | duration > 0 | `"30s"` | Connect timeout for upstream connections. There is no whole-request timeout. |
| `idle_timeout` | duration > 0 | `"60s"` | Longest wait for response headers and for each body read; a download that receives no bytes for this long is aborted. Also the idle timeout for pooled HTTP connections. See [Stalled and slow transfers](#stalled-and-slow-transfers). |
| `bind_address` | IP address | unset | Local source address for outgoing connections. |
| `user_agent` | string | `"tain/<version>"` | HTTP `User-Agent`. |
| `schedule` | cron | unset | Sync schedule for `tain daemon`. Required by `daemon`; ignored by `sync`. Validated by `check` and when the daemon starts or reloads; an expression that never fires, such as `"0 0 30 2 *"`, is rejected. |
| `lock_timeout` | duration | `"0s"` | How long `sync` waits for another process holding a mirror's lock. `0s` fails immediately. |
| `segment_min_size` | size | `"256MiB"` | Files at least this large are fetched with parallel range requests when the upstream supports `Range`; smaller files use one request. TOML only. |
| `segments_per_file` | integer `1`..`8` | `4` | Number of parallel range requests for such a file; a value outside `1`..`8` is rejected (exit code 2). Each range is at least 32 MiB, so a file gets fewer ranges if it is too small for this many. |
| `log_level` | string | `"info"` | Log level or filter, see [Logging](#logging). |
| `log_format` | `"text"` \| `"json"` | `"text"` | Log format, see [Logging](#logging). |

Pool and index files are currently downloaded one at a time, so
`parallel` and `host_connections` only limit the parallel range requests
of a segmented download (`segment_min_size`, `segments_per_file`). They
will also bound concurrent pool downloads once those exist.

### `[global.retry]`

| Key | Type | Default | Description |
|---|---|---|---|
| `count` | integer | `3` | Retries per file (so up to `count + 1` attempts), for `InRelease`/`Release`/`Release.gpg`, indexes and pool files. Retried: connection and other transport errors, stalls and slow transfers, body read errors, size or checksum mismatches, HTTP 408, 429 and 5xx. Not retried: other 4xx answers, rejected TLS certificates and refused redirects. See below. |
| `index_rounds` | integer | `5` | How many times a suite's metadata phase is restarted when the upstream `InRelease`/`Release` changes mid-sync. When exhausted, the suite fails and the published copy is left untouched. |

Between attempts `tain` waits a random time between 0 and
`min(30 s, 1 s × 2^(attempt-1))` (full-jitter backoff). On 429 and 503 it
waits for the host's `Retry-After` instead (at most 300 s, 30 s if the
header is absent). A
file that still fails after the last retry fails its suite for this run;
the next run starts the suite again, reusing pool files already
downloaded.

### `[defaults]`

`[defaults]` accepts the mirror-level keys that make sense to share. Each
mirror inherits any key it does not set itself.

| Key | Notes |
|---|---|
| `backend` | see `[[mirror]]` |
| `path` | Rarely useful: mirrors must not share a directory, so this is rejected as soon as two mirrors inherit it. |
| `architectures` | |
| `components` | |
| `create_suite_symlinks` | |
| `indexes` | table, same keys as `[mirror.indexes]` |
| `verify` | table, same keys as `[mirror.verify]` |
| `gc` | table, same keys as `[mirror.gc]` |

`name`, `url`, `suites` and `force_http1` cannot be set in `[defaults]`.

Inline tables are convenient here:

```toml
[defaults]
architectures = ["amd64", "arm64"]
gc = { enabled = true, grace_period = "72h" }
```

### `[[mirror]]`

| Key | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Unique identifier, used in logs, metrics, `--mirror` filters and as the default `path` (so it must then follow the `path` rules). |
| `url` | URL | required | Repository root, i.e. the URL a client would put in `sources.list` (`https://deb.debian.org/debian`). Must be `http` or `https`. |
| `backend` | `"apt"` | `"apt"` | Repository format. `apt` is the only backend. |
| `path` | path | `name` | Directory under `global.target`. Must be relative, must not contain `..` and must not be empty or `.`. Two mirrors may not use the same directory, and one mirror's directory may not lie inside another's (`debian` and `debian/pve` conflict; `debian` and `debian-security` do not). |
| `suites` | list of strings | required | Suites to mirror, e.g. `["trixie", "trixie-updates"]`. Slash suites such as `"stable/updates"` work. Flat repositories are [not supported](#not-supported-flat-repositories). Must not be empty. |
| `components` | list of strings | `[]` | Components, e.g. `["main", "contrib"]`. Set at least one; an empty list is rejected when the configuration is loaded. |
| `architectures` | list of strings | required | Binary architectures, e.g. `["amd64", "arm64"]`. Architecture `all` is included implicitly. Must not be empty. |
| `create_suite_symlinks` | bool | `true` | Create the `dists/<Suite>` to `dists/<Codename>` symlink (for example `stable -> trixie`) when the Release file names both. |
| `force_http1` | bool | `false` | Use HTTP/1.1 only for this mirror. By default HTTP/2 is negotiated when the server offers it. Not available in `[defaults]`. |

### `[mirror.indexes]`

`Packages` indexes for the configured components and architectures are
always mirrored and cannot be disabled (there is no `packages` key). The
other families are selected here.

| Key | Type | Default | Description |
|---|---|---|---|
| `contents` | bool | `true` | `Contents-<arch>` files. |
| `i18n` | bool or list | `true` | `Translation-<lang>` files. `true`: all languages; `false`: none; a list such as `["en", "zh_CN"]`: only those. Language tags are matched case-insensitively against the upstream file names (Debian ships `Translation-zh_CN`, `Translation-pt_BR`, ...). |
| `dep11` | bool | `true` | AppStream (`dep11/`) metadata. |
| `cnf` | bool | `true` | command-not-found (`cnf/`) metadata. |
| `sources` | bool | `false` | `Sources` indexes and the source packages they reference. |
| `debian_installer` | bool | `false` | debian-installer `Packages` (udebs) and the `installer-<arch>/` image trees. Image files are verified against the upstream `SHA256SUMS`, and the `current` symlink is rebuilt after publish. |

PDiffs (`*.diff/Index`) are not mirrored; apt clients fall back to the full
index.

### `[mirror.verify]`

| Key | Type | Default | Description |
|---|---|---|---|
| `pgp` | `"off"` \| `"if-present"` \| `"required"` | `"off"` | OpenPGP check of `InRelease`, or of `Release` + `Release.gpg`. `off`: never check. `if-present`: check when a signature exists, a bad signature fails the suite; see [Signatures](#signatures) for the downgrade rule. `required`: a missing or bad signature fails the suite. |
| `keyring` | path | unset | Keyring holding the upstream signing keys: binary (`.gpg`), ASCII-armored (`.asc`), or several armored blocks concatenated (`cat a.asc b.asc`). Required whenever `pgp` is not `off`; without it the configuration is rejected (exit code 2). The file itself is read at sync time; a missing or unreadable keyring fails the suite. An empty string counts as unset, so a mirror with `keyring = ""` inherits the `[defaults]` keyring. |
| `allow_weak_hash` | bool | `false` | Accept index entries that carry only MD5 or SHA-1 checksums. When `false`, a `Packages` or `Sources` entry with only weak checksums fails the suite, and the error names the index and some of the entries; `Release` entries with only weak checksums are dropped with a warning. |

`pgp = "required"` needs a build with the `pgp` cargo feature (on by
default, and in all release artifacts). In a build without it, such a
configuration is rejected when it is loaded (exit code 2).

A failed check fails that suite only. The previously published copy of
the suite stays in place. [Security behaviour](#security-behaviour)
lists every check.

### `[mirror.gc]`

Garbage collection removes files that no recent generation references
any more. It runs at the end of a sync in which every suite was updated
or unchanged; a sync in which every suite was unchanged still runs it.
It is skipped when:

- any suite of the mirror failed in this run, or
- the manifest does not record the files of every published suite.

A published suite whose files the newest manifest does not record is
fully re-synced (every pool file re-hashed, missing ones downloaded) so
they are recorded. This happens to every suite once, on the first run
after upgrading from 0.1.0.

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Actually delete files. When `false`, GC still computes and logs its candidates but deletes nothing. |
| `grace_period` | duration | `"72h"` | Unreferenced files younger than this (by mtime) are kept. |
| `max_delete_ratio` | ratio | `0.3` | Circuit breaker: if the candidates exceed this fraction of the scanned files, or of the scanned bytes, GC deletes nothing and logs the full candidate list. Protects against an upstream that suddenly publishes empty indexes. |
| `keep_generations` | integer | `3` | Number of recent generations whose files are kept (`0` acts as `1`). Older generation manifests are deleted after every sync that writes a new one, whether or not GC is enabled. GC also keeps the newest `keep_generations` previous copies of each suite's `dists/` tree under `.tain/prev/<suite>/`. |
| `dry_run` | bool | `false` | Log candidates without deleting, even if `enabled = true`. |

GC is also forced into dry-run mode by `tain sync --gc-dry-run`, by
`tain sync --dry-run`, and on the first sync into a directory that already
contains files but has no `tain` state (for example an existing mirror being
taken over). Run `tain verify` after such a takeover before relying on GC.

### Not supported: flat repositories

A flat repository has its `Release` and `Packages` files in a plain
directory instead of under `dists/` (`deb https://example.com/apt ./` or
`deb https://example.com/apt stable/` in `sources.list`). `tain` cannot
mirror them. Following apt's rule, any suite that is `"."` or ends in `/` (such as
`"./"`, `"stable/"` or `"<dir>/./"`) is a flat repository and is rejected
when the configuration is loaded (exit code 2), in TOML and in
`TAIN_DISTS`, also when the mirror lists other suites. `tain import mirrors-list` comments
such lines out instead of converting them.

### Complete example

```toml
[global]
target = "/srv/mirrors"
parallel = 32
host_connections = 8
schedule = "0 2,8,14,20 * * *"   # used by `tain daemon` only

[global.retry]
count = 3

[defaults]
architectures = ["amd64", "arm64"]
gc = { enabled = true, grace_period = "72h", max_delete_ratio = 0.3 }

[[mirror]]
name = "debian"
url = "https://deb.debian.org/debian"
suites = ["trixie", "trixie-updates", "trixie-backports"]
components = ["main", "contrib", "non-free", "non-free-firmware"]

[mirror.indexes]
i18n = ["en"]
debian_installer = true

[mirror.verify]
pgp = "required"
keyring = "/usr/share/keyrings/debian-archive-keyring.gpg"

[[mirror]]
name = "debian-security"
url = "https://security.debian.org/debian-security"
suites = ["trixie-security"]
components = ["main", "contrib", "non-free", "non-free-firmware"]

[mirror.indexes]
i18n = ["en"]

[mirror.verify]
pgp = "required"
keyring = "/usr/share/keyrings/debian-archive-keyring.gpg"

[[mirror]]
name = "proxmox"
url = "http://download.proxmox.com/debian/pve"
suites = ["trixie"]
components = ["pve-no-subscription"]
architectures = ["amd64"]
force_http1 = true
```

With this file, Debian lands in `/srv/mirrors/debian`, and a client uses
`deb http://<your-host>/debian trixie main` if `/srv/mirrors` is served
over HTTP.

## Environment variables

### Global overrides

These apply in both TOML and single-mirror mode and replace the matching
`[global]` value.

| Variable | Overrides | Notes |
|---|---|---|
| `TAIN_CONFIG` | | Path to the TOML file. Same as `--config`, which wins if both are set. |
| `TAIN_TARGET` | `target` | |
| `TAIN_PARALLEL` | `parallel` | integer > 0 |
| `TAIN_HOST_CONNECTIONS` | `host_connections` | integer > 0 |
| `TAIN_SEGMENTS` | `segments_per_file` | integer `1`..`8` |
| `TAIN_CONNECT_TIMEOUT` | `connect_timeout` | duration > 0 |
| `TAIN_IDLE_TIMEOUT` | `idle_timeout` | duration > 0 |
| `TAIN_RETRY` | `retry.count` | |
| `TAIN_INDEX_RETRY` | `retry.index_rounds` | |
| `TAIN_BIND_ADDRESS` | `bind_address` | |
| `TAIN_USER_AGENT` | `user_agent` | |
| `TAIN_SCHEDULE` | `schedule` | cron |
| `TAIN_LOCK_TIMEOUT` | `lock_timeout` | duration |
| `TAIN_LOG_LEVEL` | `log_level` | see [Logging](#logging) |
| `TAIN_LOG_FORMAT` | `log_format` | `text` or `json`, see [Logging](#logging) |

There is no variable for `segment_min_size`.

### Single-mirror mode

When no TOML file is found and `TAIN_URL` is set, `tain` builds its mirrors
from the environment. This is meant for one-container-per-upstream
deployments. The backend is always `apt`.

| Variable | Required | Default | Description |
|---|---|---|---|
| `TAIN_URL` | yes | | Repository root URL. |
| `TAIN_DISTS` | yes | | Suites, components and architectures, see [syntax](#tain_dists-syntax). |
| `TAIN_PATH` | no | derived | Directory under `TAIN_TARGET`. Only allowed when `TAIN_DISTS` has a single group. |
| `TAIN_INDEXES` | no | `default` | Index selection, see [syntax](#tain_indexes-syntax). |
| `TAIN_VERIFY_PGP` | no | `off` | `off`, `if-present` or `required`. |
| `TAIN_KEYRING` | if `TAIN_VERIFY_PGP` is not `off` | | Keyring path, see `verify.keyring`. |
| `TAIN_GC` | no | `false` | `gc.enabled`. Accepts `1`/`true`/`yes`/`on` and `0`/`false`/`no`/`off`. |
| `TAIN_GC_GRACE` | no | `72h` | `gc.grace_period`. |
| `TAIN_GC_MAX_DELETE_RATIO` | no | `0.3` | `gc.max_delete_ratio`. |
| `TAIN_GC_KEEP_GENERATIONS` | no | `3` | `gc.keep_generations`. |

The mirror name is derived from the URL: host and path, lowercased, with
every character outside `[a-z0-9._-]` replaced by `-`. For
`http://download.proxmox.com/debian/pve` that is
`download.proxmox.com-debian-pve`. The directory defaults to the name, so
set `TAIN_PATH` for a shorter one. With several `TAIN_DISTS` groups, each
group becomes its own mirror named `<name>-0`, `<name>-1`, ... and its
directory comes from the group's fourth field, or defaults to that name.

`verify.allow_weak_hash`, `gc.dry_run`, `create_suite_symlinks` and
`force_http1` cannot be set in single-mirror mode; they keep their
defaults. Use a TOML file if you need them.

When a TOML file is in use, the variables in this table are ignored;
`tain` logs a warning naming the ones that are set.

### `TAIN_DISTS` syntax

```
TAIN_DISTS = <group>[;<group>...]
<group>    = <suites>|<components>|<architectures>[|<path>]
```

- Suites, components and architectures are comma-separated.
- Groups are separated by `;` or a newline.
- The optional fourth field is the local directory for that group. The
  upstream URL is always `TAIN_URL`.
- Flat repositories are [not supported](#not-supported-flat-repositories).

```sh
TAIN_DISTS='bookworm|main,contrib|amd64,arm64'
TAIN_DISTS='trixie,trixie-updates|main|amd64;bookworm|main|amd64|debian-old'
```

### `TAIN_INDEXES` syntax

A comma-separated list of tokens, applied left to right. `+name` and
`-name` switch one family on or off; a bare family name is the same as
`+name`. A family that no token sets keeps its default (the `default` row
below), so `+sources` alone equals `default,+sources`.

| Token | Effect |
|---|---|
| `default` | contents, i18n (all languages), dep11, cnf on. sources and debian-installer are left as an earlier token set them, and off if none did |
| `all` | every family on |
| `minimal` | every optional family off (only `Packages`) |
| `contents`, `i18n`, `dep11`, `cnf`, `sources`, `di` (or `debian_installer`) | family names for `+`/`-` |

Because `all` and `minimal` set every family, they override earlier
tokens; `default` does not touch sources or debian-installer, so
`+sources,default` keeps sources on.

```sh
TAIN_INDEXES='default,-contents'     # everything default except Contents
TAIN_INDEXES='minimal,+i18n'         # Packages and Translation only
TAIN_INDEXES='default,+sources,+di'  # default plus sources and debian-installer
TAIN_INDEXES='+sources'              # same as default,+sources
```

A language list for i18n is only available in TOML.

## Security behaviour

Every check below fails only the affected suite; its published copy stays
as it was.

### Signatures

With `verify.pgp` set to `if-present` or `required`:

- An `InRelease` that is not clearsigned is never used or published (apt
  rejects one). The suite is synced from `Release` + `Release.gpg`
  instead, as it is when `InRelease` is absent (a 4xx answer other than
  408 and 429).
- `if-present` is trust on first use: a suite whose upstream serves no
  signature is synced unsigned. Once a signed copy is published (a
  clearsigned `InRelease`, or a `Release.gpg` that verifies against the
  keyring), an upstream that serves no signature fails the suite
  (`PgpDowngrade`, possible signature stripping).
- Signatures made with MD5, SHA-1 or RIPEMD-160 digests are ignored. A
  file signed only that way fails the suite.
- A file with several signatures (such as a multi-key `Release.gpg`) is
  accepted if any one of them verifies; at most 32 are examined.
- A key or subkey is used only if it is not revoked, was valid when the
  signature was made and is valid now, and is allowed to sign. A subkey
  also needs a valid binding signature with a back-signature.
- In `InRelease` mode, upstream `Release` and `Release.gpg` are published
  next to it only if `Release` has the same content as the signed body of
  `InRelease` and `Release.gpg` verifies; otherwise they are left out.

### Release `Date`

The `Date` of a suite's published `Release` is a floor. An incoming
`Release` with an older `Date`, or with no `Date` once a floor exists,
fails the suite. The floor is taken from `.tain/state.json` and from the
published files themselves, so it survives a lost state file. Changing a
mirror's `url` discards its state but keeps the floor: to switch to an
upstream that lags behind the old one, remove `dists/<suite>` first. A
`Valid-Until` in the past only logs a warning.

### Checksums and sizes

Every index and pool file is checked against the size and checksums
listed for it before it is published; a mismatch is retried and then
fails the suite. Entries with only MD5 or SHA-1 checksums follow
`verify.allow_weak_hash`. `InRelease` and `Release` larger than 16 MiB,
or `Release.gpg` larger than 1 MiB, are refused. Package paths
(`Filename` in `Packages`/`Sources`, paths in installer `SHA256SUMS`) that
would leave the mirror directory or point into `.tain/` are refused. So are
paths that would overwrite verified metadata: any
`dists/<name>/InRelease`, `Release` or `Release.gpg`, a file listed in
the suite's `Release` unless both list the same SHA-256 (and size, when
given), as for the installer's `MD5SUMS`, any `by-hash` object
under `dists/`, a path below a suite alias symlink such as
`dists/stable`, or a file in
another configured suite's directory. Such an entry fails the suite
(`PoolPathConflict`, also reported by `--dry-run`); other files under the
suite's own directory, as some third-party repositories use, still sync.

### Network

- Redirects: at most 10 hops. A redirect from https to http is refused,
  as is a redirect to an internal IP literal (loopback, private,
  link-local, CGNAT and other non-public ranges) or a `localhost` name,
  unless the mirror URL itself is such a literal. Host names are not
  resolved for this check: a DNS name that resolves to an internal address
  is not blocked. For egress isolation use systemd `IPAddressDeny=`/
  `IPAddressAllow=` or a container network policy.
- TLS: certificates are verified against the system CA store
  (`SSL_CERT_FILE` and `SSL_CERT_DIR` are honoured) and the bundled
  Mozilla roots. A rejected certificate is not retried.

### Stalled and slow transfers

There is no whole-request timeout. Two watchdogs abort a transfer instead;
both count as a retryable failure (see `retry.count`):

- Idle: no response headers, or no body bytes, for `idle_timeout`.
- Rate floor (fixed, not configurable): after a 10 s start-up grace, each
  arriving chunk is judged against the last `H = 30 s + idle_timeout`.
  With the longest pause in `H` removed, the remaining time, if at least
  30 s, must average 10 KiB/s; and once a full `H` has elapsed, all of `H`
  must average `10 KiB/s × 30 s / H`. A transfer that keeps 10 KiB/s with
  at most one pause shorter than `idle_timeout` per `H` never trips; with
  the default `idle_timeout` no transfer is sustained below about
  3.3 KiB/s.

## Logging

Logs go to stderr. Two settings control them:

- `log_level` (`TAIN_LOG_LEVEL`): a level (`error`, `warn` or `warning`,
  `info`, `debug`, `trace`, `off`) or a comma-separated filter such as
  `info,tain::core=debug`. Levels are case-insensitive. A bare word that
  is not a level is rejected (exit 2), including a crate name: write
  `tain=debug`, not `tain`. Default `info`.
- `log_format` (`TAIN_LOG_FORMAT`): `text` (default) or `json`.

The environment variable wins over the `[global]` key, which wins over the
default. Both are read once at startup; `SIGHUP` does not change them.
Messages printed while the configuration file is being read use the
environment variables only. An invalid level or format is a configuration
error (exit code 2). To keep logs in a file, redirect stderr or let systemd
or Docker collect them.

## Importing a `mirror.list`

```sh
tain import mirrors-list /etc/apt/mirror.list > config.toml
tain --config config.toml check
```

The converter reads an apt-mirror `mirror.list` (`-` reads from
stdin) and prints TOML on stdout. It understands:

- `deb`, `deb-src` and `deb-<arch>` lines (`deb-amd64 URL SUITE COMP...`);
- an options bracket `[arch=amd64,arm64 signed-by=/path/key.gpg]`;
- `mirror_path <url-prefix> <dir>`, which becomes the mirror's `path`;
- `#` comments and blank lines.

Other directives, such as apt-mirror's `set` and `clean` lines, are
rejected with a line number; delete them first. Lines for the same URL
(a trailing `/` does not count) and keyring merge into one `[[mirror]]` with the union of their suites,
components and architectures (a line without an architecture contributes
`amd64`). A `deb-src` line joins the mirror of its URL, whatever its
options, and turns on `indexes.sources`. `signed-by=` becomes
`verify.pgp = "required"` with that keyring. If a mirror ends up with no
architecture, the output adds `[defaults] architectures = ["amd64"]`.

Mirror names come from the URL (see [single-mirror mode](#single-mirror-mode));
a name already taken gets the first free `-2`, `-3`, ... suffix.

A `mirror_path` prefix is compared with each mirror URL as a URL: scheme
and host ignore case, a default port equals no port, and the path must
match whole segments (`http://x/debian` covers `http://x/debian/sub` but
not `http://x/debian-security`; path case matters). The longest matching
prefix wins; when two lines name the same prefix, the later one wins.
Because `path` must be relative to `target`, an absolute or `..`
directory is not converted; neither is a directory already used by, or
overlapping, another mirror's. Every `mirror_path` line that is not
applied, including one that is the best match for no `deb` line, appears
as a `# mirror_path ... not applied: <reason>` comment (in the mirror's
block or under `[global]`) and as a warning on stderr; the mirror keeps
its default path.

Some lines cannot be converted: flat repositories (a suite that is `.` or
ends in `/`, such as `./` or `stable/`, [not supported](#not-supported-flat-repositories)),
URLs other than `http`/`https`, lines without components, suites that
would leave the mirror directory (such as `../../etc`), and control
characters in a suite, component or architecture. They are copied
into a comment block at the end of the output, grouped by reason, a
warning naming each line number goes to stderr, and the rest of the file
is converted as usual. In a build without OpenPGP support, `signed-by=`
becomes a comment instead of a `[mirror.verify]` block. The output always
passes `tain check`; still, read it before use.

## On-disk layout

```
<target>/<path>/            mirror root, serve this over HTTP
    dists/                  published suites (as upstream)
    pool/                   package files (as upstream)
    .tain/                  tain's own state, do not serve
        state.json          per-suite state (Release token, Date, generation)
        lock                per-mirror lock
        manifest/           generation manifests: every file of every suite
        staging/            work area for the sync in progress
        prev/<suite>/<gen>/ previous copies of a suite's dists/ tree, removed by GC
```

`staging/` sits inside the mirror root so that publishing a suite is a
rename on one filesystem. Exclude `.tain/` from your web server.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | At least one mirror or suite failed (`sync`); problems found (`verify`); a mirror is unhealthy or its state is unreadable (`status`). |
| 2 | Configuration error: no source, invalid TOML or environment value, `verify.pgp` without `verify.keyring`, a flat-repository suite, no components, an unsafe suite name, an empty or relative `target`, an invalid or overlapping mirror `path`, a non-http(s) `url`, `segments_per_file` outside `1`..`8`, invalid log level or format, missing, invalid or never-firing `schedule` (`check`, `daemon`), no mirrors configured (`sync`, `verify`, `status`, `daemon`), an unknown `--mirror` name, bad `--healthy-within`, unparseable `mirror.list`. |
| 3 | Lock contention: every selected mirror failed and at least one because another process held its lock (`sync`). |
| 4 | Fatal I/O: unreadable config file, unwritable target, disk full. |

For `tain sync`, 4 takes precedence over everything else, then 3, then 1.
With `--dry-run`, a failed suite is reported in the plan and does not make
the exit code 1.
`tain daemon` exits 0 after `SIGTERM`/`SIGINT`, and 2 if its schedule has
no next occurrence; failures of individual scheduled runs are logged and
do not stop the daemon. A `--metrics-file`
write failure is logged and never changes the exit code.
