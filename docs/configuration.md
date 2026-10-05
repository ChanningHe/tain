# Configuration reference

This page documents every configuration key that `tain` 0.1 understands.
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
- [Logging](#logging)
- [Importing an apt-mirror `mirror.list`](#importing-an-apt-mirror-mirrorlist)
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
If the new configuration fails to load, the daemon logs a warning and keeps
running with the previous one.

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

The file has four kinds of tables. Unknown keys are rejected, so a typo
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
| `target` | path | `"/data"` | Root directory. Each mirror lives in `<target>/<mirror.path>`. |
| `parallel` | integer > 0 | `32` | Maximum number of files downloaded at once, across all mirrors in a run. |
| `host_connections` | integer > 0 | `8` | Maximum concurrent requests to one upstream host. Mirrors that share a host share this budget. On HTTP 429/503 the per-host limit is reduced and `Retry-After` is honoured. |
| `connect_timeout` | duration > 0 | `"30s"` | Connect timeout for upstream connections. There is no whole-request timeout. |
| `idle_timeout` | duration > 0 | `"60s"` | Stall timeout: an index or package download that receives no bytes for this long is aborted. Also the idle timeout for pooled HTTP connections. |
| `bind_address` | IP address | unset | Local source address for outgoing connections. |
| `user_agent` | string | `"tain/<version>"` | HTTP `User-Agent`. |
| `schedule` | cron | unset | Sync schedule for `tain daemon`. Required by `daemon`; ignored by `sync`. The expression is only validated when the daemon starts. |
| `lock_timeout` | duration | `"0s"` | How long `sync` waits for another process holding a mirror's lock. `0s` fails immediately. |
| `segment_min_size` | size | `"256MiB"` | Files at least this large are fetched with parallel range requests when the upstream supports `Range`; smaller files use one request. TOML only. |
| `segments_per_file` | integer | `4` | Number of parallel range requests for such a file, at most 8. Each range is at least 32 MiB, so a file gets fewer ranges if it is too small for this many. |
| `log_level` | string | `"info"` | Log level or filter, see [Logging](#logging). |
| `log_format` | `"text"` \| `"json"` | `"text"` | Log format, see [Logging](#logging). |

### `[global.retry]`

| Key | Type | Default | Description |
|---|---|---|---|
| `count` | integer | `3` | Retries per pool file download when the upstream answers HTTP 429 or 503 (so up to `count + 1` attempts). Other failures (connection errors, other HTTP errors, stalls, hash mismatches) fail the suite for this run; the next run retries it, reusing files that were already downloaded. |
| `index_rounds` | integer | `5` | How many times a suite's metadata phase is restarted when the upstream `InRelease`/`Release` changes mid-sync. When exhausted, the suite fails and the published copy is left untouched. |

### `[defaults]`

`[defaults]` accepts the mirror-level keys that make sense to share. Each
mirror inherits any key it does not set itself.

| Key | Notes |
|---|---|
| `backend` | see `[[mirror]]` |
| `path` | Rarely useful: mirrors must not share a directory. |
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
| `name` | string | required | Unique identifier, used in logs, metrics, `--mirror` filters and as the default `path`. |
| `url` | URL | required | Repository root, i.e. the URL a client would put in `sources.list` (`https://deb.debian.org/debian`). |
| `backend` | `"apt"` | `"apt"` | Repository format. `apt` is the only backend in 0.1. |
| `path` | path | `name` | Directory under `global.target`. |
| `suites` | list of strings | required | Suites to mirror, e.g. `["trixie", "trixie-updates"]`. Slash suites such as `"stable/updates"` work. Flat repositories are [not supported](#not-supported-flat-repositories). Must not be empty. |
| `components` | list of strings | `[]` | Components, e.g. `["main", "contrib"]`. Set at least one. |
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
| `i18n` | bool or list | `true` | `Translation-<lang>` files. `true`: all languages; `false`: none; a list such as `["en", "zh_cn"]`: only those. Language tags are matched case-insensitively. |
| `dep11` | bool | `true` | AppStream (`dep11/`) metadata. |
| `cnf` | bool | `true` | command-not-found (`cnf/`) metadata. |
| `sources` | bool | `false` | `Sources` indexes and the source packages they reference. |
| `debian_installer` | bool | `false` | debian-installer `Packages` (udebs) and the `installer-<arch>/` image trees. Image files are verified against the upstream `SHA256SUMS`, and the `current` symlink is rebuilt after publish. |

PDiffs (`*.diff/Index`) are not mirrored; apt clients fall back to the full
index.

### `[mirror.verify]`

| Key | Type | Default | Description |
|---|---|---|---|
| `pgp` | `"off"` \| `"if-present"` \| `"required"` | `"off"` | OpenPGP check of `InRelease`, or of `Release` + `Release.gpg`. `off`: never check. `if-present`: check when a signature exists, a bad signature fails the suite. `required`: a missing or bad signature fails the suite. |
| `keyring` | path | unset | Keyring holding the upstream signing keys, binary (`.gpg`) or ASCII-armored (`.asc`). Required whenever `pgp` is not `off`; without it the configuration is rejected (exit code 2). An empty string counts as unset, so a mirror with `keyring = ""` inherits the `[defaults]` keyring. |
| `allow_weak_hash` | bool | `false` | Trust `Release`, `Packages` and `Sources` entries that carry only MD5 or SHA-1 checksums. By default such entries are skipped and their files are not downloaded; the upstream indexes are still published unchanged. |

`pgp = "required"` needs a build with the `pgp` cargo feature (on by
default, and in all release artifacts). In a build without it, a suite that
needs a signature check fails at sync time.

A failed signature check fails that suite only. The previously published
copy of the suite stays in place.

### `[mirror.gc]`

Garbage collection removes files that no published generation references
any more. It runs at the end of a sync, and only when no suite of the
mirror failed; a sync in which every suite was unchanged still runs it.

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Actually delete files. When `false`, GC still computes and logs its candidates but deletes nothing. |
| `grace_period` | duration | `"72h"` | Unreferenced files younger than this (by mtime) are kept. |
| `max_delete_ratio` | ratio | `0.3` | Circuit breaker: if the candidates exceed this fraction of the scanned files, or of the scanned bytes, GC deletes nothing and logs the full candidate list. Protects against an upstream that suddenly publishes empty indexes. |
| `keep_generations` | integer | `3` | Number of recent generations whose files are kept. This also bounds how many previous copies of each suite's `dists/` tree are retained under `.tain/prev/`. |
| `dry_run` | bool | `false` | Log candidates without deleting, even if `enabled = true`. |

GC is also forced into dry-run mode by `tain sync --gc-dry-run`, by
`tain sync --dry-run`, and on the first sync into a directory that already
contains files but has no `tain` state (for example an existing mirror being
taken over). Run `tain verify` after such a takeover before relying on GC.

### Not supported: flat repositories

A flat repository has its `Release` and `Packages` files in a plain
directory instead of under `dists/` (`deb https://example.com/apt ./` or
`deb https://example.com/apt stable/` in `sources.list`). 0.1 cannot mirror
them. Following apt's rule, any suite that is `"."` or ends in `/` (such as
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
| `TAIN_SEGMENTS` | `segments_per_file` | integer |
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

## Logging

Logs go to stderr. Two settings control them:

- `log_level` (`TAIN_LOG_LEVEL`): a level (`error`, `warn`, `info`, `debug`,
  `trace`) or a filter such as `info,tain::core=debug`. Default `info`.
- `log_format` (`TAIN_LOG_FORMAT`): `text` (default) or `json`.

The environment variable wins over the `[global]` key, which wins over the
default. Both are read once at startup; `SIGHUP` does not change them.
Messages printed while the configuration file is being read use the
environment variables only. An invalid level or format is a configuration
error (exit code 2). To keep logs in a file, redirect stderr or let systemd
or Docker collect them.

## Importing an apt-mirror `mirror.list`

```sh
tain import mirrors-list /etc/apt/mirror.list > config.toml
tain --config config.toml check
```

The converter prints TOML on stdout (`-` reads from stdin). It understands:

- `deb`, `deb-src` and `deb-<arch>` lines (`deb-amd64 URL SUITE COMP...`);
- an options bracket `[arch=amd64,arm64 signed-by=/path/key.gpg]`;
- `mirror_path <url-prefix> <dir>`, which becomes the mirror's `path`;
- `#` comments and blank lines.

Other directives, such as apt-mirror's `set` and `clean` lines, are
rejected with a line number; delete them first. Lines for the same URL,
architecture set and keyring merge into one `[[mirror]]`. `deb-src` turns on
`indexes.sources`. `signed-by=` becomes `verify.pgp = "required"` with that
keyring. If a line has no architecture, the output adds
`[defaults] architectures = ["amd64"]`.

Lines for flat repositories (a suite that is `.` or ends in `/`, such
as `./` or `stable/`) are [not supported](#not-supported-flat-repositories): they are
copied into a comment block at the end of the output, a warning naming
each line number goes to stderr, and the rest of the file is converted as
usual. Always read the generated file and run `tain check` on it.

## On-disk layout

```
<target>/<path>/            mirror root, serve this over HTTP
    dists/                  published suites (as upstream)
    pool/                   package files (as upstream)
    .tain/                  tain's own state, do not serve
        state.json          per-suite state (Release hash, Date, generation)
        lock                per-mirror lock
        staging/            work area for the sync in progress
        prev/               previous copies of each suite's dists/ tree
        ...                 generation manifests
```

`staging/` sits inside the mirror root so that publishing a suite is a
rename on one filesystem. Exclude `.tain/` from your web server.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | At least one mirror or suite failed (`sync`); problems found (`verify`); a mirror is unhealthy or its state is unreadable (`status`). |
| 2 | Configuration error: no source, invalid TOML or environment value, `verify.pgp` without `verify.keyring`, a flat-repository suite, invalid log level, missing or invalid `schedule` for `daemon`, bad `--healthy-within`, unparseable `mirror.list`. |
| 3 | Lock contention: every selected mirror failed and at least one because another process held its lock (`sync`). |
| 4 | Fatal I/O: unreadable config file, unwritable target, disk full. |

For `tain sync`, 4 takes precedence over everything else, then 3, then 1.
`tain daemon` exits 0 after `SIGTERM`/`SIGINT`; failures of individual
scheduled runs are logged and do not stop the daemon. A `--metrics-file`
write failure is logged and never changes the exit code.
