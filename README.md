# tain

[![CI](https://github.com/channinghe/tain/actions/workflows/ci.yml/badge.svg)](https://github.com/channinghe/tain/actions/workflows/ci.yml)

`tain` keeps a local mirror of APT repositories (Debian, Ubuntu and
third-party repositories such as Proxmox) in sync with upstream.

## Install

Every [release](https://github.com/channinghe/tain/releases) ships static
Linux binaries (amd64, arm64), a `.deb` for amd64 and container images.

**Debian/Ubuntu package (amd64).** Installs `/usr/bin/tain`, the systemd
units, a `tain` system user and a starter `/etc/tain/config.toml`:

```sh
sudo apt install ./tain_*_amd64.deb
```

**Tarball.** Pick `amd64` or `arm64`, check the download, and install the
binary where the shipped systemd units expect it:

```sh
ARCH=amd64 VERSION=0.1.1
BASE=https://github.com/channinghe/tain/releases/download/v$VERSION
curl -fLO "$BASE/tain-linux-$ARCH.tar.gz" -fLO "$BASE/tain-linux-$ARCH.tar.gz.sha256"
sha256sum -c "tain-linux-$ARCH.tar.gz.sha256"
tar xzf "tain-linux-$ARCH.tar.gz"
sudo install -m 755 "tain-linux-$ARCH/tain" /usr/bin/tain
```

The tarball also contains the systemd units; see
[dist/systemd/README.md](dist/systemd/README.md) to set them up.

**Container image.** `ghcr.io/channinghe/tain` for linux/amd64 and
linux/arm64, tagged `latest`, `X.Y.Z`, `X.Y` and `X`. Each tag has a
`-debug` variant (`latest-debug`, `X.Y.Z-debug`) that adds a busybox shell
for `docker exec`. The image runs as uid 65532 and its default command is
`tain daemon`.

HTTPS upstreams are verified against the system CA store
(`SSL_CERT_FILE` and `SSL_CERT_DIR` are honoured, so a private CA works)
and the bundled Mozilla roots. In the container, mount a bundle that
includes your CA over `/etc/ssl/certs/ca-certificates.crt`.

## Quick start

### One mirror in Docker, configured by environment

```sh
sudo install -d -o 1000 -g 1000 /srv/mirrors
docker run -d --name tain-proxmox --restart unless-stopped \
  --user 1000:1000 \
  -v /srv/mirrors:/data \
  -e TAIN_URL=http://download.proxmox.com/debian/pve \
  -e TAIN_DISTS='trixie|pve-no-subscription|amd64' \
  -e TAIN_PATH=proxmox \
  -e TAIN_GC=1 \
  -e TAIN_SCHEDULE='0 */6 * * *' \
  ghcr.io/channinghe/tain:latest
```

The mirror appears in `/srv/mirrors/proxmox`; serve that directory with any web
server. `TAIN_SCHEDULE` is a cron expression in the container's time zone
(UTC unless you set `TZ`). [docker/docker-compose.yml](docker/docker-compose.yml)
has the same setup for Compose, with a health check.

### Several mirrors from a TOML file

```toml
# /etc/tain/config.toml
[global]
target = "/data"
schedule = "0 2,8,14,20 * * *"

[defaults]
architectures = ["amd64"]
gc = { enabled = true }

[[mirror]]
name = "debian"
url = "https://deb.debian.org/debian"
suites = ["trixie", "trixie-updates"]
components = ["main", "contrib", "non-free-firmware"]

[mirror.verify]
pgp = "required"
keyring = "/usr/share/keyrings/debian-archive-keyring.gpg"

[[mirror]]
name = "proxmox"
url = "http://download.proxmox.com/debian/pve"
suites = ["trixie"]
components = ["pve-no-subscription"]
```

Check it, then run it with the image's default command:

```sh
tain --config /etc/tain/config.toml check
docker run -d --name tain --restart unless-stopped --user 1000:1000 \
  -v /srv/mirrors:/data \
  -v /etc/tain/config.toml:/etc/tain/config.toml:ro \
  -v /usr/share/keyrings:/usr/share/keyrings:ro \
  ghcr.io/channinghe/tain:latest
```

On a host install, set `target = "/srv/mirrors"` to match the systemd
units. The full list of keys and environment variables is in
[docs/configuration.md](docs/configuration.md).

### systemd

Two ways to schedule syncs. Use one, not both.

```sh
# A: systemd timer runs `tain sync` around 02:00, 08:00, 14:00 and 20:00
sudo systemctl enable --now tain-sync.timer

# B: long-running `tain daemon` using global.schedule from the config
sudo systemctl enable --now tain-daemon.service
sudo systemctl reload tain-daemon.service   # re-read the config (SIGHUP)
```

The units run as user `tain` and may only write to `/srv/mirrors`
(`ReadWritePaths=`). A `tain@.service` template runs
`/etc/tain/<instance>.toml`. See [dist/systemd/README.md](dist/systemd/README.md).

### One-off runs

```sh
tain sync                         # all mirrors in /etc/tain/config.toml
tain sync --mirror debian         # just one
tain sync --dry-run               # print what would be downloaded, publish nothing
```

## Commands

`--config <path>` (or `TAIN_CONFIG`) works with every command. Without it,
`tain` reads `/etc/tain/config.toml`, or builds a single mirror from
`TAIN_URL` and `TAIN_DISTS`.

| Command | Description |
|---|---|
| `tain sync [--mirror NAME]... [--dry-run] [--gc-dry-run] [--metrics-file PATH]` | Run one sync of all (or the named) mirrors and exit. An unknown `NAME` is a configuration error (exit 2). `--dry-run` downloads the `Release` files and the indexes it needs to plan (into `.tain/staging/`, removed afterwards), prints the plan on stdout and publishes nothing: no pool downloads, no state, manifest or GC changes. It still creates the mirror directory and `.tain/lock`, and a suite that fails is reported in the plan without changing the exit code. `--gc-dry-run` reports GC candidates without deleting. |
| `tain daemon [--no-initial-sync]` | Sync once at start (unless `--no-initial-sync`), then on every `schedule` tick. A tick that arrives while a sync is running is skipped. `SIGHUP` reloads the config; `SIGTERM`/`SIGINT` stop the daemon once the running sync, if any, has finished. |
| `tain check` | Load and validate the configuration (mirror paths, backend rules, `schedule`), print it with all defaults resolved, and exit. Makes no network requests and writes nothing. Keyring files are not read, and a configuration without mirrors passes (every other command exits 2 on it). |
| `tain verify [--mirror NAME]...` | Re-hash every file recorded for the latest generation and report missing or corrupt files. It only reports; nothing is changed. An unknown `NAME` is a configuration error (exit 2). |
| `tain status [--json] [--healthy-within DUR]` | Print per mirror the generation, the suite in the most recently published generation, and the age of that suite's upstream `Release` `Date` (not necessarily the newest `Date` among all suites, and not the time of the last sync): an upstream that publishes rarely looks old however recently `tain` ran. With `--healthy-within`, exit 1 if any mirror's age exceeds `DUR` (for example `7d`) or is unknown. |
| `tain import mirrors-list FILE` | Convert an apt-mirror `mirror.list` (`-` for stdin) to TOML on stdout. |

## License

[MIT license](LICENSE)
