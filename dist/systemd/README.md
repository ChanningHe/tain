# Tain systemd unit files

Three ways to run tain under systemd; pick the one that fits your setup:

| Unit                    | Shape                | When |
| ----------------------- | -------------------- | ---- |
| `tain-sync.service` + `tain-sync.timer` | oneshot + timer | systemd decides when to sync; tain's own lock prevents overlapping runs, and `Persistent=true` catches up on runs missed while the host was down. Prefer this if you already manage jobs with systemd timers. |
| `tain-daemon.service`   | long-running daemon  | tain schedules itself from a cron expression (`global.schedule` or `TAIN_SCHEDULE`, required), reloads its config on SIGHUP (`systemctl reload`) and stops gracefully on SIGTERM. Same model as the Docker image's default command. |
| `tain@.service`         | template (per-mirror) | One instance per config file (`/etc/tain/debian.toml` → `tain@debian.service`, `/etc/tain/ubuntu.toml` → `tain@ubuntu.service`). No matching timer is shipped; write a `tain@.timer` (or per-instance timers) if you want them scheduled. |

## Install

The `.deb` package installs the binary and these units, creates the `tain`
user and a starter `/etc/tain/config.toml` for you. From the release
tarball, as root, inside the unpacked `tain-linux-<arch>/` directory:

```bash
# The units run /usr/bin/tain
install -o root -g root -m 755 tain /usr/bin/tain

# Copy the units
cd systemd
install -o root -g root -m 644 tain-sync.service tain-sync.timer \
    tain-daemon.service tain@.service /usr/lib/systemd/system/

# Create the service user (matches ReadWritePaths= below)
useradd --system --user-group --home-dir /srv/mirrors --shell /usr/sbin/nologin tain
mkdir -p /srv/mirrors /etc/tain
chown -R tain:tain /srv/mirrors

# Install config (edit as needed)
install -o root -g tain -m 640 your-config.toml /etc/tain/config.toml

systemctl daemon-reload
```

Then enable **one** of:

```bash
systemctl enable --now tain-sync.timer       # systemd-managed cadence
systemctl enable --now tain-daemon.service   # built-in scheduler (needs global.schedule)
```

## Adjust limits and paths

Override settings with a drop-in (`systemctl edit tain-sync.service`)
rather than editing the shipped files, which an upgrade replaces:

- `ReadWritePaths=` defaults to `/srv/mirrors`. `ProtectSystem=strict`
  blocks writes anywhere else. A drop-in adds to the list; to replace it,
  reset it with an empty assignment first:

  ```ini
  [Service]
  ReadWritePaths=
  ReadWritePaths=/data/mirrors
  ```

  `--metrics-file` writes outside the mirror (e.g. a node_exporter textfile
  directory), so that directory needs its own `ReadWritePaths=` line.
- `MemoryMax=4G` caps memory use.
- `TimeoutStartSec=1d` (oneshot units) stops a hung sync so the next timer
  run can start. A sync killed this way is safe: the published tree is
  untouched and the next run resumes, keeping pool files already
  downloaded. Raise it if a first full sync takes longer.

- Network egress is not filtered by default (`RestrictAddressFamilies=`
  only limits socket types). tain refuses redirects to internal IP
  literals but does not check what a DNS name resolves to. To keep it off
  internal networks, add for example:

  ```ini
  [Service]
  IPAddressDeny=localhost link-local multicast 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7
  # Keep the DNS resolver reachable, e.g. the systemd-resolved stub:
  IPAddressAllow=127.0.0.53
  ```

  Skip this if an upstream or proxy lives on your LAN.

The units also run with no capabilities, `NoNewPrivileges=`,
`ProtectSystem=strict`, `ProtectHome=`, `PrivateTmp=`, `PrivateDevices=`,
`MemoryDenyWriteExecute=` and the other `Protect*`/`Restrict*` settings
listed in the files, `UMask=0022` (the web server must read the mirror),
and idle I/O priority with `Nice=10`.

A package upgrade restarts a running `tain-daemon.service`. On stop the
daemon lets an in-flight sync finish for up to `TimeoutStopSec=5min`, then
it is killed; an interrupted sync is safe and resumes on the next run.

## Exit codes

```
0  success                         → systemd: normal
1  partial (some suites failed)    → systemd: failed → alerting
2  config error                    → systemd: failed → alerting (operator)
3  lock contention (previous run)  → systemd: failed → often benign
4  fatal I/O                       → systemd: failed → alerting (disk / perms)
```

`SuccessExitStatus=` is intentionally left at the default (0 only) so a
monitoring system sees every non-zero exit as a failed run.
