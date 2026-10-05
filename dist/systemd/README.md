# Tain systemd unit files

Three ways to run tain under systemd; pick the one that fits your setup:

| Unit                    | Shape                | When |
| ----------------------- | -------------------- | ---- |
| `tain-sync.service` + `tain-sync.timer` | oneshot + timer | systemd decides when to sync; tain's own lock prevents overlapping runs, and `Persistent=true` catches up on runs missed while the host was down. Prefer this if you already manage jobs with systemd timers. |
| `tain-daemon.service`   | long-running daemon  | tain schedules itself from a cron expression (`global.schedule` or `TAIN_SCHEDULE`, required), reloads its config on SIGHUP (`systemctl reload`) and stops gracefully on SIGTERM. Same model as the Docker image's default command. |
| `tain@.service`         | template (per-mirror) | One instance per config file (`/etc/tain/debian.toml` → `tain@debian.service`, `/etc/tain/ubuntu.toml` → `tain@ubuntu.service`). No matching timer is shipped; write a `tain@.timer` (or per-instance timers) if you want them scheduled. |

## Install

The `.deb` package installs these units, creates the `tain` user and a
starter `/etc/tain/config.toml` for you. For the tarball, as root:

```bash
# Copy the units
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

## Adjust `ReadWritePaths=`

The default is `/srv/mirrors`; edit each `.service` file if your mirror
lives elsewhere. `ProtectSystem=strict` blocks writes outside of it.

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
