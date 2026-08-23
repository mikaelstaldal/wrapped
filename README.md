# wrapped

Run a program in a sandbox using Linux namespaces.

## Prerequisites

This is a Linux program, might also work in WSL in Windows (currently not tested). 

Requires [bubblewrap](https://github.com/containers/bubblewrap) to be installed and the `bwrap` command to be in `PATH`.

The `--network bridge` mode requires [pasta](https://passt.top/) (from the passt project) to be installed and in `PATH`.

The `--network filtered` mode (used with `--allow-host`) requires [pasta](https://passt.top/) and `nft` (from the nftables project) to be installed and in `PATH`.

The `--cgroup`, `--cpu-limit` and `--memory-limit` flags require `systemd-run` to be installed and in `PATH`, and a systemd user session.

## Install

```bash
go install -tags netgo github.com/mikaelstaldal/wrapped/cmd/wrapped@latest
```

## Build

To build with version information baked in:

```bash
go build -trimpath -buildvcs=true -tags netgo -ldflags "-X main.version=0.1.0" ./cmd/wrapped
```

Without `-ldflags`, `wrapped --version` prints `dev`.

## Usage

```
wrapped [flags] -- program [arguments...]
```

### Flags

| Flag                        | Description                                                                            |
|-----------------------------|----------------------------------------------------------------------------------------|
| `--network <mode>`          | Network mode: `none` (default), `host`, `bridge`, or `filtered`                        |
| `--expose-tcp <port>`       | Expose TCP port from sandbox to host (repeatable, bridge mode only)                    |
| `--expose-udp <port>`       | Expose UDP port from sandbox to host (repeatable, bridge mode only)                    |
| `--allow-host <host>`       | Allow network access to a specific host (repeatable, implies `--network filtered`)     |
| `--current-dir`             | Mount the current directory read-only                                                  |
| `--current-dir-writable`    | Mount the current directory writable                                                   |
| `--mount <path>`            | Mount additional directory read-only (repeatable)                                      |
| `--mount-writable <path>`   | Mount additional directory writable (repeatable)                                       |
| `--symlink <dest>=<src>`    | Create a symlink at DEST pointing to SRC (repeatable, specify as `--symlink DEST=SRC`) |
| `--tmpfs <path>`            | Mount a tmpfs at the given path (repeatable)                                           |
| `-w`, `--workdir <path>`    | Working directory inside the sandbox                                                   |
| `-e`, `--env <VAR[=value]>` | Pass environment variable (repeatable)                                                 |
| `--all-env`                 | Pass through all environment variables (use with caution, can expose secrets)          |
| `--apparmor <profile>`      | Run program with an AppArmor profile                                                   |
| `--only-network`            | Only sandbox the network, leave filesystem untouched                                   |
| `--unshare-cgroup`          | Unshare the cgroup namespace                                                           |
| `--cgroup`                  | Run the program in a cgroup of its own                                                 |
| `--cpu-limit <cpus>`        | Limit CPU usage to the given number of CPUs, e.g. `0.5` or `2` (implies `--cgroup`)    |
| `--memory-limit <size>`     | Limit memory usage, e.g. `512M` or `2G` (implies `--cgroup`)                           |

#### Network modes

| Mode       | Description                                                                                                                                                    |
|------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `none`     | No network access (default). The network namespace is fully isolated.                                                                                          |
| `host`     | Full network access with no isolation.                                                                                                                         |
| `bridge`   | Transparent network access via [pasta](https://passt.top/). The sandbox has its own network namespace and cannot reach localhost, but can reach the Internet.  |
| `filtered` | Network access filtered by IP via nftables rules inside a pasta namespace. Hosts are resolved at startup. Use with `--allow-host`. Requires `pasta` and `nft`. |

### File system

The program to run (the file only, not the directory) is implicitly mounted read-only if not covered by any 
`--mount`, `--mount-writable`, `--current-dir`, `--current-dir-writable` or automatic mount (`/usr`, `/etc`).

### Resource limits

`--cgroup` runs the program in a cgroup of its own, so that its resource usage is
accounted for and can be limited separately from the rest of the session. `--cpu-limit`
and `--memory-limit` set limits on that cgroup and imply `--cgroup`, so a cgroup can also
be created without any limits at all. CPU and memory accounting is enabled either way,
so a cgroup created without limits still measures the program's usage; read it from
`cpu.stat` and `memory.current` in the cgroup the program reports in `/proc/self/cgroup`.

`--cpu-limit` is a number of CPUs, so `1` allows one CPU worth of runtime and `0.5` half
of one. Fractions are supported down to a hundredth of a CPU. `--memory-limit` is a number
of bytes with an optional `K`, `M`, `G`, `T` or `P` suffix, which are powers of 1024. A
program exceeding its memory limit is killed by the kernel's OOM killer.

These flags require `systemd-run` to be installed and in `PATH`, and a systemd user
session with a reachable session bus. wrapped runs the sandbox in a transient systemd
scope, which systemd removes once the program exits. The session bus is found through
`DBUS_SESSION_BUS_ADDRESS` or `XDG_RUNTIME_DIR`; when a shell has inherited neither,
wrapped falls back to the standard `/run/user/<uid>/bus`, and reports

```
no systemd user session bus: ...; a cgroup needs a systemd user session, which su,
sudo, cron and container shells do not set up
```

when there is no session bus to be found at all. A login shell has one; `su`, `sudo`,
`cron` and minimal container shells generally do not. `loginctl --user show-session`
tells you whether the current shell belongs to a session. If wrapped is itself confined
by an AppArmor profile, see
[Confining wrapped with AppArmor](#confining-wrapped-with-apparmor) below, which is a
separate cause of the same symptom.

Limits are applied by the corresponding cgroup controllers, which systemd must be
delegating to your user; `cpu` and `memory` delegation is the default on current
systemd versions.

With `--network bridge` or `--network filtered`, the pasta process providing the
sandbox's network is placed in the same cgroup as the sandbox, so its resource usage
counts towards the limits too.

`--cgroup` is independent of `--unshare-cgroup`; combine them to also hide the cgroup
path from the sandboxed program, which then sees its own cgroup as the root.

### Lifetime of the sandbox

Nothing survives wrapped: when wrapped exits, the sandboxed program, everything it
started, both `bwrap` processes and, in bridge and filtered mode, `pasta` are
terminated. This holds when the program exits normally, when wrapped is interrupted or
terminated, and when wrapped is killed outright with `SIGKILL` or by the OOM killer —
in that last case a reaper process, which wrapped leaves running beside the sandbox for
exactly this purpose, does it instead.

wrapped runs the sandbox in a process group of its own and takes that group down with
`SIGKILL`. With `--cgroup` (or either limit flag) it also kills the transient scope's
cgroup, which is the stronger of the two: the kernel applies it to every process in the
cgroup at once, whatever its parent, process group or session. Without a cgroup, a
program that calls `setsid` and a process orphaned by one of the processes above it
being killed can escape; with one, they cannot. Use `--cgroup` when the program must
not be able to leave anything behind.

The sandbox is the terminal's foreground process group while it runs, so `Ctrl-C`,
`Ctrl-\` and `Ctrl-Z` reach the program directly. wrapped suspends and resumes along
with it, so job control works as it would without wrapped in between. A program killed
by a signal makes wrapped exit with 128 plus the signal number, as a shell would
report it, so an out-of-memory kill under `--memory-limit` shows up as exit code 137.

### Confining wrapped with AppArmor

This is about confining the `wrapped` binary itself, and is unrelated to the
`--apparmor` flag, which applies a profile to the program *inside* the sandbox.

[`apparmor/wrapped`](apparmor/wrapped) is a profile for wrapped:

```bash
sudo install -m 644 apparmor/wrapped /etc/apparmor.d/wrapped
sudo apparmor_parser --replace /etc/apparmor.d/wrapped
```

It attaches to `~/go/bin/wrapped`, `~/.local/bin/wrapped`, `/usr/local/bin/wrapped` and
`/usr/bin/wrapped`; edit `@{wrapped_path}` at the top if your binary lives elsewhere, and
put local additions in `/etc/apparmor.d/local/wrapped` rather than in the profile itself.

The profile is deliberately small, because wrapped opens very little: it execs `bwrap`,
`pasta`, `nft` and `systemd-run`, and those need privileges the profile itself must not
carry. Resolving the paths on the command line needs no rules, since wrapped only
`lstat`s and `readlink`s them. It also execs itself as the reaper described in
[Lifetime of the sandbox](#lifetime-of-the-sandbox), which is what the `@{wrapped_path}
ix,` rule is for.

Two rules are worth understanding before you write your own profile.

```
  ptrace (read),
```

wrapped reads `/proc/<pid>/stat` and `/proc/<pid>/cgroup` of the sandbox it started, to
identify its process group and find its cgroup. Reading another process's entries under
`/proc` is mediated as ptrace `read` when that process runs under a different profile,
so a `@{PROC}/** r,` rule alone is not enough and the denial is reported against the
peer rather than against `/proc`:

```
apparmor="DENIED" operation="ptrace" profile="wrapped" comm="wrapped" \
  requested_mask="read" peer="unconfined"
```

The peer is `unconfined` for a `bwrap` with no profile of its own, and `pasta` with
`--network bridge` or `--network filtered`.

```
  /usr/bin/systemd-run pux,
```

The exec mode for `systemd-run` **must be lowercase**. The uppercase modes (`Px`, `Ux`,
`Cx`) scrub the environment through the kernel's unsafe-exec path, the one used for
setuid binaries, which sets `AT_SECURE`. systemd reads `DBUS_SESSION_BUS_ADDRESS` and
`XDG_RUNTIME_DIR` with `secure_getenv()`, which returns nothing under `AT_SECURE`, so
`systemd-run` cannot find the session bus however the environment is set up, and
`--cgroup` fails with `Failed to connect to bus: No medium found`. Environment scrubbing
is not logged as a denial, so nothing appears in `dmesg` to point at the cause.

### Environment

By default, PATH is reset to a standard value `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`. 
Use `--all-env` or `--env PATH` to keep the host PATH, or `--env PATH=...` to set a custom one.

### Examples

Run a program with no network and no access to the filesystem (beyond read-only access to system directories like `/usr` and `/etc`):
```bash
wrapped program arg1 arg2
```

Run with full network access (no isolation):
```bash
wrapped --network host curl https://example.com
```

Run with transparent network access via pasta (sandboxed but with full connectivity):
```bash
wrapped --network bridge curl https://example.com
```

Allow network access only to specific hosts (hosts are resolved to IPs at startup):
```bash
wrapped --allow-host example.com --allow-host googleapis.com curl https://example.com
```

Mount the current directory writable and pass environment variables:
```bash
wrapped --current-dir-writable -e HOME -e MY_VAR=value program
```

Limit the program to half a CPU and 512 MiB of memory:
```bash
wrapped --cpu-limit 0.5 --memory-limit 512M program
```

Run in a cgroup of its own without imposing any limit:
```bash
wrapped --cgroup program
```

Run with network isolation only (no filesystem sandbox):
```bash
wrapped --only-network curl https://example.com
```

Network-only sandbox with pasta bridge networking:
```bash
wrapped --only-network --network bridge curl https://example.com
```

Network-only sandbox with filtered network access:
```bash
wrapped --only-network --allow-host example.com curl https://example.com
```

## Caveats

The `--only-network` mode provides no effective sandboxing of untrusted programs, and
it might be possible for a malicious program to even circumvent the network restrictions.
Use this only to control network access of trusted progams.

## License

Copyright 2026 Mikael Ståldal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
