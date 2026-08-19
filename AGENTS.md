# Coding agent instructions

This file provides guidance to coding agents when working with code in this repository.

## Project Overview

**wrapped** is a CLI tool that runs programs in a sandbox using [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`). It requires `bwrap` to be installed and in `PATH`. Linux only.
The `--network bridge` and `--network filtered` modes require `pasta` (from the [passt](https://passt.top/) project). The `--network filtered` mode additionally requires `nft` (nftables).
The `--cgroup`, `--cpu-limit` and `--memory-limit` flags require `systemd-run` and a systemd user session.

The project is implemented in **Go**:
-  — library in `wrapped.go`, CLI in `cmd/wrapped/main.go`

## Build & Run

```bash
go build -tags netgo -o wrapped ./cmd/wrapped
golangci-lint run ./...
go test ./...
```

## Architecture

The Go implementation is structured as a library + CLI:
- `wrapped.go` — `package wrapped` library exposing `Wrapped()`. Builds bwrap arguments, then either `syscall.Exec`s bwrap (default) or runs it as a child process (filtered/bridge network modes).
- `cmd/wrapped/main.go` — `package main` CLI using `cobra` for argument parsing. Calls `wrapped.Wrapped()`.

Key design: the tool constructs a `bwrap` command line with namespace isolation flags (`--unshare-user`, `--unshare-ipc`, `--unshare-pid`, etc.), then execs into it. The sandbox provides:
- Read-only bind mounts of `/usr`, `/etc`
- Symlinks for `/lib`, `/lib64`, `/bin`, `/sbin`
- Cleared environment with selective passthrough
- Optional network access, current directory mounting (read-only or writable), and extra mount points
- Optional AppArmor profile enforcement

### Network modes

1. **No network** (`--network none`, default): `--unshare-net` isolates the network namespace completely.
2. **Full network** (`--network host`): no network isolation, DNS resolution via `/run/systemd/resolve` if available.
3. **Bridge network** (`--network bridge`): pasta runs in command mode, creating user+network namespaces and running bwrap as its child (`pasta --config-net ... -- bwrap ...`). All pasta port forwarding and splice forwarding is disabled (`-t none -u none -T none -U none`) to prevent the sandbox from reaching host loopback services. DNS is handled by bind-mounting the non-stub `/run/systemd/resolve/resolv.conf` over the stub resolver. Bwrap's `--uid`/`--gid` flags explicitly map the current user's UID/GID inside the sandbox. IPv4-only mode (`-4`) is used when the host lacks IPv6 routing.
4. **Filtered network** (`--network filtered`): pasta creates a network namespace (like bridge mode), then nftables rules inside the namespace restrict outbound traffic to only the resolved IPs of allowed hosts. Hosts are resolved at startup. Requires `nft` in PATH. Transparent to applications — no proxy configuration needed.

### Cgroups and resource limits

`--cgroup` (implied by `--cpu-limit` and `--memory-limit`) runs the sandbox in a transient systemd scope, i.e. a cgroup of its own. `buildCgroupPrefix` in `wrapped.go` turns a `Cgroup` value into a `systemd-run --user --scope --quiet --collect [--property ...] --` prefix that is placed in front of the command wrapped would otherwise have run — `bwrap` in the default mode, `pasta` in the bridge and filtered modes, so that pasta shares the sandbox's limits. `systemd-run --scope` execs its command once the scope exists, so the default mode still `syscall.Exec`s and keeps its PID.

`CPUAccounting=yes` and `MemoryAccounting=yes` are always passed. systemd enables a cgroup controller for a unit only if the unit uses it, so without them `--cgroup` on its own produces a cgroup with neither the `cpu` nor the `memory` controller — nothing limited and nothing measured, and no `cpu.max`/`memory.current` to inspect. Requesting accounting explicitly also keeps the same control files present regardless of the distribution's `DefaultCPUAccounting`/`DefaultMemoryAccounting`.

`systemdUserBusEnv` resolves the session bus before running `systemd-run`, because `systemd-run --user` reports a bare `Failed to connect to bus: No medium found` (`-ENOMEDIUM` from `sd_bus_open_user`) when neither `DBUS_SESSION_BUS_ADDRESS` nor `XDG_RUNTIME_DIR` is set — which says nothing about wrapped or cgroups. When only the variables are missing, it points `XDG_RUNTIME_DIR` at the standard `/run/user/<uid>`; when there is no bus there either, it fails with an error naming the cause. This is why `buildCgroupPrefix` also returns the environment the sandbox chain must run with: both the `syscall.Exec` path and the pasta child need it.

One failure mode is worth recognising, because it looks like a wrapped bug and leaves no trace in the AppArmor logs: if a profile confining the `wrapped` binary execs `systemd-run` with an uppercase mode (`Px`, `Ux`, `Cx`), AppArmor scrubs the environment through the kernel's unsafe-exec path, setting `AT_SECURE`. systemd reads the bus variables with `secure_getenv()`, which returns nothing under `AT_SECURE`, so `systemd-run` reports `Failed to connect to bus: No medium found` no matter what environment wrapped hands it. The fix is in the profile (a lowercase `px`/`pux`/`ux`/`ix`), not in this code. `apparmor/wrapped` in this repo is a profile for the wrapped binary itself, and documents this; keep it in step with the programs `wrapped.go` execs.

systemd is what makes this work unprivileged: it owns the delegated cgroup subtree, so wrapped never has to find a writable cgroup, deal with the no-internal-processes rule, or clean up after itself. Do not replace this with direct writes under `/sys/fs/cgroup`.

The CLI flags are deliberately backend-agnostic: `--cpu-limit` is a number of CPUs and `--memory-limit` a byte count with an optional `K`/`M`/`G`/`T`/`P` suffix. `cpuQuota` and `memoryMax` validate them and translate to systemd's `CPUQuota` percentage and `MemoryMax`. Keep translation in those two functions rather than letting systemd syntax into the CLI.

### Internal re-exec

The nft rules must be applied inside pasta's namespace but before bwrap, so that `nft` gets `CAP_NET_ADMIN` from pasta's user namespace rather than bwrap's. pasta's command mode runs a single command, so wrapped runs itself as that command: `pasta ... -- wrapped __nft-exec <ruleset> <bwrap> <bwrap args...>`. The `__nft-exec` helper (`RunInternalCommand` in `wrapped.go`, dispatched at the top of `main`) pipes the ruleset to `nft` and, **only if that succeeds**, execs bwrap — so a failure to apply the rules never falls open to an unfiltered network.

The ruleset and the bwrap arguments travel as ordinary argv elements, so no shell and no quoting is involved. Do not reintroduce `sh -c` here. Note that this makes `--network filtered` depend on `os.Executable()`: a program embedding this package must call `wrapped.RunInternalCommand(os.Args[1:])` before parsing its own arguments.

### Documentation

Keep the documentation in `README.md` up-to-date with command line options etc.

### Testing

Use [testify](https://github.com/stretchr/testify) (`assert` and `require` packages) for all Go tests.
