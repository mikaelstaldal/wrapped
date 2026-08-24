# Coding agent instructions

This file provides guidance to coding agents when working with code in this repository.

## Project Overview

**wrapped** is a CLI tool that runs programs in a sandbox using [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`). It requires `bwrap` to be installed and in `PATH`. Linux only.
The `--network bridge` and `--network filtered` modes require `pasta` (from the [passt](https://passt.top/) project). The `--network filtered` mode additionally requires `nft` (nftables).
Running the sandbox in a cgroup of its own, which wrapped does by default whenever it can, requires `systemd-run` and a systemd user session; without them the sandbox runs without a cgroup. The `--cgroup`, `--cpu-limit` and `--memory-limit` flags make the cgroup mandatory, and `--no-cgroup` declines it.

The project is implemented in **Go**:
-  — library in `wrapped.go`, CLI in `cmd/wrapped/main.go`

## Build & Run

```bash
go build -trimpath -buildvcs=true -tags netgo -o wrapped ./cmd/wrapped
golangci-lint run ./...
go test ./...
go test -short ./...   # unit tests only, no bwrap/pasta/systemd-run, no signals
```

## Architecture

The Go implementation is structured as a library + CLI:
- `wrapped.go` — `package wrapped` library exposing `Wrapped()`. Builds the bwrap arguments and hands the resulting command line to `runSandbox`, either directly (default) or wrapped in pasta (bridge/filtered network modes).
- `supervise.go` — `runSandbox` and everything about starting the sandbox and taking it down again: the process group, the terminal handover, the reaper, and the two kill levers. See [Terminating the sandbox](#terminating-the-sandbox).
- `cmd/wrapped/main.go` — `package main` CLI using `cobra` for argument parsing. Calls `wrapped.Wrapped()`.

Key design: the tool constructs a `bwrap` command line with namespace isolation flags (`--unshare-user`, `--unshare-ipc`, `--unshare-pid`, etc.), then runs it. The sandbox provides:
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

### The environment the chain runs with

Two environments are in play, and they are not the same one. The sandboxed program's is
built out of bwrap's `--clearenv` and `--setenv` arguments in `buildBaseBwrapArgs`. The
processes of the sandbox chain — `systemd-run`, `pasta`, `bwrap` and wrapped's own
internal helpers between them — get theirs from `sandboxChainEnv`, which is `PATH` plus
`chainEnvPassthrough` and nothing else. Nothing in the chain looks up anything else, so
nothing else is handed to it, and a secret in the operator's environment cannot leak from
a helper's `/proc/<pid>/environ` or its core dump. The reaper gets no environment at all;
it reads a pipe, reads `/proc` and signals what it finds there.

`sandboxChainEnv(true)` is the exception, and belongs to exactly those runs where bwrap
is **not** given `--clearenv` and so passes its own environment on to the program:
`--all-env` and `--only-network`. Passing the environment through is the point of both,
so the whole of it has to travel down the chain. Any new run mode has to make that call
one way or the other; getting it wrong either drops the program's environment or leaks
the operator's.

`chainEnvPassthrough` is `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR`, which is how
`systemd-run --user` finds the session bus. Dropping either is worse than it looks:
`systemdUserBusEnv` decides whether there is a bus to be found from wrapped's *own*
environment, so it would find the bus reachable and still hand `systemd-run` an
environment in which it is not. `PATH` is not a nicety either — the `__nft-exec` helper
looks `nft` up in it, and a lookup in an empty `PATH` resolves against the current
directory, which is why an empty `PATH` and no `PATH` at all both fall back to
`defaultPath`. Only a run that passes the environment through keeps an empty one.

### Cgroups and resource limits

wrapped runs the sandbox in a transient systemd scope, i.e. a cgroup of its own, whenever it can. `buildCgroupPrefix` in `wrapped.go` turns a `Cgroup` value into a `systemd-run --user --scope --quiet --collect [--property ...] --` prefix that is placed in front of the command wrapped would otherwise have run — `bwrap` in the default mode, `pasta` in the bridge and filtered modes, so that pasta shares the sandbox's limits. `systemd-run --scope` execs its command once the scope exists, so the scope is in place before the sandbox starts.

`Cgroup.Mode` says what an unavailable cgroup costs, and `resolveCgroupPrefix` acts on it:

- `CgroupAuto` (the zero value, and the CLI's default) takes a cgroup where there is one to be had and runs without one where there is not. This is the mode that must never fail a run over a cgroup.
- `CgroupRequired` (`--cgroup`) reports the failure instead. `--cpu-limit` and `--memory-limit` imply it, which `Cgroup.mandatory` derives from the limit rather than the caller having to set both: a limit that goes unapplied is not a limit. `--no-cgroup` (`CgroupDisabled`) is refused together with any of the three, in the CLI by three separate `MarkFlagsMutuallyExclusive` pairs — one set of all four would also rule out `--cgroup` with a limit — and in the library by `buildCgroupPrefix` rejecting a limit it is told not to place in a cgroup. `Cgroup.mandatory` keys on the limit whatever the mode for that second half to survive `resolveCgroupPrefix`: a mandatory-blind version degraded the contradiction away and ran the program with neither the cgroup nor the limit. An unknown `CgroupMode` is rejected in `resolveCgroupPrefix` for the same reason — degrading is what makes a wrong value look like it worked.

Auto mode also runs `systemd-run` once for real, on a trivial program, before committing to it (`probeSystemdRun`). The two conditions `buildCgroupPrefix` can see — no `systemd-run` in `PATH`, no session bus — are not all of them: the `AT_SECURE` failure described below happens at the point of use, and in auto mode a run that would otherwise have worked must not be lost to it. The probe costs one round trip to the session bus and leaves nothing behind, and does not run in required mode, where a failure is to be reported rather than avoided. Unit tests must not reach it; `wrapped_test.go` exercises auto mode only through conditions that are detected before anything is exec'd.

Degradation is silent: no cgroup is the same run a machine without systemd has always given, and a warning on every run would be noise on exactly the machines that can do nothing about it. `--cgroup` is how a caller asks to be told.

`runSandbox` names the scope before it knows whether there will be one, so it clears `unit` when the prefix comes back empty. Leaving it set would send `waitForScopeCgroup` looking for a scope that will never exist, and cost every degraded run the full `scopeCgroupTimeout`.

wrapped passes `--unit` so that it knows the scope's name in advance; that is how `waitForScopeCgroup` recognises the sandbox's cgroup in `/proc/<pid>/cgroup` afterwards, which is what makes `cgroup.kill` addressable. Do not drop it.

`CPUAccounting=yes` and `MemoryAccounting=yes` are always passed, so that a cgroup created without limits still measures what the program uses instead of depending on the distribution's `DefaultCPUAccounting`/`DefaultMemoryAccounting`. The two are not symmetric, and the difference has already produced one wrong test: systemd enables a controller for a unit only if the unit needs it, so `MemoryAccounting` enables the `memory` controller (giving `memory.current` and `memory.max`), while `CPUAccounting` does **not** enable the `cpu` controller, because cgroup v2 reports CPU usage in `cpu.stat` regardless. `cpu.max` therefore exists only once `--cpu-limit` is set, and its absence means unlimited.

`systemdUserBusEnv` resolves the session bus before running `systemd-run`, because `systemd-run --user` reports a bare `Failed to connect to bus: No medium found` (`-ENOMEDIUM` from `sd_bus_open_user`) when neither `DBUS_SESSION_BUS_ADDRESS` nor `XDG_RUNTIME_DIR` is set — which says nothing about wrapped or cgroups. When only the variables are missing, it points `XDG_RUNTIME_DIR` at the standard `/run/user/<uid>`; when there is no bus there either, it fails with an error naming the cause. This is why `buildCgroupPrefix` also returns the environment the sandbox chain must run with: both the `syscall.Exec` path and the pasta child need it.

One failure mode is worth recognising, because it looks like a wrapped bug and leaves no trace in the AppArmor logs: if a profile confining the `wrapped` binary execs `systemd-run` with an uppercase mode (`Px`, `Ux`, `Cx`), AppArmor scrubs the environment through the kernel's unsafe-exec path, setting `AT_SECURE`. systemd reads the bus variables with `secure_getenv()`, which returns nothing under `AT_SECURE`, so `systemd-run` reports `Failed to connect to bus: No medium found` no matter what environment wrapped hands it. The fix is in the profile (a lowercase `px`/`pux`/`ux`/`ix`), not in this code — auto mode's probe keeps such a profile from failing every run, but it does not make the profile right. `apparmor/wrapped` in this repo is a profile for the wrapped binary itself, and documents this; keep it in step with the programs `wrapped.go` execs.

systemd is what makes this work unprivileged: it owns the delegated cgroup subtree, so wrapped never has to find a writable cgroup, deal with the no-internal-processes rule, or clean up after itself. Do not replace this with direct writes under `/sys/fs/cgroup`.

The CLI flags are deliberately backend-agnostic: `--cpu-limit` is a number of CPUs and `--memory-limit` a byte count with an optional `K`/`M`/`G`/`T`/`P` suffix. `cpuQuota` and `memoryMax` validate them and translate to systemd's `CPUQuota` percentage and `MemoryMax`. Keep translation in those two functions rather than letting systemd syntax into the CLI.

### Internal re-exec

The nft rules must be applied inside pasta's namespace but before bwrap, so that `nft` gets `CAP_NET_ADMIN` from pasta's user namespace rather than bwrap's. pasta's command mode runs a single command, so wrapped runs itself as that command: `pasta ... -- wrapped __nft-exec <ruleset> <bwrap> <bwrap args...>`. The `__nft-exec` helper (`RunInternalCommand` in `wrapped.go`, dispatched at the top of `main`) pipes the ruleset to `nft` and, **only if that succeeds**, execs bwrap — so a failure to apply the rules never falls open to an unfiltered network.

The ruleset and the bwrap arguments travel as ordinary argv elements, so no shell and no quoting is involved. Do not reintroduce `sh -c` here.

`RunInternalCommand` dispatches a second helper, `__reap`, described below. Between them they make **every** run depend on `os.Executable()`, not just `--network filtered`: a program embedding this package must call `wrapped.RunInternalCommand(os.Args[1:])` before parsing its own arguments.

### Terminating the sandbox

wrapped must leave nothing behind — not the program, not its subprocesses, not either bwrap process, not pasta — and must manage it when a process crashes or is killed outright. bwrap's `--die-with-parent` is deliberately not used; it is unreliable. `supervise.go` holds all of this.

`runSandbox` forks the sandbox chain with `Setpgid`, so the sandbox is a process group of its own, and waits for it with `syscall.Wait4`. Cleanup has two levers:

- **`cgroup.kill`** on the transient scope, whenever the sandbox has one — which is by default, wherever one can be created. The kernel applies it to every process in the cgroup at once, regardless of parent, process group or session, so it survives a program that daemonises and a process orphaned by a `SIGKILL` further up the chain. `killCgroup` falls back to signalling `cgroup.procs` by hand on kernels before 5.14, where `cgroup.kill` does not exist. This is the reliable lever.
- **`SIGKILL` to the process group**, which is all there is without a cgroup, and which `setsid` escapes. Best-effort by construction.

Neither lever works if wrapped is itself killed with `SIGKILL`, so `startReaper` re-execs wrapped as `__reap <pgid> <starttime>` with the read end of a pipe on descriptor 3 and the write end held only by wrapped. The reaper blocks reading that pipe; end-of-file means wrapped is gone, however it went, and the reaper then pulls both levers. wrapped sends the cgroup path down the pipe once `waitForScopeCgroup` has resolved it, since the scope does not exist until systemd-run has created it. The reaper is started **after** the sandbox, so that nothing in the sandbox can inherit the write end and hold the pipe open; it runs `Setsid` so signals aimed at wrapped's own process group cannot take it out.

`killProcessGroup` checks the leader's start time from `/proc/<pid>/stat` field 22 before signalling, so a process id handed out again after the sandbox exited is not signalled by mistake.

A process group of its own would make the sandbox a background job, stopped by `SIGTTIN` the moment it read from the terminal, so `terminalHandover` makes it the foreground group instead, and `waitForSandbox` waits with `WUNTRACED` so that a `Ctrl-Z` of the sandbox suspends wrapped along with it and job control keeps working. `SIGTTIN`/`SIGTTOU` are ignored only **after** the fork, since an ignored signal stays ignored across `exec` and the sandbox must not inherit that.

### Documentation

Keep the documentation in `README.md` up-to-date with command line options etc.

### Testing

Use [testify](https://github.com/stretchr/testify) (`assert` and `require` packages) for all Go tests.

The two test files are not interchangeable, and a test in the wrong one is a real problem rather than an untidiness:

- `wrapped_test.go` holds unit tests. They must not exec anything, send a signal, or touch a real cgroup. `go test -short ./...` runs these alone, which is what a machine whose AppArmor profile confines the test runner needs — a denied `bwrap` there is not a wrapped bug and must not be reported as one.
- `wrapped_integration_test.go` holds everything that runs real programs or signals real processes. Every test in it is named `TestIntegration...` and **must** call `requireIntegration(t)` first, plus the `require*` helper for whatever it needs, so it skips rather than fails where that thing is unavailable.

Take particular care with tests around process termination. A test that feeds a made-up process id to something that ends in `kill(2)` can take the whole session down: `kill` reads 0 as the caller's own process group and **-1 as every process the caller can signal**. `cgroupProcs` drops anything that is not a positive process id for exactly this reason, and `TestCgroupProcsRejectsAnythingButAProcessID` guards it. Test the parsing and the walking; do not test the killing with values you invented.
