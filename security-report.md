# Security Review of wrapped

## HIGH: DNS tunneling in filtered network mode

`wrapped.go:249` — The nftables rules allow **all** outbound DNS (port 53 tcp/udp to any destination):

```
nft add rule inet filter output meta l4proto '{ tcp, udp }' th dport 53 accept
```

A sandboxed process can exfiltrate data via DNS tunneling (encoding data in queries to an attacker-controlled domain) or use DNS-over-TCP to establish covert channels. This significantly undermines the purpose of `--network filtered`.

**Recommendation:** Restrict DNS to the system's configured resolver IPs only (parse them from `/run/systemd/resolve/resolv.conf`), or limit DNS to loopback/the pasta gateway address.

---

## MEDIUM: Broad `/etc` exposure

`wrapped.go:472` — The entire `/etc` directory is mounted read-only into the sandbox:

```go
"--ro-bind", "/etc", "/etc",
```

This exposes potentially sensitive files to the sandboxed process:
- `/etc/shadow` (usually not world-readable, but still unnecessary exposure)
- `/etc/ssh/` (host keys)
- `/etc/machine-id`
- `/etc/subuid`, `/etc/subgid`
- Application-specific secrets in `/etc` (e.g., `/etc/wireguard/`, database configs)

**Recommendation:** Consider bind-mounting only the specific files needed from `/etc` (e.g., `resolv.conf`, `hosts`, `passwd`, `group`, `nsswitch.conf`, `ld.so.cache`, `localtime`, locale configs) rather than the entire directory.

---

## MEDIUM: No `--die-with-parent` flag

The bwrap arguments never include `--die-with-parent`. If the `wrapped` process is killed (e.g., SIGKILL), the sandboxed process continues running unsupervised. This is especially relevant in the `syscall.Exec` path (line 124) where there's no parent process managing the child.

**Recommendation:** Add `--die-with-parent` to the bwrap arguments in `buildBaseBwrapArgs`.

---

## MEDIUM: Incomplete signal forwarding in pasta modes

`wrapped.go:383` — Only SIGINT and SIGTERM are forwarded:

```go
signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
```

SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2, etc. are not forwarded. This means the sandboxed process may not respond to these signals as expected, and a SIGQUIT (which normally triggers a core dump for debugging) would kill the `wrapped` wrapper but leave the sandbox running.

**Recommendation:** Forward additional relevant signals, at minimum SIGHUP and SIGQUIT.

---

## LOW: Home directory check doesn't resolve symlinks

`wrapped.go:485-491` — The check comparing `cwd` against `HOME` uses raw string comparison:

```go
homeDir, ok := os.LookupEnv("HOME")
...
if cwd == homeDir || isParentOrEqual(cwd, homeDir) {
```

`os.Getwd()` returns the resolved physical path, but `HOME` may contain a symlink (e.g., `HOME=/home/user` where `/home` is a symlink to `/data/homes`). In that case, the check could be bypassed. Conversely, if `HOME` is the resolved path but the user `cd`s through a symlink, the check could false-positive.

**Recommendation:** Resolve both `cwd` and `homeDir` with `filepath.EvalSymlinks` before comparing.

---

## LOW: `os.Environ()` leaked to bwrap process itself

`wrapped.go:124`:

```go
syscall.Exec(bwrapPath, argv, os.Environ())
```

The full host environment is passed to the bwrap *process*. While bwrap's `--clearenv` controls what the sandboxed *child* sees, the bwrap process itself (briefly) has access to all environment variables. In practice this is low risk since bwrap is trusted, but it's cleaner to pass a minimal environment.

---

## LOW: No validation of user-supplied mount paths against sensitive locations

`wrapped.go:509-522` — Mount paths (`--mount`, `--mount-writable`) are resolved via `EvalSymlinks` but there's no check against dangerous paths like `/`, `/proc`, `/sys`. A user could accidentally do `--mount-writable /` and expose the entire filesystem writable inside the sandbox.

**Recommendation:** Consider warning or blocking mounts of `/`, `/proc`, `/sys`, `/dev`, and the home directory.

---

## INFO: Verified safe

- **`shellQuote` implementation is correct** — The single-quote wrapping with `'\''` escape is the standard POSIX-safe quoting approach. No injection risk.
- **nftables IP injection is safe** — `buildNftRules` only uses IPs that have passed through `net.ParseIP`, which validates format. No injection into the nft commands is possible.
- **Bridge mode disables port forwarding correctly** — The `-t none -u none -T none -U none` flags correctly prevent the sandbox from reaching host loopback services via pasta's port forwarding mechanism.

---

## Summary

| Severity | Finding |
|----------|---------|
| HIGH | DNS tunneling possible in filtered mode (unrestricted port 53) |
| MEDIUM | All of `/etc` exposed to sandbox |
| MEDIUM | No `--die-with-parent` — orphaned sandboxes possible |
| MEDIUM | Incomplete signal forwarding in pasta modes |
| LOW | Home directory symlink bypass |
| LOW | Full env passed to bwrap process in exec path |
| LOW | No validation against dangerous mount targets |
