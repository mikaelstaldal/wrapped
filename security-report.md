# Security Review of wrapped

---

## MEDIUM: No `--die-with-parent` flag

The bwrap arguments never include `--die-with-parent`. If the `wrapped` process is killed (e.g., SIGKILL), the sandboxed process continues running unsupervised. This is especially relevant in the `syscall.Exec` path (line 124) where there's no parent process managing the child.

**Recommendation:** Add `--die-with-parent` to the bwrap arguments in `buildBaseBwrapArgs`.

---

## LOW: `os.Environ()` leaked to bwrap process itself

`wrapped.go:124`:

```go
syscall.Exec(bwrapPath, argv, os.Environ())
```

The full host environment is passed to the bwrap *process*. While bwrap's `--clearenv` controls what the sandboxed *child* sees, the bwrap process itself (briefly) has access to all environment variables. In practice this is low risk since bwrap is trusted, but it's cleaner to pass a minimal environment.

---

## INFO: Verified safe

- **`shellQuote` implementation is correct** — The single-quote wrapping with `'\''` escape is the standard POSIX-safe quoting approach. No injection risk.
- **nftables IP injection is safe** — `buildNftRules` only uses IPs that have passed through `net.ParseIP`, which validates format. No injection into the nft commands is possible.
- **Bridge mode disables port forwarding correctly** — The `-t none -u none -T none -U none` flags correctly prevent the sandbox from reaching host loopback services via pasta's port forwarding mechanism.
