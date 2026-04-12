# Issues

## Security

#### DNS fallback in filtered network mode allows all DNS traffic

When DNS resolver IPs cannot be parsed from `/run/systemd/resolve/resolv.conf` or `/etc/resolv.conf`, the nftables rule falls back to allowing DNS queries to *any* destination on port 53. This defeats the purpose of `--network filtered`.

**Location:** `wrapped.go` (buildNftRules)  
**Recommendation:** Fail with an error if resolver IPs cannot be determined, rather than opening up all DNS.

#### nftables rules built by string concatenation

The filtered-mode nft script is assembled by concatenating strings including IP addresses. Although IPs are validated by `net.ParseIP`, the pattern is fragile and any future addition of unvalidated input could lead to command injection.

**Location:** `wrapped.go` (buildNftRules)  
**Recommendation:** Pass nft rules via stdin or construct them with separate arguments to avoid shell string concatenation.

---

#### TOCTOU race on mount path resolution

Mount paths are resolved with `filepath.EvalSymlinks` in the host process, but between that check and when bwrap actually mounts the path, a racing process could swap the path for a symlink to a forbidden location.

**Location:** `wrapped.go` (buildBaseBwrapArgs)  
**Recommendation:** Document this limitation; mitigating it fully requires OS-level support.

#### `--all-env` leaks sensitive host environment variables

When `--all-env` is used, all host environment variables (including `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `KUBECONFIG`, etc.) are passed into the sandbox without filtering.

**Location:** `wrapped.go` (buildBaseBwrapArgs)  
**Recommendation:** Document the risk prominently. Optionally strip well-known secret variable names even in `--all-env` mode.
---
-

## Usability

### High

#### `--symlink` documentation describes argument order backwards

The README (line 47) and CLI help text say "Create a symlink from SRC to DEST (specify as `--symlink DEST=SRC`)" — the prose is backwards. The left side is the symlink path (dest) and the right side is the target (src), so it should read "Create a symlink at DEST pointing to SRC".

**Location:** `README.md:47`, `cmd/wrapped/main.go:110`  
**Recommendation:** Fix the description to "Create a symlink at DEST pointing to SRC (repeatable, specify as `--symlink DEST=SRC`)".

---

### Medium

#### `--only-network` incompatibility checks happen too late

Most `--only-network` flag conflicts are validated inside `Wrapped()` rather than in Cobra's `PreRunE`, and only two pairs are declared with `MarkFlagsMutuallyExclusive`. Users discover incompatibilities only after the command runs.

**Location:** `wrapped.go:78–110`, `cmd/wrapped/main.go:121–122`  
**Recommendation:** Move all `--only-network` incompatibility checks to `PreRunE`, or add more `MarkFlagsMutuallyExclusive` pairs.

#### `--expose-tcp` / `--expose-udp` mode constraint validated at runtime

These flags silently accepted with any `--network` mode; the error "--expose-tcp and --expose-udp can only be used with --network bridge" only fires at runtime.

**Location:** `wrapped.go:115–116, 129–130, 137–139`  
**Recommendation:** Validate in `PreRunE` that `--expose-tcp`/`--expose-udp` require `--network bridge`.

#### `--allow-host` silently changes network mode

When `--allow-host` is given without an explicit `--network`, the code silently changes the network mode to `filtered`. This can surprise users who expected `none` (the default).

**Location:** `cmd/wrapped/main.go:62–68`  
**Recommendation:** Either print a note ("Note: --allow-host implies --network filtered"), or require the user to explicitly pass `--network filtered` alongside `--allow-host`.

#### No install hint when bwrap / pasta / nft is missing

When a required binary is not in PATH, the error is technically accurate but not actionable. E.g.: `exec: "bwrap": executable file not found in $PATH`.

**Location:** `wrapped.go:148, 216, 439, 448`  
**Recommendation:** Append a brief install hint to each missing-binary error, e.g. "install bubblewrap via your package manager".

#### No test coverage

The repository has no `*_test.go` files. CLI flag combinations, error messages, and mount validation logic cannot be regression-tested.

**Recommendation:** Add unit tests for flag validation, error message text, mount path resolution, and symlink parsing.

---

### Low

#### PATH reset is undocumented

When `--all-env` is not used, PATH is silently reset to `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`. This is not mentioned in the README or help text, and surprises users with custom PATH values.

**Location:** `wrapped.go:690`  
**Recommendation:** Document in README: "By default, PATH is reset to a standard value. Use `--all-env` to keep the host PATH, or `-e PATH=...` to set a custom one."

#### HOME directory error message lacks context

"cannot run from home directory or its parent directories" does not explain why the restriction exists or suggest an alternative.

**Location:** `wrapped.go:635`  
**Recommendation:** Extend the message, e.g.: "cannot run from home directory or its parent directories (use --mount or --mount-writable to explicitly opt in to specific paths)".

#### `--mount` vs `--current-dir` relationship undocumented

The README does not explain how `--mount` and `--current-dir` relate or whether they can be used together. The automatic mounting of the program binary itself is also only mentioned as a footnote.

**Location:** `README.md:43–45, 108–110`  
**Recommendation:** Add a short paragraph clarifying: what `--current-dir` does, that `--mount` mounts additional directories, and that the program binary is always mounted read-only.

#### `--workdir` interaction with `--current-dir` undocumented

The help text says only "Working directory". The behaviour — that it defaults to the current directory when `--current-dir` is set — is not described.

**Location:** `README.md:50`, `cmd/wrapped/main.go:112`  
**Recommendation:** Expand the description: "Working directory inside the sandbox. Defaults to the current directory when `--current-dir` is set."

#### Network mode help text lacks descriptions

`--network` help text lists only the four mode names without explaining what each does. Users must consult the README.

**Location:** `cmd/wrapped/main.go:105`  
**Recommendation:** Expand to e.g. "Network mode: none (isolated, default), host (unrestricted), bridge (sandboxed via pasta), filtered (bridge + nftables allowlist)".
