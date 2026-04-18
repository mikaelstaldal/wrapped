# Issues

## Usability

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
