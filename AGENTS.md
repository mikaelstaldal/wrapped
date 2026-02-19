# Coding agent instructions

This file provides guidance to coding agents when working with code in this repository.

## Project Overview

**wrapped** is a CLI tool that runs programs in a sandbox using [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`). It requires `bwrap` to be installed and in `PATH`. Linux only. 
The `--allow-host` feature additionally requires `socat`.

The project is implemented in **Go**:
-  — library in `wrapped.go` and `proxy.go`, CLI in `cmd/wrapped/main.go`

## Build & Run

```bash
go build -o wrapped ./cmd/wrapped
go vet ./...
go test ./...
```

## Architecture

The Go implementation is structured as a library + CLI:
- `wrapped.go` — `package wrapped` library exposing `Wrapped()`. Builds bwrap arguments, then either `syscall.Exec`s bwrap (default) or runs it as a child process (filtered network mode).
- `proxy.go` — HTTP and SOCKS5 proxy servers with domain filtering for `--allow-host`. Uses `things-go/go-socks5` for the SOCKS5 server. Shared `matchHost()` function supports exact and wildcard (`*.example.com`) matching.
- `cmd/wrapped/main.go` — `package main` CLI using `cobra` for argument parsing. Calls `wrapped.Wrapped()`.

Key design: the tool constructs a `bwrap` command line with namespace isolation flags (`--unshare-user`, `--unshare-ipc`, `--unshare-pid`, etc.), then execs into it. The sandbox provides:
- Read-only bind mounts of `/usr`, `/etc`
- Symlinks for `/lib`, `/lib64`, `/bin`, `/sbin`
- Cleared environment with selective passthrough
- Optional network access, current directory mounting (read-only or writable), and extra mount points
- Optional AppArmor profile enforcement

### Network modes

1. **No network** (default): `--unshare-net` isolates the network namespace completely.
2. **Full network** (`--network`): no network isolation, DNS resolution via `/run/systemd/resolve` if available.
3. **Filtered network** (`--allow-host`): network namespace is isolated, but HTTP/SOCKS5 proxy servers on the host filter traffic by domain. Unix domain sockets + socat bridge the proxies into the sandbox. Proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, etc.) are set automatically. Mutually exclusive with `--network`.

### Documentation

Keep the documentation in `README.md` up-to-date with command line options etc.
