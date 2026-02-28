# wrapped

Run a program in a sandbox using Linux namespaces.

## Inspiration

The filtered network sandboxing (`--network filtered`) is inspired by [Anthropic's sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime). 
Although it is quite inconvenient for a general sandboxing tool to be implemented in TypeScript and require a JavaScript runtime. 
So this program is implemented in Go and can produce a standalone statically linked binary.

## Prerequisites

This is a Linux program, might also work in WSL in Windows (currently not tested). 

Requires [bubblewrap](https://github.com/containers/bubblewrap) to be installed and the `bwrap` command to be in `PATH`.

The `--network bridge` mode requires [pasta](https://passt.top/) (from the passt project) to be installed and in `PATH`.

The `--network filtered` mode (used with `--allow-host` and `--allow-all-hosts`) requires `socat` to be installed and in `PATH`.

## Install

```bash
go install -tags netgo github.com/mikaelstaldal/wrapped/cmd/wrapped@latest
```

## Build

To build with version information baked in:

```bash
go build -tags netgo -ldflags "-X main.version=1.0.0 -X main.commit=$(git rev-parse --short HEAD)" -o wrapped ./cmd/wrapped
```

Without `-ldflags`, `wrapped --version` prints `dev`.

## Usage

```
wrapped [flags] -- program [arguments...]
```

### Flags

| Flag                        | Description                                                                                                            |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------|
| `--network <mode>`          | Network mode: `none` (default), `host`, `bridge`, or `filtered`                                                        |
| `--allow-host <host>`       | Allow network access to a specific host (repeatable, supports `*.example.com` wildcards, implies `--network filtered`) |
| `--allow-all-hosts`         | Allow network access to all hosts (implies `--network filtered`, use `--deny-host` to exclude specific hosts)          |
| `--deny-host <host>`        | Deny network access to a specific host when using `--allow-all-hosts` (repeatable, supports `*.example.com` wildcards) |
| `--current-dir`             | Mount the current directory read-only                                                                                  |
| `--current-dir-writable`    | Mount the current directory writable                                                                                   |
| `--mount <path>`            | Mount additional directory read-only (repeatable)                                                                      |
| `--mount-writable <path>`   | Mount additional directory writable (repeatable)                                                                       |
| `-e`, `--env <VAR[=value]>` | Pass environment variable (repeatable)                                                                                 |
| `-w`, `--workdir <path>`    | Working directory inside the sandbox                                                                                   |
| `--network-log <file>`      | Log all network connections to a file (requires `--network filtered`)                                                  |
| `--apparmor <profile>`      | Run program with an AppArmor profile                                                                                   |
| `--only-network`            | Only sandbox the network, leave filesystem untouched                                                                   |

#### Network modes

| Mode       | Description                                                                                                                       |
|------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `none`     | No network access (default). The network namespace is fully isolated.                                                             |
| `host`     | Full network access with no isolation.                                                                                            |
| `bridge`   | Transparent network access via [pasta](https://passt.top/). The sandbox has its own network namespace but can reach the Internet. |
| `filtered` | Network access filtered by domain via HTTP/SOCKS5 proxies. Use with `--allow-host` or `--allow-all-hosts`. Requires `socat`.      |

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

Allow network access only to specific hosts:
```bash
wrapped --allow-host example.com --allow-host '*.googleapis.com' curl https://example.com
```

Allow network access to all hosts except specific ones:
```bash
wrapped --allow-all-hosts --deny-host '*.evil.com' curl https://example.com
```

Mount the current directory writable and pass environment variables:
```bash
wrapped --current-dir-writable -e HOME -e MY_VAR=value program
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

### Note

The directory where the program to run is in is implicitly mounted read-only if not explicitly mentioned with 
`--mount` or `--mount-writable`, which means that the program to run will be able to read other files in that directory.

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
