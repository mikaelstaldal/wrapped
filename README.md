# wrapped

Run a program in a sandbox using Linux namespaces.

## Prerequisites

This is a Linux program, might also work in WSL in Windows (currently not tested). 

Requires [bubblewrap](https://github.com/containers/bubblewrap) to be installed and the `bwrap` command to be in `PATH`.

The `--network bridge` mode requires [pasta](https://passt.top/) (from the passt project) to be installed and in `PATH`.

The `--network filtered` mode (used with `--allow-host`) requires [pasta](https://passt.top/) and `nft` (from the nftables project) to be installed and in `PATH`.

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
| `--allow-host <host>`       | Allow network access to a specific host (repeatable, implies `--network filtered`)                                     |
| `--current-dir`             | Mount the current directory read-only                                                                                  |
| `--current-dir-writable`    | Mount the current directory writable                                                                                   |
| `--mount <path>`            | Mount additional directory read-only (repeatable)                                                                      |
| `--mount-writable <path>`   | Mount additional directory writable (repeatable)                                                                       |
| `--symlink <dest>=<src>`    | Create a symlink from SRC to DEST (repeatable, specify as `--symlink DEST=SRC`)                                        |
| `--tmpfs <path>`            | Mount a tmpfs at the given path (repeatable)                                                                           |
| `-e`, `--env <VAR[=value]>` | Pass environment variable (repeatable)                                                                                 |
| `-w`, `--workdir <path>`    | Working directory inside the sandbox                                                                                   |
| `--apparmor <profile>`      | Run program with an AppArmor profile                                                                                   |
| `--only-network`            | Only sandbox the network, leave filesystem untouched                                                                   |

#### Network modes

| Mode       | Description                                                                                                                                                    |
|------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `none`     | No network access (default). The network namespace is fully isolated.                                                                                          |
| `host`     | Full network access with no isolation.                                                                                                                         |
| `bridge`   | Transparent network access via [pasta](https://passt.top/). The sandbox has its own network namespace and cannot reach localhost, but can reach the Internet.  |
| `filtered` | Network access filtered by IP via nftables rules inside a pasta namespace. Hosts are resolved at startup. Use with `--allow-host`. Requires `pasta` and `nft`. |

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

The program to run (the file only, not the directory) is implicitly mounted read-only if not covered by any 
`--mount` or `--mount-writable` or automatic mount (`/usr`, `/etc`).

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
