# wrapped

Run a program in a sandbox using [bubblewrap](https://github.com/containers/bubblewrap).

## Inspiration

The network sandboxing is inspired by [Anthropic's sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime). 
Although it is quite inconvenient for a general sandboxing tool to be implemented in 
TypeScript and require a JavaScript runtime. So this program is implemented in Go and can produce a standalone statically 
linked binary.

## Prerequisites

This is a Linux program, might also work in WSL in Windows (currently not tested). 

Requires bubblewrap to be installed and the `bwrap` command to be in `PATH`.

The `--allow-host` feature additionally requires `socat` to be installed and in `PATH`.

## Install

```bash
go install -tags netgo github.com/mikaelstaldal/wrapped/cmd/wrapped@latest
```

## Usage

```
wrapped [flags] -- program [arguments...]
```

### Flags

| Flag | Description |
|------|-------------|
| `--network` | Enable full network access |
| `--allow-host <host>` | Allow network access to a specific host (repeatable, supports `*.example.com` wildcards) |
| `--current-dir` | Mount the current directory read-only |
| `--current-dir-writable` | Mount the current directory writable |
| `--mount <path>` | Mount additional directory read-only (repeatable) |
| `--mount-writable <path>` | Mount additional directory writable (repeatable) |
| `-e`, `--env <VAR[=value]>` | Pass environment variable (repeatable) |
| `-w`, `--workdir <path>` | Working directory inside the sandbox |
| `--apparmor <profile>` | Run program with an AppArmor profile |

### Examples

Run a program with no network and no access to the filesystem (beyond `/usr` and `/etc`):
```bash
wrapped program arg1 arg2
```

Run with full network access:
```bash
wrapped --network curl https://example.com
```

Allow network access only to specific hosts:
```bash
wrapped --allow-host example.com --allow-host '*.googleapis.com' curl https://example.com
```

Mount the current directory writable and pass environment variables:
```bash
wrapped --current-dir-writable -e HOME -e MY_VAR=value program
```

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
