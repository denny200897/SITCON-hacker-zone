# Aegis

**Code Security Review Agent Harness** — an interactive CLI that scans a
repository, has an LLM reviewer investigate the code with read-only tools,
mechanically proves findings in a sandbox, and writes a report.

## Install

### macOS / Linux

```sh
curl -fsSL https://raw.githubusercontent.com/denny200897/SITCON-hacker-zone/main/scripts/install.sh | sh
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/denny200897/SITCON-hacker-zone/main/scripts/install.ps1 | iex
```

The installer downloads the right binary for your OS/CPU from the latest
[release](https://github.com/denny200897/SITCON-hacker-zone/releases), puts it
on your `PATH`, and then you just run:

```sh
aegis
```

That launches the interactive interface. Pick an action with `↑↓` and `Enter`
(no commands to memorize), or type a command directly.

<details>
<summary>Install options</summary>

Environment variables understood by both installers:

| Variable | Meaning |
| --- | --- |
| `AEGIS_VERSION` | Install a specific release tag instead of the latest (e.g. `v0.1.0`) |
| `AEGIS_INSTALL_DIR` | Install to a custom directory |
| `AEGIS_REPO` | Download from a different `owner/repo` |

</details>

## First run

Inside `aegis`, use the menu (or type the commands):

1. **Providers & API keys → Add a provider** (Anthropic / OpenAI-compatible / OpenRouter)
2. **Providers & API keys → Set an API key** (entered hidden, never stored in plaintext)
3. **Model routing → Set a model** (`all` sets every role at once)
4. **Status** / **Doctor** to check providers and Docker
5. **Review a repository** → point it at a path

A running review streams the agent's thinking, tool calls, and results, then
writes `report.md`, `findings.json`, and `findings.sarif` under the target
repo's `out/run-<timestamp>/`.

**Requirements at runtime:** a Docker daemon (for the proof sandbox) and at
least one configured LLM provider + API key. `semgrep` is optional.

## Build from source

```sh
go build -o ./bin/aegis ./cmd/aegis
```

Requires Go 1.26+. The build is pure Go (no CGO), so it cross-compiles with
`GOOS`/`GOARCH` out of the box.

See [docs/USAGE.md](docs/USAGE.md) for the full workflow, and
[SPEC.md](SPEC.md) for the design.
