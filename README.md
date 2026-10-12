# MCP Config Audit

A dependency-free Python CLI that checks a few risky patterns in common MCP client JSON configurations. It reports findings without executing configured commands, contacting endpoints, or printing credential values.

## Checks

- **Literal credentials in `env`** — high severity; values are never included in output.
- **Remote plain HTTP URLs** — medium severity; loopback hosts are exempt.
- **Shell command mode** — flags shell executables invoked with `-c`, `/c`, or PowerShell command flags.
- **Floating `npx` / `uvx` package specs** — asks for exact version pins.

Supports JSON server maps named `mcpServers` and `servers`. These are review signals, not a complete security audit: the tool does not read machine environment variables, execute servers, inspect package contents, or parse every client-specific config format.

## Run

Requires Python 3.10+; no third-party dependencies.

```sh
python mcp_config_audit.py example.json
python mcp_config_audit.py path/to/mcp.json --json
python mcp_config_audit.py path/to/mcp.json --fail-on medium
python -m unittest -v
```

By default, the CLI exits with status 1 only for high-severity findings. `--fail-on medium` also fails on medium findings.

## Why this exists

MCP servers extend an AI client with local commands and remote tools. A static review can catch a few configuration mistakes before the client starts those tools. This checker intentionally stays small and does not claim to decide whether a server is trustworthy.

See [`example.json`](example.json) and the tests for reproducible cases.
