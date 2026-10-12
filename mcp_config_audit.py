#!/usr/bin/env python3
"""Small, dependency-free checks for common MCP client JSON configurations."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SECRET_NAME = re.compile(r"(?:token|secret|password|api[_-]?key|access[_-]?key|private[_-]?key|credential)", re.IGNORECASE)
PLACEHOLDER = re.compile(r"^(?:\$\{[^}]+\}|<[^>]+>|your[-_ ].*|example(?:[-_ ].*)?|changeme|replace[-_ ]?me|dummy)$", re.IGNORECASE)
VERSION = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\Z")
SHELLS = {"sh", "bash", "zsh", "fish", "dash", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
SHELL_FLAGS = {"-c", "/c", "-command", "-encodedcommand"}
FLAG_WITH_VALUE = {"--package", "-p", "--from"}
SKIP_FLAGS = {"-y", "--yes", "--quiet", "-q", "--no-progress"}


@dataclass(frozen=True)
class Finding:
    server: str
    field: str
    rule: str
    severity: str
    message: str


def _is_literal_secret(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    return PLACEHOLDER.search(value) is None


def _is_pinned_spec(spec: str, runner: str) -> bool:
    if runner.startswith("npx"):
        if spec.startswith("@"):
            slash = spec.find("/")
            version_sep = spec.rfind("@")
            if slash < 0 or version_sep <= slash:
                return False
            version = spec[version_sep + 1 :]
        else:
            if "@" not in spec:
                return False
            version = spec.rsplit("@", 1)[1]
        return VERSION.fullmatch(version) is not None

    if "==" not in spec:
        return False
    _, version = spec.rsplit("==", 1)
    return VERSION.fullmatch(version) is not None


def _runner_package_spec(args: list[str]) -> str | None:
    index = 0
    while index < len(args):
        token = args[index]
        if token in FLAG_WITH_VALUE:
            return args[index + 1] if index + 1 < len(args) else None
        if token in SKIP_FLAGS or token.startswith("-"):
            index += 1
            continue
        return token
    return None


def _findings_for_server(name: str, config: dict[str, Any], root: str) -> list[Finding]:
    findings: list[Finding] = []
    prefix = f"{root}.{name}"

    env = config.get("env")
    if isinstance(env, dict):
        for key, value in env.items():
            if SECRET_NAME.search(str(key)) and _is_literal_secret(value):
                findings.append(Finding(
                    name,
                    f"{prefix}.env.{key}",
                    "literal-secret",
                    "high",
                    "A credential-like environment variable has a literal value; the value is intentionally not shown.",
                ))

    remote_url = config.get("url")
    if isinstance(remote_url, str):
        parsed = urlsplit(remote_url)
        host = (parsed.hostname or "").lower()
        loopback = host in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme.lower() == "http" and not loopback:
            findings.append(Finding(
                name,
                f"{prefix}.url",
                "cleartext-http",
                "medium",
                "The remote MCP endpoint uses HTTP; traffic is not protected by TLS.",
            ))

    command = config.get("command")
    args = config.get("args", [])
    if isinstance(command, str):
        executable = Path(command.replace("\\", "/")).name.lower()
        normalized_args = [str(arg).lower() for arg in args] if isinstance(args, list) else []
        if executable in SHELLS and any(arg in SHELL_FLAGS for arg in normalized_args):
            findings.append(Finding(
                name,
                f"{prefix}.command",
                "shell-wrapper",
                "medium",
                "The server command passes a command string to a shell; review quoting and the source of interpolated values.",
            ))

        if executable in {"npx", "npx.cmd", "uvx", "uvx.exe"}:
            package = _runner_package_spec([str(arg) for arg in args] if isinstance(args, list) else [])
            if package and not _is_pinned_spec(package, executable):
                findings.append(Finding(
                    name,
                    f"{prefix}.args",
                    "unpinned-runner-package",
                    "medium",
                    f"The {executable} package spec does not pin an exact version.",
                ))

    return findings


def audit_config(document: Any) -> list[Finding]:
    """Audit common mcpServers and VS Code servers JSON sections."""
    if not isinstance(document, dict):
        raise ValueError("The JSON document must be an object.")

    findings: list[Finding] = []
    recognized = False
    for root in ("mcpServers", "servers"):
        servers = document.get(root)
        if not isinstance(servers, dict):
            continue
        recognized = True
        for name, server in servers.items():
            if isinstance(server, dict):
                findings.extend(_findings_for_server(str(name), server, root))

    if not recognized:
        raise ValueError("No supported server map found; expected mcpServers or servers.")

    return sorted(findings, key=lambda finding: (finding.server, finding.rule, finding.field))


def _exit_status(findings: list[Finding], fail_on: str) -> int:
    if fail_on == "never":
        return 0
    if fail_on == "high":
        return int(any(item.severity == "high" for item in findings))
    return int(bool(findings))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit common MCP server JSON configurations.")
    parser.add_argument("config", type=Path, help="Path to an MCP client JSON configuration")
    parser.add_argument("--json", action="store_true", help="Print findings as JSON")
    parser.add_argument("--fail-on", choices=("high", "medium", "never"), default="high",
                        help="Exit with status 1 at this severity threshold (default: high)")
    args = parser.parse_args(argv)

    try:
        document = json.loads(args.config.read_text(encoding="utf-8"))
        findings = audit_config(document)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"mcp-config-audit: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([asdict(item) for item in findings], ensure_ascii=False, indent=2))
    elif not findings:
        print("No findings in the supported checks.")
    else:
        for item in findings:
            print(f"{item.severity.upper():6} {item.rule:24} {item.field}: {item.message}")
        print(f"\n{len(findings)} finding(s).")

    return _exit_status(findings, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
