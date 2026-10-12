import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mcp_config_audit import audit_config


class AuditConfigTests(unittest.TestCase):
    def test_literal_secret_is_reported_without_echoing_value(self):
        secret = "123456:real-looking-bot-token"
        findings = audit_config({"mcpServers": {"telegram": {"command": "python", "env": {"BOT_TOKEN": secret}}}})
        self.assertEqual([item.rule for item in findings], ["literal-secret"])
        self.assertEqual(findings[0].severity, "high")
        self.assertNotIn(secret, json.dumps([item.__dict__ for item in findings]))

    def test_environment_placeholders_are_not_called_secrets(self):
        placeholder = "$" + "{API_KEY}"
        findings = audit_config({"mcpServers": {"safe": {"command": "python", "env": {"API_KEY": placeholder, "OTHER_TOKEN": "<set-me>"}}}})
        self.assertEqual(findings, [])

    def test_remote_http_warns_but_https_and_loopback_do_not(self):
        findings = audit_config({"servers": {
            "plain": {"url": "http://mcp.example.test/sse"},
            "tls": {"url": "https://mcp.example.test/sse"},
            "local": {"url": "http://localhost:8000/mcp"},
        }})
        self.assertEqual([(item.server, item.rule) for item in findings], [("plain", "cleartext-http")])

    def test_shell_command_mode_is_reported(self):
        findings = audit_config({"servers": {"shell": {"command": "/bin/bash", "args": ["-c", "python server.py"]}}})
        self.assertIn("shell-wrapper", [item.rule for item in findings])

    def test_npx_needs_exact_package_version(self):
        findings = audit_config({"mcpServers": {
            "floating": {"command": "npx", "args": ["--yes", "@demo/mcp-server"]},
            "pinned": {"command": "npx", "args": ["--yes", "@demo/mcp-server@1.2.3"]},
        }})
        self.assertEqual([(item.server, item.rule) for item in findings], [("floating", "unpinned-runner-package")])

    def test_uvx_accepts_exact_pip_version_pin(self):
        findings = audit_config({"mcpServers": {
            "floating": {"command": "uvx", "args": ["demo-mcp-server"]},
            "pinned": {"command": "uvx", "args": ["--from", "demo-mcp-server==1.2.3", "demo-mcp-server"]},
        }})
        self.assertEqual([(item.server, item.rule) for item in findings], [("floating", "unpinned-runner-package")])

    def test_unsupported_shape_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "mcpServers.*servers"):
            audit_config({"mcp_servers": {}})

    def test_cli_fails_on_high_severity_and_json_omits_secret(self):
        secret = "never-print-this-token"
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "mcp.json"
            config.write_text(json.dumps({"mcpServers": {"sample": {"command": "python", "env": {"API_TOKEN": secret}}}}), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("mcp_config_audit.py")), str(config), "--json"],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn('"rule": "literal-secret"', result.stdout)
        self.assertNotIn(secret, result.stdout)


if __name__ == "__main__":
    unittest.main()
