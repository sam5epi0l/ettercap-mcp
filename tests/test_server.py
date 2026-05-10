import json
import stat
import tempfile
import unittest
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ettercap_mcp.server import (
    McpError,
    build_ettercap_command,
    parse_plugin_list,
    tool_offline_pcap,
    tool_plugin_plan,
    tool_plugin_run,
    tool_run,
    tool_write_filter,
)


def fake_binary(name: str, directory: str) -> str:
    path = Path(directory) / name
    path.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


class EttercapMcpTests(unittest.TestCase):
    def test_builds_structured_command(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = fake_binary("ettercap", tmpdir)
            argv = build_ettercap_command(
                {
                    "binary": binary,
                    "ui": "text",
                    "silent": True,
                    "mitm": "arp:remote",
                    "targets": ["/192.168.1.1/", "/192.168.1.2-10/"],
                }
            )
        self.assertEqual(
            argv,
            [
                binary,
                "-T",
                "-z",
                "-M",
                "arp:remote",
                "/192.168.1.1/",
                "/192.168.1.2-10/",
            ],
        )

    def test_rejects_invalid_target_characters(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = fake_binary("ettercap", tmpdir)
            with self.assertRaises(McpError):
                build_ettercap_command({"binary": binary, "targets": ["$(id)"]})

    def test_rejects_non_ettercap_binary(self):
        with self.assertRaises(McpError):
            build_ettercap_command({"binary": "/bin/echo", "targets": ["//"]})

    def test_live_execute_requires_acknowledgement(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = fake_binary("ettercap", tmpdir)
            with self.assertRaises(McpError):
                tool_run({"binary": binary, "execute": True, "targets": ["//"]})

    def test_dry_run_returns_mcp_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = fake_binary("ettercap", tmpdir)
            result = tool_run({"binary": binary, "execute": False, "targets": ["//"]})
        payload = json.loads(result["content"][0]["text"])
        self.assertFalse(payload["executed"])
        self.assertEqual(payload["argv"][-1], "//")

    def test_offline_pcap_defaults_to_quit_script(self):
        with tempfile.TemporaryDirectory() as tmpdir, tempfile.NamedTemporaryFile(suffix=".pcap") as pcap:
            binary = fake_binary("ettercap", tmpdir)
            result = tool_offline_pcap({"binary": binary, "pcap": pcap.name, "execute": False})
        payload = json.loads(result["content"][0]["text"])
        self.assertIn("-s", payload["argv"])
        self.assertIn("q", payload["argv"])

    def test_plugin_plan_repeated_p_flags(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = fake_binary("ettercap", tmpdir)
            result = tool_plugin_plan(
                {
                    "binary": binary,
                    "plugins": ["arp_cop", "find_conn"],
                    "quiet": True,
                    "silent": True,
                    "targets": ["///"],
                }
            )
        payload = json.loads(result["content"][0]["text"])
        self.assertEqual(payload["argv"].count("-P"), 2)
        self.assertIn("arp_cop", payload["argv"])
        self.assertIn("find_conn", payload["argv"])

    def test_plugin_plan_plugin_list_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = fake_binary("ettercap", tmpdir)
            result = tool_plugin_plan(
                {
                    "binary": binary,
                    "plugins": ["arp_cop", "find_conn"],
                    "use_plugin_list": True,
                    "targets": ["///"],
                }
            )
        payload = json.loads(result["content"][0]["text"])
        self.assertIn("--plugin-list", payload["argv"])
        self.assertIn("arp_cop,find_conn", payload["argv"])

    def test_plugin_run_requires_acknowledgement_for_live_execution(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = fake_binary("ettercap", tmpdir)
            with self.assertRaises(McpError):
                tool_plugin_run({"binary": binary, "plugins": ["arp_cop"], "execute": True, "targets": ["///"]})

    def test_visual_aliases_and_only_mitm(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = fake_binary("ettercap", tmpdir)
            argv = build_ettercap_command(
                {
                    "binary": binary,
                    "ui": "text",
                    "hex_dump": True,
                    "only_mitm": True,
                    "lua_scripts": "script.lua",
                    "lua_args": "n=v",
                }
            )
        self.assertIn("-o", argv)
        self.assertIn("-V", argv)
        self.assertIn("hex", argv)
        self.assertIn("--lua-script", argv)
        self.assertIn("--lua-args", argv)

    def test_rejects_conflicting_visual_aliases(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = fake_binary("ettercap", tmpdir)
            with self.assertRaises(McpError):
                build_ettercap_command({"binary": binary, "hex_dump": True, "ascii_dump": True})

    def test_write_filter_refuses_overwrite_by_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "tcp.ecf"
            result = tool_write_filter(
                {
                    "path": str(path),
                    "content": 'if (ip.proto == TCP) {\n   msg("TCP Packet Detected\\n");\n}\n',
                }
            )
            payload = json.loads(result["content"][0]["text"])
            self.assertEqual(payload["path"], str(path))
            with self.assertRaises(McpError):
                tool_write_filter({"path": str(path), "content": "msg(\"x\");\n"})

    def test_parse_plugin_list(self):
        plugins = parse_plugin_list(
            """
Available plugins :

         arp_cop  1.1  Report suspicious ARP activity
       dns_spoof  1.3  Sends spoofed dns replies
"""
        )
        self.assertEqual(plugins[0]["name"], "arp_cop")
        self.assertEqual(plugins[1]["description"], "Sends spoofed dns replies")


if __name__ == "__main__":
    unittest.main()
