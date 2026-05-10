from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SERVER_NAME = "ettercap-mcp"
SERVER_VERSION = "0.1.0"

MAX_TIMEOUT_SECONDS = 600
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_LIVE_TIMEOUT_SECONDS = 45

TARGET_RE = re.compile(r"^[A-Za-z0-9:._,;/\-\[\]]*$")
MITM_RE = re.compile(r"^[A-Za-z0-9:._,;/\-\[\]]+$")
PLUGIN_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
PROTO_VALUES = {"tcp", "udp", "all"}
VISUAL_VALUES = {"hex", "ascii", "text", "ebcdic", "html", "utf8"}
UI_VALUES = {"text", "curses", "gtk"}
ETTERCAP_BINARY_NAMES = {"ettercap"}
ETTERFILTER_BINARY_NAMES = {"etterfilter"}
COMMAND_ARG_KEYS = {
    "binary",
    "execute",
    "acknowledge_authorized_network",
    "timeout_seconds",
    "ui",
    "targets",
    "mitm",
    "plugins",
    "plugin_list",
    "filters",
    "hex_dump",
    "ascii_dump",
    "iface",
    "lua_scripts",
    "lua_args",
    "secondary",
    "address",
    "netmask",
    "pcap_filter",
    "read_pcap",
    "write_pcap",
    "bridge",
    "proto",
    "visual",
    "regex",
    "script",
    "wifi_key",
    "log",
    "log_info",
    "log_msg",
    "load_hosts",
    "save_hosts",
    "config",
    "certificate",
    "private_key",
    "quiet",
    "superquiet",
    "silent",
    "nopromisc",
    "unoffensive",
    "broadcast",
    "reversed",
    "dns",
    "ext_headers",
    "compress",
    "only_mitm",
    "daemonize",
    "ip6scan",
    "nosslmitm",
}
PLAN_ARG_KEYS = COMMAND_ARG_KEYS - {"execute", "acknowledge_authorized_network", "timeout_seconds"}
OFFLINE_PCAP_ARG_KEYS = (COMMAND_ARG_KEYS - {"read_pcap", "acknowledge_authorized_network"}) | {"pcap"}
PLUGIN_ARG_KEYS = (COMMAND_ARG_KEYS - {"plugin_list"}) | {"use_plugin_list"}
PLUGIN_PLAN_ARG_KEYS = PLUGIN_ARG_KEYS - {"execute", "acknowledge_authorized_network", "timeout_seconds"}


class McpError(Exception):
    def __init__(self, message: str, code: int = -32000):
        super().__init__(message)
        self.code = code


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False


def log(message: str) -> None:
    print(f"[{SERVER_NAME}] {message}", file=sys.stderr, flush=True)


def json_dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def text_content(text: str) -> list[dict[str, Any]]:
    return [{"type": "text", "text": text}]


def tool_result(payload: Any) -> dict[str, Any]:
    if isinstance(payload, str):
        text = payload
    else:
        text = json.dumps(payload, indent=2, sort_keys=True)
    return {"content": text_content(text)}


def require_object(args: Any) -> dict[str, Any]:
    if args is None:
        return {}
    if not isinstance(args, dict):
        raise McpError("Tool arguments must be an object", -32602)
    return args


def clamp_timeout(value: Any, default: int = DEFAULT_TIMEOUT_SECONDS) -> int:
    if value is None:
        return default
    if not isinstance(value, int) or value <= 0:
        raise McpError("timeout_seconds must be a positive integer", -32602)
    return min(value, MAX_TIMEOUT_SECONDS)


def command_exists(binary: str) -> str | None:
    return shutil.which(binary)


def reject_unknown_args(args: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(args) - allowed)
    if unknown:
        raise McpError(f"Unsupported argument(s): {', '.join(unknown)}", -32602)


def validate_binary(binary: Any, default: str = "ettercap", allowed_names: set[str] | None = None) -> str:
    if binary is None:
        binary = default
    if not isinstance(binary, str) or not binary:
        raise McpError("binary must be a non-empty string", -32602)
    allowed_names = allowed_names or {default}
    if os.sep in binary:
        path = Path(binary)
        if not path.exists():
            raise McpError(f"binary does not exist: {binary}", -32602)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise McpError(f"binary is not executable: {binary}", -32602)
        if path.name not in allowed_names:
            raise McpError(f"binary must be one of: {', '.join(sorted(allowed_names))}", -32602)
        return str(path)
    if binary not in allowed_names:
        raise McpError(f"binary must be one of: {', '.join(sorted(allowed_names))}", -32602)
    resolved = command_exists(binary)
    if not resolved:
        raise McpError(f"Unable to find binary on PATH: {binary}", -32602)
    return resolved


def validate_string(value: Any, name: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise McpError(f"{name} must be a non-empty string", -32602)
    if "\x00" in value or "\n" in value or "\r" in value:
        raise McpError(f"{name} contains invalid control characters", -32602)
    if pattern and not pattern.fullmatch(value):
        raise McpError(f"{name} contains unsupported characters", -32602)
    return value


def validate_optional_path(value: Any, name: str, must_exist: bool = False) -> str | None:
    if value is None:
        return None
    path = validate_string(value, name)
    if must_exist and not Path(path).exists():
        raise McpError(f"{name} does not exist: {path}", -32602)
    return path


def validate_string_list(value: Any, name: str, pattern: re.Pattern[str] | None = None) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise McpError(f"{name} must be an array", -32602)
    return [validate_string(item, f"{name} item", pattern) for item in value]


def run_command(argv: list[str], timeout_seconds: int) -> CommandResult:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
        return CommandResult(
            argv=argv,
            returncode=proc.returncode,
            stdout=proc.stdout[-20000:],
            stderr=proc.stderr[-20000:],
            duration_seconds=round(time.monotonic() - started, 3),
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=argv,
            returncode=124,
            stdout=(exc.stdout or "")[-20000:] if isinstance(exc.stdout, str) else "",
            stderr=(exc.stderr or "")[-20000:] if isinstance(exc.stderr, str) else "",
            duration_seconds=round(time.monotonic() - started, 3),
            timed_out=True,
        )


def result_to_dict(result: CommandResult) -> dict[str, Any]:
    return {
        "argv": result.argv,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "duration_seconds": result.duration_seconds,
        "timed_out": result.timed_out,
    }


def parse_plugin_list(stdout: str) -> list[dict[str, str]]:
    plugins: list[dict[str, str]] = []
    for line in stdout.splitlines():
        match = re.match(r"^\s*([A-Za-z0-9_.-]+)\s+([0-9][A-Za-z0-9_.-]*)\s+(.+?)\s*$", line)
        if match:
            plugins.append(
                {
                    "name": match.group(1),
                    "version": match.group(2),
                    "description": match.group(3),
                }
            )
    return plugins


def build_ettercap_command(args: dict[str, Any], *, require_text_default: bool = True) -> list[str]:
    binary = validate_binary(args.get("binary"), "ettercap", ETTERCAP_BINARY_NAMES)
    argv = [binary]

    ui = args.get("ui", "text" if require_text_default else None)
    if ui is not None:
        ui = validate_string(ui, "ui")
        if ui not in UI_VALUES:
            raise McpError(f"ui must be one of: {', '.join(sorted(UI_VALUES))}", -32602)
        argv.append({"text": "-T", "curses": "-C", "gtk": "-G"}[ui])

    boolean_flags = {
        "quiet": "-q",
        "superquiet": "-Q",
        "silent": "-z",
        "nopromisc": "-p",
        "unoffensive": "-u",
        "broadcast": "-b",
        "reversed": "-R",
        "dns": "-d",
        "ext_headers": "-E",
        "compress": "-c",
        "only_mitm": "-o",
        "daemonize": "-D",
        "ip6scan": "-6",
        "nosslmitm": "-S",
    }
    for key, flag in boolean_flags.items():
        value = args.get(key)
        if value is not None and not isinstance(value, bool):
            raise McpError(f"{key} must be boolean", -32602)
        if value:
            argv.append(flag)

    value_flags = [
        ("iface", "-i", None, False),
        ("secondary", "-Y", None, False),
        ("address", "-A", None, False),
        ("netmask", "-n", None, False),
        ("pcap_filter", "-f", None, False),
        ("read_pcap", "-r", None, True),
        ("write_pcap", "-w", None, False),
        ("log", "-L", None, False),
        ("log_info", "-l", None, False),
        ("log_msg", "-m", None, False),
        ("load_hosts", "-j", None, True),
        ("save_hosts", "-k", None, False),
        ("config", "-a", None, True),
        ("certificate", "--certificate", None, True),
        ("private_key", "--private-key", None, True),
        ("regex", "-e", None, False),
        ("script", "-s", None, False),
        ("wifi_key", "-W", None, False),
        ("bridge", "-B", None, False),
        ("lua_scripts", "--lua-script", None, False),
        ("lua_args", "--lua-args", None, False),
    ]
    for key, flag, pattern, must_exist in value_flags:
        value = args.get(key)
        if value is not None:
            validator = validate_optional_path if key in {"read_pcap", "load_hosts", "config", "certificate", "private_key"} else validate_string
            if validator is validate_optional_path:
                item = validate_optional_path(value, key, must_exist=must_exist)
            else:
                item = validate_string(value, key, pattern)
            argv.extend([flag, item])

    proto = args.get("proto")
    if proto is not None:
        proto = validate_string(proto, "proto")
        if proto not in PROTO_VALUES:
            raise McpError(f"proto must be one of: {', '.join(sorted(PROTO_VALUES))}", -32602)
        argv.extend(["-t", proto])

    visual = args.get("visual")
    hex_dump = args.get("hex_dump")
    ascii_dump = args.get("ascii_dump")
    if hex_dump is not None and not isinstance(hex_dump, bool):
        raise McpError("hex_dump must be boolean", -32602)
    if ascii_dump is not None and not isinstance(ascii_dump, bool):
        raise McpError("ascii_dump must be boolean", -32602)
    if visual is not None and (hex_dump or ascii_dump):
        raise McpError("Use either visual or hex_dump/ascii_dump, not both", -32602)
    if hex_dump and ascii_dump:
        raise McpError("Use only one of hex_dump or ascii_dump", -32602)
    if hex_dump:
        visual = "hex"
    elif ascii_dump:
        visual = "ascii"
    if visual is not None:
        visual = validate_string(visual, "visual")
        if visual not in VISUAL_VALUES:
            raise McpError(f"visual must be one of: {', '.join(sorted(VISUAL_VALUES))}", -32602)
        argv.extend(["-V", visual])

    mitm = args.get("mitm")
    if mitm is not None:
        argv.extend(["-M", validate_string(mitm, "mitm", MITM_RE)])

    for plugin in validate_string_list(args.get("plugins"), "plugins", PLUGIN_RE):
        argv.extend(["-P", plugin])

    plugin_list = args.get("plugin_list")
    if plugin_list is not None:
        plugins = validate_string_list(plugin_list, "plugin_list", PLUGIN_RE)
        argv.extend(["--plugin-list", ",".join(plugins)])

    filters = args.get("filters")
    if filters is not None:
        if not isinstance(filters, list):
            raise McpError("filters must be an array", -32602)
        for filter_path in filters:
            argv.extend(["-F", validate_string(filter_path, "filter")])

    targets = validate_string_list(args.get("targets"), "targets", TARGET_RE)
    if len(targets) > 2:
        raise McpError("targets accepts at most two Ettercap targets", -32602)
    argv.extend(targets)
    return argv


def merge_plugin_args(args: dict[str, Any]) -> dict[str, Any]:
    plugins = validate_string_list(args.get("plugins"), "plugins", PLUGIN_RE)
    if not plugins:
        raise McpError("plugins must contain at least one plugin name", -32602)

    merged = dict(args)
    use_plugin_list = merged.pop("use_plugin_list", False)
    if not isinstance(use_plugin_list, bool):
        raise McpError("use_plugin_list must be boolean", -32602)
    if use_plugin_list:
        merged.pop("plugins", None)
        merged["plugin_list"] = plugins
    else:
        merged["plugins"] = plugins
    return merged


def is_live_or_invasive(args: dict[str, Any]) -> bool:
    return not args.get("read_pcap") or bool(args.get("mitm") or args.get("bridge"))


def require_authorization(args: dict[str, Any]) -> None:
    if args.get("acknowledge_authorized_network") is not True:
        raise McpError(
            "Live Ettercap operations require acknowledge_authorized_network=true. "
            "Only run on systems and networks where you have explicit authorization.",
            -32602,
        )


def tool_interfaces(args: dict[str, Any]) -> dict[str, Any]:
    reject_unknown_args(args, {"binary", "timeout_seconds"})
    binary = validate_binary(args.get("binary"), "ettercap", ETTERCAP_BINARY_NAMES)
    timeout = clamp_timeout(args.get("timeout_seconds"), 15)
    return tool_result(result_to_dict(run_command([binary, "-I"], timeout)))


def tool_help(args: dict[str, Any]) -> dict[str, Any]:
    reject_unknown_args(args, {"binary", "timeout_seconds"})
    binary = validate_binary(args.get("binary"), "ettercap", ETTERCAP_BINARY_NAMES)
    timeout = clamp_timeout(args.get("timeout_seconds"), 10)
    return tool_result(result_to_dict(run_command([binary, "--help"], timeout)))


def tool_version(args: dict[str, Any]) -> dict[str, Any]:
    reject_unknown_args(args, {"binary", "timeout_seconds"})
    binary = validate_binary(args.get("binary"), "ettercap", ETTERCAP_BINARY_NAMES)
    timeout = clamp_timeout(args.get("timeout_seconds"), 10)
    return tool_result(result_to_dict(run_command([binary, "--version"], timeout)))


def tool_plugins(args: dict[str, Any]) -> dict[str, Any]:
    reject_unknown_args(args, {"binary", "timeout_seconds"})
    binary = validate_binary(args.get("binary"), "ettercap", ETTERCAP_BINARY_NAMES)
    timeout = clamp_timeout(args.get("timeout_seconds"), 20)
    result = run_command([binary, "-P", "list"], timeout)
    payload = result_to_dict(result)
    payload["plugins"] = parse_plugin_list(result.stdout)
    payload["plugin_count"] = len(payload["plugins"])
    return tool_result(payload)


def tool_plan(args: dict[str, Any]) -> dict[str, Any]:
    reject_unknown_args(args, PLAN_ARG_KEYS)
    argv = build_ettercap_command(args)
    return tool_result({"argv": argv, "command_preview": shlex.join(argv), "executed": False})


def tool_run(args: dict[str, Any]) -> dict[str, Any]:
    reject_unknown_args(args, COMMAND_ARG_KEYS)
    execute = args.get("execute", False)
    if not isinstance(execute, bool):
        raise McpError("execute must be boolean", -32602)
    argv = build_ettercap_command(args)
    if not execute:
        return tool_result({"argv": argv, "command_preview": shlex.join(argv), "executed": False})
    if is_live_or_invasive(args):
        require_authorization(args)
    timeout = clamp_timeout(args.get("timeout_seconds"), DEFAULT_LIVE_TIMEOUT_SECONDS)
    return tool_result(result_to_dict(run_command(argv, timeout)))


def tool_plugin_plan(args: dict[str, Any]) -> dict[str, Any]:
    reject_unknown_args(args, PLUGIN_PLAN_ARG_KEYS)
    merged = merge_plugin_args(args)
    argv = build_ettercap_command(merged)
    return tool_result({"argv": argv, "command_preview": shlex.join(argv), "executed": False})


def tool_plugin_run(args: dict[str, Any]) -> dict[str, Any]:
    reject_unknown_args(args, PLUGIN_ARG_KEYS)
    merged = merge_plugin_args(args)
    return tool_run(merged)


def tool_offline_pcap(args: dict[str, Any]) -> dict[str, Any]:
    reject_unknown_args(args, OFFLINE_PCAP_ARG_KEYS)
    pcap = validate_optional_path(args.get("pcap"), "pcap", must_exist=True)
    merged = dict(args)
    merged["read_pcap"] = pcap
    merged.setdefault("ui", "text")
    merged.setdefault("quiet", True)
    merged.setdefault("silent", True)
    merged.setdefault("script", "q")
    merged.pop("pcap", None)
    argv = build_ettercap_command(merged)
    execute = args.get("execute", True)
    if not isinstance(execute, bool):
        raise McpError("execute must be boolean", -32602)
    if not execute:
        return tool_result({"argv": argv, "command_preview": shlex.join(argv), "executed": False})
    timeout = clamp_timeout(args.get("timeout_seconds"), 120)
    return tool_result(result_to_dict(run_command(argv, timeout)))


def tool_compile_filter(args: dict[str, Any]) -> dict[str, Any]:
    reject_unknown_args(args, {"binary", "source", "output", "execute", "timeout_seconds"})
    binary = validate_binary(args.get("binary"), "etterfilter", ETTERFILTER_BINARY_NAMES)
    source = validate_optional_path(args.get("source"), "source", must_exist=True)
    output = validate_optional_path(args.get("output"), "output", must_exist=False)
    if source is None or output is None:
        raise McpError("source and output are required", -32602)
    argv = [binary, source, "-o", output]
    execute = args.get("execute", True)
    if not isinstance(execute, bool):
        raise McpError("execute must be boolean", -32602)
    if not execute:
        return tool_result({"argv": argv, "command_preview": shlex.join(argv), "executed": False})
    timeout = clamp_timeout(args.get("timeout_seconds"), 30)
    return tool_result(result_to_dict(run_command(argv, timeout)))


def tool_write_filter(args: dict[str, Any]) -> dict[str, Any]:
    reject_unknown_args(args, {"path", "content", "overwrite"})
    path_value = validate_optional_path(args.get("path"), "path", must_exist=False)
    content = args.get("content")
    if not isinstance(content, str) or not content:
        raise McpError("content must be a non-empty string", -32602)
    if "\x00" in content:
        raise McpError("content contains invalid NUL characters", -32602)
    overwrite = args.get("overwrite", False)
    if not isinstance(overwrite, bool):
        raise McpError("overwrite must be boolean", -32602)
    if path_value is None:
        raise McpError("path is required", -32602)
    path = Path(path_value)
    if path.exists() and not overwrite:
        raise McpError(f"path already exists: {path}", -32602)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return tool_result({"path": str(path), "bytes_written": len(content.encode("utf-8"))})


def tool_target_help(_: dict[str, Any]) -> dict[str, Any]:
    return tool_result(
        {
            "target_syntax": "MAC/IPs/PORTs, or MAC/IPs/IPv6/PORTs when IPv6 is enabled",
            "examples": ["//80", "/10.0.0.1/", "/10.0.0.1-5;10.0.1.33/20-25,80,110", "//", "///"],
            "ipv6_note": "IPv6-enabled Ettercap builds use MAC/IPs/IPv6/PORTs, so an all-host empty target is /// instead of //.",
            "mitm_methods": {
                "arp": "arp, arp:remote, arp:oneway, or arp:remote,oneway",
                "icmp": "icmp:MAC/IP for ICMP redirect through a gateway",
                "dhcp": "dhcp:ip_pool/netmask/dns",
                "port": "port, port:remote, port:tree, or port:remote,tree",
                "ndp": "ndp, ndp:remote, or ndp:oneway when IPv6 support is enabled",
            },
            "safety": "Live interception can disrupt networks. Use unoffensive mode for passive gateway use and run only with authorization.",
            "plugins": "Use ettercap_plugins to list installed plugins, then ettercap_plugin_plan or ettercap_plugin_run to launch one or more plugins with normal Ettercap targets/options.",
        }
    )


ETTERCAP_COMMAND_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "binary": {"type": "string", "default": "ettercap"},
        "execute": {"type": "boolean", "default": False},
        "acknowledge_authorized_network": {"type": "boolean", "default": False},
        "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT_SECONDS},
        "ui": {"type": "string", "enum": sorted(UI_VALUES), "default": "text"},
        "targets": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 2,
            "description": "Ettercap target strings such as //, //80, or /192.168.1.1/.",
        },
        "mitm": {"type": "string", "description": "MITM method, for example arp:remote, dhcp:pool/netmask/dns, or ndp:remote."},
        "plugins": {"type": "array", "items": {"type": "string"}},
        "plugin_list": {"type": "array", "items": {"type": "string"}},
        "filters": {"type": "array", "items": {"type": "string"}},
        "hex_dump": {"type": "boolean", "description": "Convenience alias for visual=hex."},
        "ascii_dump": {"type": "boolean", "description": "Convenience alias for visual=ascii."},
        "iface": {"type": "string"},
        "lua_scripts": {"type": "string", "description": "Comma-separated Lua script list for --lua-script."},
        "lua_args": {"type": "string", "description": "Comma-separated Lua arguments for --lua-args."},
        "secondary": {"type": "string"},
        "address": {"type": "string"},
        "netmask": {"type": "string"},
        "pcap_filter": {"type": "string"},
        "read_pcap": {"type": "string"},
        "write_pcap": {"type": "string"},
        "bridge": {"type": "string"},
        "proto": {"type": "string", "enum": sorted(PROTO_VALUES)},
        "visual": {"type": "string", "enum": sorted(VISUAL_VALUES)},
        "regex": {"type": "string"},
        "script": {"type": "string"},
        "wifi_key": {"type": "string"},
        "log": {"type": "string"},
        "log_info": {"type": "string"},
        "log_msg": {"type": "string"},
        "load_hosts": {"type": "string"},
        "save_hosts": {"type": "string"},
        "config": {"type": "string"},
        "certificate": {"type": "string"},
        "private_key": {"type": "string"},
        "quiet": {"type": "boolean"},
        "superquiet": {"type": "boolean"},
        "silent": {"type": "boolean"},
        "nopromisc": {"type": "boolean"},
        "unoffensive": {"type": "boolean"},
        "broadcast": {"type": "boolean"},
        "reversed": {"type": "boolean"},
        "dns": {"type": "boolean"},
        "ext_headers": {"type": "boolean"},
        "compress": {"type": "boolean"},
        "only_mitm": {"type": "boolean"},
        "daemonize": {"type": "boolean"},
        "ip6scan": {"type": "boolean"},
        "nosslmitm": {"type": "boolean"},
    },
    "additionalProperties": False,
}

PLUGIN_COMMAND_SCHEMA: dict[str, Any] = {
    **ETTERCAP_COMMAND_SCHEMA,
    "required": ["plugins"],
    "properties": {
        **{
            k: v
            for k, v in ETTERCAP_COMMAND_SCHEMA["properties"].items()
            if k != "plugin_list"
        },
        "plugins": {
            "type": "array",
            "items": {"type": "string", "pattern": r"^[A-Za-z0-9_.-]+$"},
            "minItems": 1,
            "description": "One or more Ettercap plugin names, for example arp_cop, dns_spoof, find_conn, or finger.",
        },
        "use_plugin_list": {
            "type": "boolean",
            "default": False,
            "description": "Use --plugin-list instead of repeated -P options.",
        },
    },
    "additionalProperties": False,
}

OFFLINE_PCAP_SCHEMA: dict[str, Any] = {
    **ETTERCAP_COMMAND_SCHEMA,
    "required": ["pcap"],
    "properties": {
        "pcap": {"type": "string", "description": "Pcap file to analyze with Ettercap."},
        **{
            k: v
            for k, v in ETTERCAP_COMMAND_SCHEMA["properties"].items()
            if k not in {"read_pcap", "acknowledge_authorized_network"}
        },
        "execute": {"type": "boolean", "default": True},
    },
    "additionalProperties": False,
}


TOOLS: dict[str, dict[str, Any]] = {
    "ettercap_help": {
        "description": "Return Ettercap --help output.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {"type": "string", "default": "ettercap"},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT_SECONDS},
            },
            "additionalProperties": False,
        },
        "handler": tool_help,
    },
    "ettercap_version": {
        "description": "Return Ettercap --version output.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {"type": "string", "default": "ettercap"},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT_SECONDS},
            },
            "additionalProperties": False,
        },
        "handler": tool_version,
    },
    "ettercap_interfaces": {
        "description": "List capture interfaces using ettercap -I.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {"type": "string", "default": "ettercap"},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT_SECONDS},
            },
            "additionalProperties": False,
        },
        "handler": tool_interfaces,
    },
    "ettercap_plugins": {
        "description": "List available Ettercap plugins using ettercap -P list and return parsed plugin metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {"type": "string", "default": "ettercap"},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT_SECONDS},
            },
            "additionalProperties": False,
        },
        "handler": tool_plugins,
    },
    "ettercap_plugin_plan": {
        "description": "Build an Ettercap plugin command without executing it. Supports all normal Ettercap targets/options.",
        "inputSchema": {
            **PLUGIN_COMMAND_SCHEMA,
            "properties": {
                k: v
                for k, v in PLUGIN_COMMAND_SCHEMA["properties"].items()
                if k not in {"execute", "acknowledge_authorized_network", "timeout_seconds"}
            },
        },
        "handler": tool_plugin_plan,
    },
    "ettercap_plugin_run": {
        "description": "Run or dry-run one or more Ettercap plugins with normal Ettercap targets/options and safety gates.",
        "inputSchema": PLUGIN_COMMAND_SCHEMA,
        "handler": tool_plugin_run,
    },
    "ettercap_plan": {
        "description": "Build an Ettercap command from structured arguments without executing it.",
        "inputSchema": {**ETTERCAP_COMMAND_SCHEMA, "properties": {k: v for k, v in ETTERCAP_COMMAND_SCHEMA["properties"].items() if k not in {"execute", "acknowledge_authorized_network", "timeout_seconds"}}},
        "handler": tool_plan,
    },
    "ettercap_run": {
        "description": "Run or dry-run a bounded Ettercap command. Live operations require explicit authorization acknowledgement.",
        "inputSchema": ETTERCAP_COMMAND_SCHEMA,
        "handler": tool_run,
    },
    "ettercap_offline_pcap": {
        "description": "Analyze a pcap file with Ettercap text mode. Defaults to execution because it is offline.",
        "inputSchema": OFFLINE_PCAP_SCHEMA,
        "handler": tool_offline_pcap,
    },
    "ettercap_compile_filter": {
        "description": "Compile an Ettercap filter source file with etterfilter.",
        "inputSchema": {
            "type": "object",
            "required": ["source", "output"],
            "properties": {
                "binary": {"type": "string", "default": "etterfilter"},
                "source": {"type": "string"},
                "output": {"type": "string"},
                "execute": {"type": "boolean", "default": True},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT_SECONDS},
            },
            "additionalProperties": False,
        },
        "handler": tool_compile_filter,
    },
    "ettercap_write_filter": {
        "description": "Write an Ettercap filter source file, replacing shell heredoc workflows.",
        "inputSchema": {
            "type": "object",
            "required": ["path", "content"],
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
                "overwrite": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
        "handler": tool_write_filter,
    },
    "ettercap_target_help": {
        "description": "Return concise Ettercap target syntax and MITM method help.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": tool_target_help,
    },
}


def mcp_tools() -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "description": spec["description"],
            "inputSchema": spec["inputSchema"],
        }
        for name, spec in TOOLS.items()
    ]


def handle_request(request: dict[str, Any]) -> dict[str, Any] | None:
    method = request.get("method")
    request_id = request.get("id")

    try:
        if method == "initialize":
            result = {
                "protocolVersion": request.get("params", {}).get("protocolVersion", "2024-11-05"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            }
        elif method == "notifications/initialized":
            return None
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": mcp_tools()}
        elif method == "tools/call":
            params = request.get("params") or {}
            name = params.get("name")
            if name not in TOOLS:
                raise McpError(f"Unknown tool: {name}", -32602)
            args = require_object(params.get("arguments"))
            result = TOOLS[name]["handler"](args)
        else:
            raise McpError(f"Method not found: {method}", -32601)

        if request_id is None:
            return None
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except McpError as exc:
        if request_id is None:
            log(str(exc))
            return None
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": exc.code, "message": str(exc)}}
    except Exception as exc:  # Defensive: keep the MCP server alive after tool failures.
        log(f"Unhandled error: {exc}")
        if request_id is None:
            return None
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": str(exc)}}


def serve() -> None:
    log("started")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}
            print(json_dumps(response), flush=True)
            continue
        response = handle_request(request)
        if response is not None:
            print(json_dumps(response), flush=True)


def main() -> None:
    serve()


if __name__ == "__main__":
    main()
