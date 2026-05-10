# Ettercap MCP Server

This repository contains a dependency-free stdio MCP server for
[Ettercap](https://github.com/Ettercap/ettercap). It exposes safe wrappers for
common Ettercap workflows: interface discovery, plugin listing and execution,
offline pcap analysis, filter compilation, command planning, and controlled
execution.

This project is not affiliated with the Ettercap project.

Ettercap can perform invasive network interception. The server defaults to
planning commands without running them. Live capture or MITM-capable operations
require `execute: true` and `acknowledge_authorized_network: true` in the tool
arguments. Use it only on systems and networks where you have authorization.

## Requirements

- Python 3.10+
- Ettercap installed and available as `ettercap`
- Optional: `etterfilter` for compiling filters

## Run

```bash
PYTHONPATH=src python3 -m ettercap_mcp.server
```

or after installation:

```bash
ettercap-mcp
```

Install locally from a clone:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

## MCP Client Configuration

Example:

```json
{
  "mcpServers": {
    "ettercap": {
      "command": "python3",
      "args": ["src/ettercap_mcp/server.py"],
      "cwd": "/path/to/ettercap-mcp"
    }
  }
}
```

Live capture usually requires elevated privileges because Ettercap opens link
layer sockets. Start the MCP server with the same privileges you would use for
Ettercap itself.

Target syntax depends on the Ettercap build. IPv4-only builds use
`MAC/IPs/PORTs`; IPv6-enabled builds use `MAC/IPs/IPv6/PORTs`, so the empty
all-host target is `///` on those builds.

## Tools

- `ettercap_help`: show `ettercap --help`.
- `ettercap_version`: show `ettercap --version`.
- `ettercap_interfaces`: list capture interfaces via `ettercap -I`.
- `ettercap_plugins`: list available Ettercap plugins and parsed metadata.
- `ettercap_plugin_plan`: build a plugin-enabled Ettercap command without running it.
- `ettercap_plugin_run`: run or dry-run one or more plugins with safety gates.
- `ettercap_plan`: build an Ettercap command without running it.
- `ettercap_run`: run a bounded Ettercap command with safety gates.
- `ettercap_offline_pcap`: analyze a pcap file with text mode Ettercap.
- `ettercap_write_filter`: write a filter source file without shell heredocs.
- `ettercap_compile_filter`: compile an Ettercap filter using `etterfilter`.
- `ettercap_target_help`: explain target and MITM method syntax.

Plugin execution uses Ettercap's native plugin flags. By default,
`ettercap_plugin_run` emits repeated `-P <plugin>` options. Set
`use_plugin_list: true` to emit `--plugin-list plugin1,plugin2` instead.
All normal Ettercap arguments such as `iface`, `targets`, `mitm`, `read_pcap`,
`filters`, `quiet`, `superquiet`, `silent`, and `script` remain available.

Example plugin dry-run arguments:

```json
{
  "plugins": ["arp_cop", "find_conn"],
  "use_plugin_list": true,
  "quiet": true,
  "silent": true,
  "targets": ["///"]
}
```

To actually run a live plugin session, add `execute: true` and
`acknowledge_authorized_network: true`.

## Corrections for Common Older Examples

- Interface listing is `ettercap -I`, not `ettercap -i`.
- `-i` selects an interface, for example `-i eth0`.
- `-v` prints the version; it is not verbose mode.
- `-V` requires a format such as `hex`, `ascii`, `text`, `html`, `utf8`, or `ebcdic`.
- `-n` sets a netmask. DNS resolution is off unless `-d` is provided.
- Current Ettercap does not expose `-X` or `-A`; use `visual: "hex"`/`hex_dump: true` or `visual: "ascii"`/`ascii_dump: true`.
- Multiple plugins should be repeated `-P plugin` values or `--plugin-list plugin1,plugin2`.

## Notes

The server speaks JSON-RPC 2.0 over stdin/stdout and logs diagnostics to stderr.
It does not use a shell when invoking Ettercap.

The `binary` override is intentionally restricted to executables named
`ettercap` or `etterfilter`; this prevents the MCP server from becoming a
general-purpose command runner.
