"""
lldb plugin for correlating JIT-compiled native code with wasm bytecode offsets.

Usage:
    (lldb) command script import tools/lldb/wazero_sourcemap.py
    (lldb) wasm load /tmp/wazero-sourcemap-<pid>.map
    (lldb) wasm offset          # show wasm offset for current PC
    (lldb) wasm wat <file.wasm> # show WAT source for current PC

Enable source map dumping in wazero by setting SourceMapDumpEnabled = true
in internal/engine/wazevo/wazevoapi/debug_options.go.
"""

import bisect
import json
import os
import subprocess

_source_map = None


class SourceMap:
    def __init__(self, data):
        self.base = int(data["base"], 16)
        self.functions = data["functions"]
        self.exec_addrs = [int(m["exec"], 16) for m in data["mappings"]]
        self.wasm_offsets = [m["wasm"] for m in data["mappings"]]
        self.func_addrs = [int(f["exec"], 16) for f in self.functions]
        self.func_names = [f["name"] for f in self.functions]

    def lookup(self, pc):
        """Return (wasm_offset, func_name) for a given PC, or (None, None)."""
        if not self.exec_addrs:
            return None, None

        idx = bisect.bisect_right(self.exec_addrs, pc) - 1
        if idx < 0:
            return None, None
        wasm_offset = self.wasm_offsets[idx]

        func_name = None
        fidx = bisect.bisect_right(self.func_addrs, pc) - 1
        if fidx >= 0:
            func_name = self.func_names[fidx]

        return wasm_offset, func_name


def cmd_wasm(debugger, command, result, internal_dict):
    args = command.strip().split()
    if not args:
        result.AppendMessage("Usage: wasm <load|offset|wat> [args...]")
        return

    subcmd = args[0]

    if subcmd == "load":
        _cmd_load(args[1:], result)
    elif subcmd == "offset":
        _cmd_offset(debugger, result)
    elif subcmd == "wat":
        _cmd_wat(debugger, args[1:], result)
    else:
        result.AppendMessage("Unknown subcommand: %s" % subcmd)
        result.AppendMessage("Usage: wasm <load|offset|wat> [args...]")


def _cmd_load(args, result):
    global _source_map
    if not args:
        result.AppendMessage("Usage: wasm load <path-to-sourcemap.map>")
        return

    path = args[0]
    if not os.path.exists(path):
        result.AppendMessage("File not found: %s" % path)
        return

    with open(path) as f:
        data = json.load(f)

    _source_map = SourceMap(data)
    result.AppendMessage(
        "Loaded source map: %d mappings, %d functions"
        % (len(_source_map.exec_addrs), len(_source_map.functions))
    )


def _get_pc(debugger):
    target = debugger.GetSelectedTarget()
    if not target:
        return None
    process = target.GetProcess()
    if not process:
        return None
    thread = process.GetSelectedThread()
    if not thread:
        return None
    frame = thread.GetSelectedFrame()
    if not frame:
        return None
    return frame.GetPC()


def _cmd_offset(debugger, result):
    if _source_map is None:
        result.AppendMessage("No source map loaded. Use: wasm load <path>")
        return

    pc = _get_pc(debugger)
    if pc is None:
        result.AppendMessage("No frame selected")
        return

    wasm_offset, func_name = _source_map.lookup(pc)
    if wasm_offset is None:
        result.AppendMessage("PC 0x%x not found in source map" % pc)
        return

    msg = "PC 0x%x -> wasm offset %d (0x%x)" % (pc, wasm_offset, wasm_offset)
    if func_name:
        msg += " in %s" % func_name
    result.AppendMessage(msg)


def _cmd_wat(debugger, args, result):
    if _source_map is None:
        result.AppendMessage("No source map loaded. Use: wasm load <path>")
        return

    if not args:
        result.AppendMessage("Usage: wasm wat <path-to-file.wasm>")
        return

    wasm_path = args[0]

    pc = _get_pc(debugger)
    if pc is None:
        result.AppendMessage("No frame selected")
        return

    wasm_offset, func_name = _source_map.lookup(pc)
    if wasm_offset is None:
        result.AppendMessage("PC 0x%x not found in source map" % pc)
        return

    msg = "PC 0x%x -> wasm offset %d (0x%x)" % (pc, wasm_offset, wasm_offset)
    if func_name:
        msg += " in %s" % func_name
    result.AppendMessage(msg)
    result.AppendMessage("")

    try:
        wat = subprocess.check_output(
            ["wasm-tools", "print", "--print-offsets", wasm_path],
            stderr=subprocess.STDOUT,
        ).decode("utf-8", errors="replace")
    except FileNotFoundError:
        result.AppendMessage(
            "wasm-tools not found. Install: cargo install wasm-tools"
        )
        return
    except subprocess.CalledProcessError as e:
        result.AppendMessage("wasm-tools error: %s" % e.output.decode())
        return

    offset_marker = "(@%#x" % wasm_offset
    context_lines = 5
    lines = wat.splitlines()
    for i, line in enumerate(lines):
        if offset_marker in line:
            start = max(0, i - context_lines)
            end = min(len(lines), i + context_lines + 1)
            for j in range(start, end):
                prefix = ">>>" if j == i else "   "
                result.AppendMessage("%s %s" % (prefix, lines[j]))
            return

    result.AppendMessage(
        "Offset 0x%x not found in WAT output. "
        "The offset may be a function-body-relative offset; "
        "try wasm-tools print --print-offsets %s | grep -n '0x%x'"
        % (wasm_offset, wasm_path, wasm_offset)
    )


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f wazero_sourcemap.cmd_wasm wasm'
    )
    print(
        "wazero source map plugin loaded. Commands:\n"
        "  wasm load <path>       - load a source map JSON file\n"
        "  wasm offset            - show wasm offset for current PC\n"
        "  wasm wat <file.wasm>   - show WAT source context for current PC"
    )
