"""
lldb plugin for correlating JIT-compiled native code with wasm bytecode offsets.

Setup:
    1. Build with the sourcemap tag: go test -tags sourcemap -c -o /tmp/test ./your/package/

Debugging workflow:
    $ lldb /tmp/test
    (lldb) settings set target.disable-aslr true
    (lldb) process handle SIGURG -n false -p true -s false
    (lldb) command script import tools/lldb/wazero_sourcemap.py
    (lldb) break set -r callWithStack
    (lldb) run -test.run ^YourTest$ -test.v

    # When it stops at callWithStack (before JIT code runs):
    (lldb) wasm load /tmp/wazero-sourcemap.map   # auto-reads .base sidecar
    (lldb) wasm break 998                         # set breakpoint at wasm offset
    (lldb) break delete 1                         # remove callWithStack breakpoint
    (lldb) continue

    # When it stops at the wasm breakpoint:
    (lldb) wasm offset                            # show wasm offset + function
    (lldb) wasm wat /path/to/file.wasm            # show WAT source context
    (lldb) register read x8 x9 x12               # inspect registers
    (lldb) disassemble -s $pc -c 15               # see native code

    Find wasm offsets with: wasm-tools print --print-offsets file.wasm

Commands:
    wasm load <map> [base]  - load source map (base from .base sidecar if omitted)
    wasm offset             - show wasm offset for current PC
    wasm wat <file.wasm>    - show WAT source context for current PC
    wasm break <offset>     - set breakpoint at wasm bytecode offset (decimal or 0x hex)
"""

import bisect
import json
import os
import subprocess

_source_map = None


class SourceMap:
    def __init__(self, data, base=0):
        """Load source map. Offsets in the file are relative; base is added at runtime."""
        self.base = base
        self.functions = data["functions"]
        # Offsets are relative to executable base.
        self._func_offsets = [int(f["exec"], 16) for f in self.functions]
        self._mapping_offsets = [int(m["exec"], 16) for m in data["mappings"]]
        self.wasm_offsets = [m["wasm"] for m in data["mappings"]]
        self.func_names = [f["name"] for f in self.functions]
        self._rebase(base)

    def rebase(self, base):
        """Set the runtime base address and recompute absolute addresses."""
        self.base = base
        self._rebase(base)

    def _rebase(self, base):
        self.exec_addrs = [off + base for off in self._mapping_offsets]
        self.func_addrs = [off + base for off in self._func_offsets]

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
    elif subcmd == "break":
        _cmd_break(debugger, args[1:], result)
    else:
        result.AppendMessage("Unknown subcommand: %s" % subcmd)
        result.AppendMessage("Usage: wasm <load|offset|wat|break> [args...]")


def _cmd_load(args, result):
    global _source_map
    if not args:
        result.AppendMessage("Usage: wasm load <path-to-sourcemap.map> [base-address]")
        result.AppendMessage("  If base-address is omitted, reads from <path>.base sidecar file.")
        return

    path = args[0]
    if not os.path.exists(path):
        result.AppendMessage("File not found: %s" % path)
        return

    base = 0
    if len(args) > 1:
        try:
            base = int(args[1], 0)
        except ValueError:
            result.AppendMessage("Invalid base address: %s" % args[1])
            return
    else:
        base_path = path.rsplit(".", 1)[0] + ".base"
        if os.path.exists(base_path):
            with open(base_path) as bf:
                base = int(bf.read().strip(), 0)

    with open(path) as f:
        data = json.load(f)

    _source_map = SourceMap(data, base)
    result.AppendMessage(
        "Loaded source map: %d mappings, %d functions, base=0x%x"
        % (len(_source_map.exec_addrs), len(_source_map.functions), base)
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


def _get_wasm_offset(debugger, pc):
    """Get wasm offset for a PC. Tries source map first, then lldb's JIT debug info."""
    if _source_map is not None:
        wasm_offset, func_name = _source_map.lookup(pc)
        if wasm_offset is not None:
            return wasm_offset, func_name

    # Fall back to lldb's line entry (from jitdebug ELF).
    # When the file is "<jit>", the line number IS the wasm offset.
    # When it's a real source file, it's a source line (not a wasm offset).
    target = debugger.GetSelectedTarget()
    addr = target.ResolveLoadAddress(pc)
    li = addr.GetLineEntry()
    if li.IsValid():
        fname = str(li.GetFileSpec())
        return li.GetLine(), fname
    return None, None


def _cmd_offset(debugger, result):
    pc = _get_pc(debugger)
    if pc is None:
        result.AppendMessage("No frame selected")
        return

    wasm_offset, func_name = _get_wasm_offset(debugger, pc)
    if wasm_offset is None:
        result.AppendMessage("PC 0x%x not found in source map or JIT debug info" % pc)
        return

    msg = "PC 0x%x -> wasm offset %d (0x%x)" % (pc, wasm_offset, wasm_offset)
    if func_name:
        msg += " in %s" % func_name
    result.AppendMessage(msg)


def _cmd_wat(debugger, args, result):
    if not args:
        result.AppendMessage("Usage: wasm wat <path-to-file.wasm>")
        return

    wasm_path = args[0]

    pc = _get_pc(debugger)
    if pc is None:
        result.AppendMessage("No frame selected")
        return

    wasm_offset, func_name = _get_wasm_offset(debugger, pc)
    if wasm_offset is None:
        result.AppendMessage("PC 0x%x not found in source map or JIT debug info" % pc)
        return

    # If the JIT debug info has real source (not <jit>), the "offset" is
    # a source line, not a wasm offset. WAT lookup won't work.
    if func_name and "<jit>" not in func_name and "/" in func_name:
        result.AppendMessage("PC 0x%x -> %s:%d (source-level debug info)" % (pc, func_name, wasm_offset))
        result.AppendMessage("WAT lookup requires wasm offsets. Rebuild without DWARF in the wasm,")
        result.AppendMessage("or use 'wasm load' with a source map to get wasm offsets.")
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


def _cmd_break(debugger, args, result):
    if _source_map is None:
        result.AppendMessage("No source map loaded. Use: wasm load <path>")
        return

    if not args:
        result.AppendMessage("Usage: wasm break <wasm-offset> (decimal or 0x hex)")
        return

    try:
        target_offset = int(args[0], 0)
    except ValueError:
        result.AppendMessage("Invalid offset: %s" % args[0])
        return

    # Find all native addresses that map to this wasm offset.
    addrs = []
    for i, wo in enumerate(_source_map.wasm_offsets):
        if wo == target_offset:
            addrs.append(_source_map.exec_addrs[i])

    if not addrs:
        result.AppendMessage("No mapping found for wasm offset %d (0x%x)" % (target_offset, target_offset))
        return

    for addr in addrs:
        debugger.HandleCommand("break set -a 0x%x" % addr)
        _, func_name = _source_map.lookup(addr)
        result.AppendMessage("Breakpoint at 0x%x (wasm offset %d) in %s" % (addr, target_offset, func_name or "?"))


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f wazero_sourcemap.cmd_wasm wasm'
    )
    print(
        "wazero source map plugin loaded. Commands:\n"
        "  wasm load <path>       - load a source map JSON file\n"
        "  wasm offset            - show wasm offset for current PC\n"
        "  wasm wat <file.wasm>   - show WAT source context for current PC\n"
        "  wasm break <offset>    - set breakpoint at wasm bytecode offset"
    )
