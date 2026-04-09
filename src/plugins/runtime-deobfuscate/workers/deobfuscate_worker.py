#!/usr/bin/env python3
"""
Runtime Deobfuscation Worker — Deobfuscation via dynamic execution.

Commands:
  - strings_runtime: Hook string decryption routines, capture decrypted strings
  - api_resolve: Hook GetProcAddress/LdrGetProcedureAddress, capture dynamic API resolution
  - cfg_trace: Record execution trace to reconstruct CFG
  - dotnet_deobfuscate: Run de4dot on .NET assemblies

Input (JSON on stdin):
  {
    "command": "strings_runtime" | "api_resolve" | "cfg_trace" | "dotnet_deobfuscate",
    "sample_path": "/path/to/binary",
    "timeout": 60,
    ...
  }

Output (JSON on last stdout line):
  {
    "ok": true/false,
    "command": "...",
    "data": { ... },
    "errors": [],
    "warnings": []
  }
"""

import json
import os
import subprocess
import shutil
import sys
import tempfile
import hashlib
from pathlib import Path


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Command: strings_runtime — Frida-based string decryption capture
# ---------------------------------------------------------------------------

def strings_runtime(sample_path: str, timeout: int = 60, frida_script: str = None) -> dict:
    """Hook string decryption routines at runtime, capture decrypted strings."""
    try:
        import frida
    except ImportError:
        return {"ok": False, "command": "strings_runtime",
                "errors": ["frida not installed. Install with: pip install frida frida-tools"]}

    # Use provided script or built-in hook
    if frida_script and os.path.exists(frida_script):
        with open(frida_script, "r") as f:
            script_src = f.read()
    else:
        script_src = _get_string_decrypt_hook_script()

    captured_strings = []
    api_calls = []
    errors = []

    def on_message(message, data):
        if message["type"] == "send":
            payload = message["payload"]
            if isinstance(payload, dict):
                msg_type = payload.get("type", "")
                if msg_type == "decrypted_string":
                    captured_strings.append({
                        "value": payload.get("value", ""),
                        "address": payload.get("address", ""),
                        "caller": payload.get("caller", ""),
                        "method": payload.get("method", ""),
                    })
                elif msg_type == "api_call":
                    api_calls.append(payload)
        elif message["type"] == "error":
            errors.append(message.get("description", str(message)))

    try:
        # Spawn process with Frida
        device = frida.get_local_device()
        pid = device.spawn([sample_path])
        session = device.attach(pid)

        script = session.create_script(script_src)
        script.on("message", on_message)
        script.load()

        device.resume(pid)

        # Wait for execution
        import time
        time.sleep(min(timeout, 30))

        # Collect results
        try:
            session.detach()
        except Exception:
            pass
        try:
            device.kill(pid)
        except Exception:
            pass

        # Deduplicate strings
        seen = set()
        unique_strings = []
        for s in captured_strings:
            val = s.get("value", "")
            if val and val not in seen:
                seen.add(val)
                unique_strings.append(s)

        return {
            "ok": True,
            "command": "strings_runtime",
            "data": {
                "total_captured": len(captured_strings),
                "unique_strings": len(unique_strings),
                "strings": unique_strings[:500],
                "api_calls": api_calls[:200],
                "execution_time": min(timeout, 30),
            },
            "errors": errors if errors else [],
            "warnings": [],
        }
    except frida.ProcessNotFoundError:
        return {"ok": False, "command": "strings_runtime",
                "errors": ["Process terminated too quickly for Frida to attach"]}
    except Exception as e:
        return {"ok": False, "command": "strings_runtime",
                "errors": [f"Frida runtime string capture failed: {e}"]}


def _get_string_decrypt_hook_script() -> str:
    """Built-in Frida script for string decryption hooks."""
    return r"""
'use strict';

// Hook CryptDecrypt (advapi32)
try {
    var CryptDecrypt = Module.findExportByName('advapi32.dll', 'CryptDecrypt');
    if (CryptDecrypt) {
        Interceptor.attach(CryptDecrypt, {
            onEnter: function(args) {
                this.pbData = args[3];
                this.pdwDataLen = args[4];
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    try {
                        var len = this.pdwDataLen.readU32();
                        var data = this.pbData.readUtf16String(len) || this.pbData.readAnsiString(len);
                        if (data && data.length > 0 && data.length < 10000) {
                            send({ type: 'decrypted_string', value: data, method: 'CryptDecrypt', address: CryptDecrypt.toString(), caller: this.returnAddress.toString() });
                        }
                    } catch(e) {}
                }
            }
        });
    }
} catch(e) {}

// Hook VirtualAlloc for code unpacking detection
try {
    var VirtualAlloc = Module.findExportByName('kernel32.dll', 'VirtualAlloc');
    if (VirtualAlloc) {
        Interceptor.attach(VirtualAlloc, {
            onEnter: function(args) {
                this.size = args[1].toInt32();
                this.protect = args[3].toInt32();
            },
            onLeave: function(retval) {
                if (this.protect === 0x40 || this.protect === 0x20) { // PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_READ
                    send({ type: 'api_call', api: 'VirtualAlloc', address: retval.toString(), size: this.size, protection: this.protect });
                }
            }
        });
    }
} catch(e) {}

// Hook WriteProcessMemory for injection detection
try {
    var WriteProcessMemory = Module.findExportByName('kernel32.dll', 'WriteProcessMemory');
    if (WriteProcessMemory) {
        Interceptor.attach(WriteProcessMemory, {
            onEnter: function(args) {
                send({ type: 'api_call', api: 'WriteProcessMemory', target_pid: args[0].toInt32(), address: args[1].toString(), size: args[2].toInt32() });
            }
        });
    }
} catch(e) {}

// Multi-byte XOR detection: hook common memory routines and check for XOR patterns
try {
    var modules = Process.enumerateModules();
    var mainModule = modules[0];
    if (mainModule) {
        // Scan for XOR loops in the main module
        Memory.scan(mainModule.base, mainModule.size, '30 ?? ?? ?? ?? ?? 0F 85', {
            onMatch: function(address, size) {
                send({ type: 'api_call', api: 'xor_loop_detected', address: address.toString() });
            },
            onComplete: function() {}
        });
    }
} catch(e) {}
"""


# ---------------------------------------------------------------------------
# Command: api_resolve — Capture dynamically resolved APIs
# ---------------------------------------------------------------------------

def api_resolve(sample_path: str, timeout: int = 60) -> dict:
    """Hook GetProcAddress/LdrGetProcedureAddress, capture resolved APIs."""
    try:
        import frida
    except ImportError:
        return {"ok": False, "command": "api_resolve",
                "errors": ["frida not installed"]}

    script_src = r"""
'use strict';
var resolved = [];

// Hook GetProcAddress
try {
    var GetProcAddress = Module.findExportByName('kernel32.dll', 'GetProcAddress');
    if (GetProcAddress) {
        Interceptor.attach(GetProcAddress, {
            onEnter: function(args) {
                this.hModule = args[0];
                var namePtr = args[1];
                if (namePtr.toInt32() > 0xFFFF) {
                    this.funcName = namePtr.readAnsiString();
                } else {
                    this.funcName = '#' + namePtr.toInt32();
                }
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0 && this.funcName) {
                    var moduleName = '';
                    try {
                        var mod = Process.findModuleByAddress(this.hModule);
                        if (mod) moduleName = mod.name;
                    } catch(e) {}
                    send({
                        type: 'resolved_api',
                        name: this.funcName,
                        module: moduleName,
                        address: retval.toString(),
                        caller: this.returnAddress.toString()
                    });
                }
            }
        });
    }
} catch(e) {}

// Hook LoadLibraryA/W
try {
    ['LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW'].forEach(function(name) {
        var func = Module.findExportByName('kernel32.dll', name);
        if (func) {
            Interceptor.attach(func, {
                onEnter: function(args) {
                    var libName = name.indexOf('W') > 0 ? args[0].readUtf16String() : args[0].readAnsiString();
                    send({ type: 'loaded_library', name: libName, api: name, caller: this.returnAddress.toString() });
                }
            });
        }
    });
} catch(e) {}

// Hook LdrGetProcedureAddress (ntdll)
try {
    var LdrGetProcedureAddress = Module.findExportByName('ntdll.dll', 'LdrGetProcedureAddress');
    if (LdrGetProcedureAddress) {
        Interceptor.attach(LdrGetProcedureAddress, {
            onEnter: function(args) {
                this.dllBase = args[0];
                try {
                    var nameStruct = args[1];
                    if (nameStruct && !nameStruct.isNull()) {
                        var len = nameStruct.add(2).readU16();
                        var buf = nameStruct.add(Process.pointerSize).readPointer();
                        this.funcName = buf.readAnsiString(len);
                    }
                } catch(e) {}
            },
            onLeave: function(retval) {
                if (this.funcName) {
                    send({
                        type: 'resolved_api',
                        name: this.funcName,
                        via: 'LdrGetProcedureAddress',
                        address: retval.toString(),
                        caller: this.returnAddress.toString()
                    });
                }
            }
        });
    }
} catch(e) {}
"""

    resolved_apis = []
    loaded_libs = []
    errors = []

    def on_message(message, data):
        if message["type"] == "send":
            payload = message["payload"]
            msg_type = payload.get("type", "")
            if msg_type == "resolved_api":
                resolved_apis.append(payload)
            elif msg_type == "loaded_library":
                loaded_libs.append(payload)
        elif message["type"] == "error":
            errors.append(message.get("description", ""))

    try:
        device = frida.get_local_device()
        pid = device.spawn([sample_path])
        session = device.attach(pid)

        script = session.create_script(script_src)
        script.on("message", on_message)
        script.load()
        device.resume(pid)

        import time
        time.sleep(min(timeout, 30))

        try:
            session.detach()
        except Exception:
            pass
        try:
            device.kill(pid)
        except Exception:
            pass

        # Build IAT map
        iat_map = {}
        for api in resolved_apis:
            key = f"{api.get('module', 'unknown')}!{api.get('name', '')}"
            if key not in iat_map:
                iat_map[key] = {
                    "name": api.get("name", ""),
                    "module": api.get("module", ""),
                    "address": api.get("address", ""),
                    "call_count": 0,
                }
            iat_map[key]["call_count"] += 1

        return {
            "ok": True,
            "command": "api_resolve",
            "data": {
                "total_resolutions": len(resolved_apis),
                "unique_apis": len(iat_map),
                "loaded_libraries": loaded_libs[:100],
                "iat_map": list(iat_map.values())[:500],
                "raw_trace": resolved_apis[:200],
            },
            "errors": errors if errors else [],
            "warnings": [],
        }
    except Exception as e:
        return {"ok": False, "command": "api_resolve",
                "errors": [f"API resolution capture failed: {e}"]}


# ---------------------------------------------------------------------------
# Command: cfg_trace — CFG recovery from execution trace
# ---------------------------------------------------------------------------

def cfg_trace(sample_path: str, timeout: int = 60, max_blocks: int = 10000) -> dict:
    """Record execution trace, reconstruct CFG from actually executed basic blocks."""
    try:
        import frida
    except ImportError:
        return {"ok": False, "command": "cfg_trace",
                "errors": ["frida not installed"]}

    script_src = r"""
'use strict';
var blocks = [];
var edges = [];
var moduleBase = null;
var moduleSize = 0;

var modules = Process.enumerateModules();
if (modules.length > 0) {
    moduleBase = modules[0].base;
    moduleSize = modules[0].size;

    Stalker.follow(Process.getCurrentThreadId(), {
        events: { compile: true, block: true },
        onReceive: function(events) {
            var parsed = Stalker.parse(events, { annotate: true, stringify: false });
            for (var i = 0; i < parsed.length; i++) {
                var ev = parsed[i];
                if (ev[0] === 'block') {
                    var start = ev[1];
                    var end = ev[2];
                    // Only track blocks in the main module
                    if (start >= moduleBase && start < moduleBase.add(moduleSize)) {
                        var rva = start.sub(moduleBase).toInt32();
                        send({ type: 'block', rva: rva, size: end.sub(start).toInt32() });
                    }
                }
            }
        }
    });
}
"""

    basic_blocks = []
    errors = []

    def on_message(message, data):
        if message["type"] == "send":
            payload = message["payload"]
            if payload.get("type") == "block":
                basic_blocks.append({
                    "rva": hex(payload["rva"]),
                    "size": payload["size"],
                })
        elif message["type"] == "error":
            errors.append(message.get("description", ""))

    try:
        device = frida.get_local_device()
        pid = device.spawn([sample_path])
        session = device.attach(pid)

        script = session.create_script(script_src)
        script.on("message", on_message)
        script.load()
        device.resume(pid)

        import time
        time.sleep(min(timeout, 30))

        try:
            session.detach()
        except Exception:
            pass
        try:
            device.kill(pid)
        except Exception:
            pass

        # Build CFG from basic blocks
        unique_blocks = {}
        for bb in basic_blocks:
            rva = bb["rva"]
            if rva not in unique_blocks:
                unique_blocks[rva] = bb

        # Reconstruct edges (sequential blocks imply edges)
        sorted_blocks = sorted(unique_blocks.values(), key=lambda b: int(b["rva"], 16))
        edges = []
        for i in range(len(sorted_blocks) - 1):
            edges.append({
                "from": sorted_blocks[i]["rva"],
                "to": sorted_blocks[i + 1]["rva"],
            })

        return {
            "ok": True,
            "command": "cfg_trace",
            "data": {
                "total_blocks_traced": len(basic_blocks),
                "unique_blocks": len(unique_blocks),
                "blocks": sorted_blocks[:max_blocks],
                "edges": edges[:max_blocks],
                "coverage_note": "CFG represents actually executed paths only (dynamic coverage)",
            },
            "errors": errors if errors else [],
            "warnings": [],
        }
    except Exception as e:
        return {"ok": False, "command": "cfg_trace",
                "errors": [f"CFG trace failed: {e}"]}


# ---------------------------------------------------------------------------
# Command: dotnet_deobfuscate — de4dot integration
# ---------------------------------------------------------------------------

def dotnet_deobfuscate(sample_path: str, output_dir: str = None) -> dict:
    """Run de4dot to deobfuscate .NET assemblies."""
    de4dot_bin = shutil.which("de4dot") or shutil.which("de4dot-x64")
    if not de4dot_bin:
        # Try common paths
        for candidate in ["/usr/local/bin/de4dot", "/opt/de4dot/de4dot", "/opt/de4dot/de4dot.exe"]:
            if os.path.exists(candidate):
                de4dot_bin = candidate
                break

    if not de4dot_bin:
        return {"ok": False, "command": "dotnet_deobfuscate",
                "errors": ["de4dot not found. Install de4dot for .NET deobfuscation."]}

    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="de4dot_")

    output_path = os.path.join(output_dir, "deobfuscated.exe")

    try:
        result = subprocess.run(
            [de4dot_bin, sample_path, "-o", output_path],
            capture_output=True, text=True, timeout=120
        )

        if os.path.exists(output_path):
            return {
                "ok": True,
                "command": "dotnet_deobfuscate",
                "data": {
                    "deobfuscated_path": output_path,
                    "sha256": sha256_file(output_path),
                    "size": os.path.getsize(output_path),
                    "stdout": result.stdout[:3000],
                    "stderr": result.stderr[:1000],
                    "detected_obfuscator": _parse_de4dot_obfuscator(result.stdout),
                },
                "errors": [],
                "warnings": [],
            }
        else:
            return {
                "ok": False,
                "command": "dotnet_deobfuscate",
                "errors": [f"de4dot did not produce output. stderr: {result.stderr[:1000]}"],
            }
    except subprocess.TimeoutExpired:
        return {"ok": False, "command": "dotnet_deobfuscate",
                "errors": ["de4dot timed out after 120s"]}
    except Exception as e:
        return {"ok": False, "command": "dotnet_deobfuscate",
                "errors": [f"de4dot execution failed: {e}"]}


def _parse_de4dot_obfuscator(stdout: str) -> str:
    """Extract detected obfuscator name from de4dot output."""
    for line in stdout.split("\n"):
        lower = line.lower()
        if "detected" in lower and ("obfuscator" in lower or "packer" in lower):
            return line.strip()
        if "confuserex" in lower or "reactor" in lower or "dotfuscator" in lower:
            return line.strip()
    return "unknown"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    try:
        payload = json.loads(sys.stdin.read())
    except json.JSONDecodeError as e:
        print(json.dumps({"ok": False, "errors": [f"Invalid JSON input: {e}"]}))
        return

    command = payload.get("command", "strings_runtime")
    sample_path = payload.get("sample_path", "")
    timeout = payload.get("timeout", 60)

    if command == "strings_runtime":
        result = strings_runtime(
            sample_path=sample_path,
            timeout=timeout,
            frida_script=payload.get("frida_script"),
        )
    elif command == "api_resolve":
        result = api_resolve(
            sample_path=sample_path,
            timeout=timeout,
        )
    elif command == "cfg_trace":
        result = cfg_trace(
            sample_path=sample_path,
            timeout=timeout,
            max_blocks=payload.get("max_blocks", 10000),
        )
    elif command == "dotnet_deobfuscate":
        result = dotnet_deobfuscate(
            sample_path=sample_path,
            output_dir=payload.get("output_dir"),
        )
    else:
        result = {"ok": False, "errors": [f"Unknown command: {command}"]}

    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
