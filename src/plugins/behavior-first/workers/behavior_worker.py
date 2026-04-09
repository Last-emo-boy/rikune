#!/usr/bin/env python3
"""
Behavioral Monitor Worker — Full behavioral capture for opaque binaries.

Commands:
  - capture: Execute binary in sandbox, capture file/registry/network/process behavior
  - ioc_extract: Extract IOCs (indicators of compromise) from behavioral report
  - network_analyze: Analyze captured network traffic

Input (JSON on stdin):
  {
    "command": "capture" | "ioc_extract" | "network_analyze",
    "sample_path": "/path/to/binary",
    "timeout": 60,
    ...
  }
"""

import json
import os
import re
import subprocess
import shutil
import sys
import tempfile
import time
import hashlib
from pathlib import Path


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Command: capture — Full behavioral capture
# ---------------------------------------------------------------------------

def behavioral_capture(sample_path: str, timeout: int = 60) -> dict:
    """Execute binary in sandbox, capture comprehensive behavior."""
    try:
        import frida
    except ImportError:
        return {"ok": False, "command": "capture",
                "errors": ["frida not installed"]}

    script_src = _get_behavior_monitor_script()

    file_ops = []
    registry_ops = []
    network_ops = []
    process_ops = []
    api_calls = []
    errors = []

    def on_message(message, data):
        if message["type"] == "send":
            payload = message["payload"]
            msg_type = payload.get("type", "")
            if msg_type == "file_op":
                file_ops.append(payload)
            elif msg_type == "registry_op":
                registry_ops.append(payload)
            elif msg_type == "network_op":
                network_ops.append(payload)
            elif msg_type == "process_op":
                process_ops.append(payload)
            elif msg_type == "api_call":
                api_calls.append(payload)
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

        # Wait for execution
        exec_timeout = min(timeout, 60)
        time.sleep(exec_timeout)

        try:
            session.detach()
        except Exception:
            pass
        try:
            device.kill(pid)
        except Exception:
            pass

        # Build behavioral profile
        profile = _build_behavioral_profile(file_ops, registry_ops, network_ops, process_ops, api_calls)

        return {
            "ok": True,
            "command": "capture",
            "data": {
                "execution_time": exec_timeout,
                "file_operations": file_ops[:200],
                "registry_operations": registry_ops[:200],
                "network_operations": network_ops[:200],
                "process_operations": process_ops[:100],
                "api_calls_summary": _summarize_api_calls(api_calls),
                "behavioral_profile": profile,
                "total_events": {
                    "file": len(file_ops),
                    "registry": len(registry_ops),
                    "network": len(network_ops),
                    "process": len(process_ops),
                    "api": len(api_calls),
                },
            },
            "errors": errors if errors else [],
            "warnings": [],
        }
    except Exception as e:
        return {"ok": False, "command": "capture",
                "errors": [f"Behavioral capture failed: {e}"]}


def _get_behavior_monitor_script() -> str:
    """Comprehensive Frida behavior monitoring script."""
    return r"""
'use strict';

// ---- File Operations ----
try {
    ['CreateFileA', 'CreateFileW'].forEach(function(name) {
        var func = Module.findExportByName('kernel32.dll', name);
        if (func) {
            Interceptor.attach(func, {
                onEnter: function(args) {
                    var path = name.endsWith('W') ? args[0].readUtf16String() : args[0].readAnsiString();
                    var access = args[1].toInt32();
                    var op = (access & 0x40000000) ? 'write' : 'read';
                    send({ type: 'file_op', operation: op, path: path, api: name });
                }
            });
        }
    });
} catch(e) {}

try {
    var DeleteFileW = Module.findExportByName('kernel32.dll', 'DeleteFileW');
    if (DeleteFileW) {
        Interceptor.attach(DeleteFileW, {
            onEnter: function(args) {
                send({ type: 'file_op', operation: 'delete', path: args[0].readUtf16String(), api: 'DeleteFileW' });
            }
        });
    }
} catch(e) {}

try {
    var MoveFileW = Module.findExportByName('kernel32.dll', 'MoveFileW');
    if (MoveFileW) {
        Interceptor.attach(MoveFileW, {
            onEnter: function(args) {
                send({ type: 'file_op', operation: 'move', path: args[0].readUtf16String(), destination: args[1].readUtf16String(), api: 'MoveFileW' });
            }
        });
    }
} catch(e) {}

// ---- Registry Operations ----
try {
    ['RegOpenKeyExA', 'RegOpenKeyExW', 'RegCreateKeyExA', 'RegCreateKeyExW'].forEach(function(name) {
        var func = Module.findExportByName('advapi32.dll', name);
        if (func) {
            Interceptor.attach(func, {
                onEnter: function(args) {
                    var key = name.endsWith('W') ? args[1].readUtf16String() : args[1].readAnsiString();
                    var op = name.startsWith('RegCreate') ? 'create' : 'open';
                    send({ type: 'registry_op', operation: op, key: key, api: name });
                }
            });
        }
    });
} catch(e) {}

try {
    ['RegSetValueExA', 'RegSetValueExW'].forEach(function(name) {
        var func = Module.findExportByName('advapi32.dll', name);
        if (func) {
            Interceptor.attach(func, {
                onEnter: function(args) {
                    var valueName = name.endsWith('W') ? args[1].readUtf16String() : args[1].readAnsiString();
                    send({ type: 'registry_op', operation: 'set_value', value_name: valueName, api: name });
                }
            });
        }
    });
} catch(e) {}

// ---- Network Operations ----
try {
    var connect = Module.findExportByName('ws2_32.dll', 'connect');
    if (connect) {
        Interceptor.attach(connect, {
            onEnter: function(args) {
                var sockaddr = args[1];
                var family = sockaddr.readU16();
                if (family === 2) { // AF_INET
                    var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                    var ip = sockaddr.add(4).readU8() + '.' + sockaddr.add(5).readU8() + '.' + sockaddr.add(6).readU8() + '.' + sockaddr.add(7).readU8();
                    send({ type: 'network_op', operation: 'connect', ip: ip, port: port, api: 'connect' });
                }
            }
        });
    }
} catch(e) {}

try {
    var send_func = Module.findExportByName('ws2_32.dll', 'send');
    if (send_func) {
        Interceptor.attach(send_func, {
            onEnter: function(args) {
                var len = args[2].toInt32();
                var preview = '';
                try { preview = args[1].readAnsiString(Math.min(len, 200)); } catch(e) {}
                send({ type: 'network_op', operation: 'send', length: len, preview: preview, api: 'send' });
            }
        });
    }
} catch(e) {}

try {
    ['InternetOpenA', 'InternetOpenW', 'InternetOpenUrlA', 'InternetOpenUrlW',
     'HttpOpenRequestA', 'HttpOpenRequestW'].forEach(function(name) {
        var func = Module.findExportByName('wininet.dll', name);
        if (func) {
            Interceptor.attach(func, {
                onEnter: function(args) {
                    var url = '';
                    try {
                        if (name.indexOf('Url') > 0) {
                            url = name.endsWith('W') ? args[1].readUtf16String() : args[1].readAnsiString();
                        } else if (name.indexOf('HttpOpen') === 0) {
                            url = name.endsWith('W') ? args[1].readUtf16String() : args[1].readAnsiString();
                        }
                    } catch(e) {}
                    send({ type: 'network_op', operation: 'http', url: url, api: name });
                }
            });
        }
    });
} catch(e) {}

// DNS
try {
    var getaddrinfo = Module.findExportByName('ws2_32.dll', 'getaddrinfo');
    if (getaddrinfo) {
        Interceptor.attach(getaddrinfo, {
            onEnter: function(args) {
                var hostname = args[0].readAnsiString();
                send({ type: 'network_op', operation: 'dns', hostname: hostname, api: 'getaddrinfo' });
            }
        });
    }
} catch(e) {}

// ---- Process Operations ----
try {
    var CreateProcessW = Module.findExportByName('kernel32.dll', 'CreateProcessW');
    if (CreateProcessW) {
        Interceptor.attach(CreateProcessW, {
            onEnter: function(args) {
                var appName = args[0].isNull() ? null : args[0].readUtf16String();
                var cmdLine = args[1].isNull() ? null : args[1].readUtf16String();
                send({ type: 'process_op', operation: 'create', app: appName, cmdline: cmdLine, api: 'CreateProcessW' });
            }
        });
    }
} catch(e) {}

try {
    var VirtualAllocEx = Module.findExportByName('kernel32.dll', 'VirtualAllocEx');
    if (VirtualAllocEx) {
        Interceptor.attach(VirtualAllocEx, {
            onEnter: function(args) {
                var handle = args[0].toInt32();
                if (handle !== -1) {
                    send({ type: 'process_op', operation: 'remote_alloc', target_handle: handle, size: args[1].toInt32(), api: 'VirtualAllocEx' });
                }
            }
        });
    }
} catch(e) {}

try {
    var NtCreateThreadEx = Module.findExportByName('ntdll.dll', 'NtCreateThreadEx');
    if (NtCreateThreadEx) {
        Interceptor.attach(NtCreateThreadEx, {
            onEnter: function(args) {
                send({ type: 'process_op', operation: 'remote_thread', api: 'NtCreateThreadEx' });
            }
        });
    }
} catch(e) {}
"""


def _summarize_api_calls(api_calls: list) -> dict:
    """Summarize API calls by category."""
    categories = {
        "memory": 0,
        "file": 0,
        "registry": 0,
        "network": 0,
        "process": 0,
        "crypto": 0,
        "other": 0,
    }
    api_freq = {}
    for call in api_calls:
        api = call.get("api", "unknown")
        api_freq[api] = api_freq.get(api, 0) + 1

        lower = api.lower()
        if any(k in lower for k in ["virtual", "heap", "mem"]):
            categories["memory"] += 1
        elif any(k in lower for k in ["file", "write", "read", "delete"]):
            categories["file"] += 1
        elif "reg" in lower:
            categories["registry"] += 1
        elif any(k in lower for k in ["socket", "connect", "send", "recv", "internet", "http"]):
            categories["network"] += 1
        elif any(k in lower for k in ["process", "thread", "create"]):
            categories["process"] += 1
        elif any(k in lower for k in ["crypt", "aes", "rsa", "hash"]):
            categories["crypto"] += 1
        else:
            categories["other"] += 1

    top_apis = sorted(api_freq.items(), key=lambda x: -x[1])[:30]
    return {
        "categories": categories,
        "top_apis": [{"api": k, "count": v} for k, v in top_apis],
        "total": len(api_calls),
    }


def _build_behavioral_profile(file_ops, registry_ops, network_ops, process_ops, api_calls) -> dict:
    """Build high-level behavioral classification from raw events."""
    tags = []
    risk_score = 0

    # File behavior
    dropped_files = [f for f in file_ops if f.get("operation") == "write"]
    deleted_files = [f for f in file_ops if f.get("operation") == "delete"]
    if dropped_files:
        tags.append("drops_files")
        risk_score += 10
    if deleted_files:
        tags.append("deletes_files")
        risk_score += 5

    # Persistence indicators
    persistence_keys = ["run", "runonce", "services", "startup"]
    for r in registry_ops:
        key = (r.get("key") or "").lower()
        if any(pk in key for pk in persistence_keys):
            tags.append("persistence")
            risk_score += 25
            break

    # Network behavior
    unique_ips = set()
    unique_domains = set()
    for n in network_ops:
        if n.get("ip"):
            unique_ips.add(n["ip"])
        if n.get("hostname"):
            unique_domains.add(n["hostname"])
        if n.get("url"):
            tags.append("http_communication")
    if unique_ips:
        tags.append("network_connections")
        risk_score += 15
    if unique_domains:
        tags.append("dns_resolution")
        risk_score += 10

    # Process injection indicators
    for p in process_ops:
        op = p.get("operation", "")
        if op == "remote_alloc":
            tags.append("process_injection")
            risk_score += 30
            break
        if op == "remote_thread":
            tags.append("remote_thread_creation")
            risk_score += 30
            break
        if op == "create":
            tags.append("spawns_processes")
            risk_score += 5

    # Anti-analysis
    anti_debug_apis = ["isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"]
    for call in api_calls:
        api_lower = (call.get("api") or "").lower()
        if api_lower in anti_debug_apis:
            tags.append("anti_debug")
            risk_score += 15
            break

    # Classification
    if risk_score >= 50:
        classification = "likely_malicious"
    elif risk_score >= 25:
        classification = "suspicious"
    elif risk_score >= 10:
        classification = "possibly_suspicious"
    else:
        classification = "benign_or_inconclusive"

    return {
        "tags": list(set(tags)),
        "risk_score": min(risk_score, 100),
        "classification": classification,
        "network_indicators": {
            "unique_ips": list(unique_ips)[:50],
            "unique_domains": list(unique_domains)[:50],
        },
        "file_indicators": {
            "files_written": len(dropped_files),
            "files_deleted": len(deleted_files),
            "written_paths": [f.get("path", "") for f in dropped_files[:20]],
        },
        "process_indicators": {
            "processes_created": len([p for p in process_ops if p.get("operation") == "create"]),
            "injection_attempts": len([p for p in process_ops if p.get("operation") in ("remote_alloc", "remote_thread")]),
        },
    }


# ---------------------------------------------------------------------------
# Command: ioc_extract — Extract IOCs from behavioral data
# ---------------------------------------------------------------------------

def ioc_extract(behavior_data: dict) -> dict:
    """Extract IOCs from behavioral capture data."""
    iocs = {
        "network": [],
        "file": [],
        "registry": [],
        "process": [],
    }

    # Network IOCs
    for n in behavior_data.get("network_operations", []):
        ip = n.get("ip")
        hostname = n.get("hostname")
        url = n.get("url")
        if ip and not ip.startswith("127.") and ip != "0.0.0.0":
            iocs["network"].append({"type": "ip", "value": ip, "port": n.get("port")})
        if hostname:
            iocs["network"].append({"type": "domain", "value": hostname})
        if url:
            iocs["network"].append({"type": "url", "value": url})

    # File IOCs
    for f in behavior_data.get("file_operations", []):
        path = f.get("path", "")
        op = f.get("operation", "")
        if op == "write" and path:
            iocs["file"].append({"type": "dropped_file", "path": path})
        elif op == "delete" and path:
            iocs["file"].append({"type": "deleted_file", "path": path})

    # Registry IOCs
    for r in behavior_data.get("registry_operations", []):
        key = r.get("key", "")
        op = r.get("operation", "")
        if op in ("create", "set_value") and key:
            iocs["registry"].append({"type": f"registry_{op}", "key": key, "value_name": r.get("value_name")})

    # Process IOCs
    for p in behavior_data.get("process_operations", []):
        if p.get("operation") == "create":
            iocs["process"].append({"type": "spawned_process", "cmdline": p.get("cmdline"), "app": p.get("app")})

    # Deduplicate
    for category in iocs:
        seen = set()
        unique = []
        for item in iocs[category]:
            key = json.dumps(item, sort_keys=True)
            if key not in seen:
                seen.add(key)
                unique.append(item)
        iocs[category] = unique

    total = sum(len(v) for v in iocs.values())

    return {
        "ok": True,
        "command": "ioc_extract",
        "data": {
            "total_iocs": total,
            "iocs": iocs,
        },
        "errors": [],
        "warnings": [],
    }


# ---------------------------------------------------------------------------
# Command: network_analyze — Analyze network behavior
# ---------------------------------------------------------------------------

def network_analyze(behavior_data: dict) -> dict:
    """Deep analysis of network behavior from capture data."""
    net_ops = behavior_data.get("network_operations", [])

    connections = []
    dns_queries = []
    http_requests = []

    for op in net_ops:
        operation = op.get("operation", "")
        if operation == "connect":
            connections.append({"ip": op.get("ip"), "port": op.get("port")})
        elif operation == "dns":
            dns_queries.append(op.get("hostname"))
        elif operation == "http":
            http_requests.append({"url": op.get("url"), "api": op.get("api")})

    # C2 detection heuristics
    c2_indicators = []
    unique_ips = set(c.get("ip") for c in connections if c.get("ip"))
    if len(unique_ips) == 1 and len(connections) > 5:
        c2_indicators.append({
            "type": "single_ip_repeated",
            "ip": list(unique_ips)[0],
            "confidence": "medium",
        })

    common_c2_ports = {443, 8443, 4444, 5555, 8080, 1337, 31337}
    for conn in connections:
        port = conn.get("port")
        if port in common_c2_ports:
            c2_indicators.append({
                "type": "suspicious_port",
                "ip": conn.get("ip"),
                "port": port,
                "confidence": "low",
            })

    return {
        "ok": True,
        "command": "network_analyze",
        "data": {
            "connections": connections[:100],
            "dns_queries": list(set(dns_queries))[:50],
            "http_requests": http_requests[:100],
            "unique_ips": list(unique_ips)[:50],
            "c2_indicators": c2_indicators[:20],
            "summary": {
                "total_connections": len(connections),
                "unique_destinations": len(unique_ips),
                "dns_queries": len(set(dns_queries)),
                "http_requests": len(http_requests),
            },
        },
        "errors": [],
        "warnings": [],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    try:
        payload = json.loads(sys.stdin.read())
    except json.JSONDecodeError as e:
        print(json.dumps({"ok": False, "errors": [f"Invalid JSON input: {e}"]}))
        return

    command = payload.get("command", "capture")

    if command == "capture":
        result = behavioral_capture(
            sample_path=payload["sample_path"],
            timeout=payload.get("timeout", 60),
        )
    elif command == "ioc_extract":
        result = ioc_extract(
            behavior_data=payload.get("behavior_data", {}),
        )
    elif command == "network_analyze":
        result = network_analyze(
            behavior_data=payload.get("behavior_data", {}),
        )
    else:
        result = {"ok": False, "errors": [f"Unknown command: {command}"]}

    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
