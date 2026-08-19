#!/usr/bin/env python3
"""Bounded Python .pyc decompiler worker for the python-decompile plugin.

Loads a CPython .pyc file, recovers code object metadata, attempts source
recovery via decompyle3/uncompyle6 when installed and version-compatible,
and always produces a bounded disassembly (dis.dis). Reads a JSON request
on stdin and writes a single JSON object on stdout. Never imports or
executes the code object's bytecode.
"""
import json
import sys
import io
import types
import struct
import importlib.util


def emit(obj):
    sys.stdout.write(json.dumps(obj, default=_json_default))
    sys.exit(0)


def _json_default(o):
    if isinstance(o, bytes):
        return {"type": "bytes", "hex": o.hex()[:128]}
    return {"type": type(o).__name__}


# Map known pyc magic numbers to a Python X.Y version string. This is a
# curated subset; unknown magics resolve to None (unsupported_version).
MAGIC_VERSIONS = {
    3390: "3.7", 3391: "3.7", 3392: "3.7", 3393: "3.7",
    3394: "3.8", 3400: "3.8", 3410: "3.8", 3411: "3.8",
    3412: "3.8", 3413: "3.9", 3420: "3.9", 3421: "3.9",
    3422: "3.9", 3423: "3.9", 3424: "3.9", 3425: "3.10",
    3430: "3.10", 3431: "3.10", 3432: "3.10", 3433: "3.10",
    3434: "3.10", 3435: "3.10", 3436: "3.10", 3437: "3.11",
    3438: "3.11", 3439: "3.11", 3440: "3.11", 3441: "3.11",
    3442: "3.11", 3443: "3.11", 3444: "3.11", 3445: "3.11",
    3446: "3.11", 3447: "3.11", 3448: "3.11", 3449: "3.11",
    3450: "3.12", 3499: "3.12", 3500: "3.13", 3531: "3.13",
}


def version_for_magic(mi):
    known = sorted(MAGIC_VERSIONS.keys())
    chosen = None
    for k in known:
        if k <= mi:
            chosen = k
    return MAGIC_VERSIONS.get(chosen) if chosen is not None else None


def header_size_for_magic(mi):
    # Python 3.0-3.2: 8 bytes; 3.3-3.6: 12 bytes; 3.7+ (PEP 552): 16 bytes.
    if 3000 <= mi <= 3200:
        return 8
    if 3300 <= mi <= 3399:
        return 12
    return 16


def collect_code_meta(code):
    meta = {
        "co_name": getattr(code, "co_name", None),
        "co_argcount": getattr(code, "co_argcount", None),
        "co_nlocals": getattr(code, "co_nlocals", None),
        "co_stacksize": getattr(code, "co_stacksize", None),
        "co_flags": getattr(code, "co_flags", None),
        "co_names": list(getattr(code, "co_names", []) or []),
        "co_varnames": list(getattr(code, "co_varnames", []) or []),
        "co_freevars": list(getattr(code, "co_freevars", []) or []),
        "co_cellvars": list(getattr(code, "co_cellvars", []) or []),
    }
    consts = []
    try:
        for c in getattr(code, "co_consts", []) or []:
            if isinstance(c, types.CodeType):
                consts.append({"type": "code", "co_name": getattr(c, "co_name", None)})
            elif isinstance(c, (str, int, float, bool, type(None))):
                consts.append(c)
            elif isinstance(c, bytes):
                consts.append({"type": "bytes", "hex": c.hex()[:128]})
            else:
                consts.append({"type": type(c).__name__})
    except Exception:
        pass
    meta["co_consts"] = consts
    return meta


def try_disassemble(code, max_lines):
    try:
        buf = io.StringIO()
        import dis
        dis.dis(code, file=buf)
        full = buf.getvalue()
        lines = full.split("\n")
        truncated = len(lines) > max_lines
        return "\n".join(lines[:max_lines]), truncated
    except Exception as e:
        return f"# disassembly failed: {e}", False


def try_decompile(code, py_ver, max_chars):
    """Attempt source recovery. Returns (source, decompiler, unsupported)."""
    # decompyle3 reliably supports Python 3.7-3.8.
    if py_ver in ("3.7", "3.8"):
        try:
            import decompyle3  # noqa: F401
            out = io.StringIO()
            from decompyle3.main import decompile as _decompile
            try:
                _decompile(code, out=out, timestamp=0)
                src = out.getvalue()
                if src:
                    truncated = len(src) > max_chars
                    return src[:max_chars], "decompyle3", False
            except Exception:
                pass
        except ImportError:
            pass
    # uncompyle6 supports 2.7 and 3.5-3.8.
    if py_ver in ("2.7", "3.5", "3.6", "3.7", "3.8"):
        try:
            import uncompyle6  # noqa: F401
            out = io.StringIO()
            from uncompyle6.main import decompile as _u_decompile
            try:
                _u_decompile(code, out=out, timestamp=0)
                src = out.getvalue()
                if src:
                    truncated = len(src) > max_chars
                    return src[:max_chars], "uncompyle6", False
            except Exception:
                pass
        except ImportError:
            pass
    # No compatible decompiler available for this version.
    unsupported = py_ver is not None and py_ver not in (
        "2.7", "3.5", "3.6", "3.7", "3.8")
    return None, None, unsupported


def main():
    payload = json.loads(sys.stdin.read())
    sample_path = payload["sample_path"]
    mode = payload.get("mode", "auto")
    max_src = int(payload.get("max_source_chars", 64000))
    max_dis = int(payload.get("max_disasm_lines", 2000))

    result = {
        "status": "setup_required",
        "decompiler_used": None,
        "python_version": None,
        "source": None,
        "disassembly": None,
        "source_truncated": False,
        "disasm_truncated": False,
        "code_object": None,
    }

    with open(sample_path, "rb") as f:
        raw = f.read()

    if len(raw) < 4:
        result["status"] = "invalid_pyc"
        emit(result)

    magic = raw[:4]
    result["code_object"] = {"magic_hex": magic.hex()}
    magic_int = struct.unpack("<H", magic[:2])[0]
    result["code_object"]["magic_int"] = magic_int

    header_size = header_size_for_magic(magic_int)
    body = raw[header_size:]

    py_ver = version_for_magic(magic_int)
    result["python_version"] = py_ver

    try:
        import marshal
        code = marshal.loads(body)
    except Exception as e:
        result["status"] = "invalid_pyc"
        result["code_object"]["error"] = str(e)
        emit(result)

    if not isinstance(code, types.CodeType):
        result["status"] = "invalid_pyc"
        result["code_object"]["error"] = "marshalled object is not a code object"
        emit(result)

    result["code_object"].update(collect_code_meta(code))

    disasm, disasm_trunc = try_disassemble(code, max_dis)
    result["disassembly"] = disasm
    result["disasm_truncated"] = disasm_trunc

    if mode == "disasm":
        result["status"] = "disasm_only"
        emit(result)

    source, decompiler, unsupported = try_decompile(code, py_ver, max_src)
    result["source"] = source
    result["source_truncated"] = bool(source) and len(source) >= max_src
    result["decompiler_used"] = decompiler

    if source:
        result["status"] = "source_recovered"
    elif unsupported:
        result["status"] = "unsupported_version"
    elif mode == "source":
        result["status"] = "setup_required"
    else:
        result["status"] = "disasm_only"

    emit(result)


if __name__ == "__main__":
    main()
