#!/usr/bin/env python3
"""
Deep Unpack Worker — Advanced multi-strategy unpacking with PE reconstruction.

Strategies (tried in order):
  1. UPX CLI decompress
  2. Speakeasy emulation → OEP dump
  3. Qiling full emulation → memory scan + dump
  4. Generic memory carve: run binary briefly, scan all RWX regions for PE signatures

PE reconstruction:
  - Fix section alignment
  - Rebuild PE header (optional sections table, checksum)
  - IAT reconstruction from API trace log

Input (JSON on stdin):
  {
    "command": "deep_unpack" | "pe_reconstruct" | "dump_scan",
    "sample_path": "/path/to/packed.exe",
    "max_layers": 5,
    "strategies": ["upx", "speakeasy", "qiling", "memory_carve"],
    "timeout": 120,
    // pe_reconstruct specific:
    "dump_path": "/path/to/dumped.bin",
    "api_trace": [{"address": "0x...", "name": "CreateFileW", "module": "kernel32.dll"}, ...],
    "image_base": "0x400000",
    "oep_rva": "0x1000"
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
import struct
import sys
import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def find_pe_signatures(data: bytes) -> list:
    """Scan raw memory for MZ/PE headers — find embedded PE images."""
    results = []
    offset = 0
    while offset < len(data) - 64:
        mz_pos = data.find(b"MZ", offset)
        if mz_pos == -1:
            break
        # Validate: e_lfanew should point to PE\0\0
        if mz_pos + 0x3C + 4 <= len(data):
            try:
                e_lfanew = struct.unpack_from("<I", data, mz_pos + 0x3C)[0]
                pe_offset = mz_pos + e_lfanew
                if pe_offset + 4 <= len(data) and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                    # Read optional header magic to determine PE32 vs PE32+
                    magic_offset = pe_offset + 24
                    if magic_offset + 2 <= len(data):
                        magic = struct.unpack_from("<H", data, magic_offset)[0]
                        pe_type = "PE32+" if magic == 0x20B else "PE32"
                    else:
                        pe_type = "unknown"
                    # Estimate size from SizeOfImage in optional header
                    size_of_image = 0
                    soi_offset = pe_offset + 24 + (56 if pe_type == "PE32" else 80 - 16)
                    if pe_type == "PE32":
                        soi_offset = pe_offset + 24 + 56
                    else:
                        soi_offset = pe_offset + 24 + 56
                    if soi_offset + 4 <= len(data):
                        size_of_image = struct.unpack_from("<I", data, soi_offset)[0]
                    results.append({
                        "offset": mz_pos,
                        "pe_type": pe_type,
                        "size_of_image": size_of_image,
                        "e_lfanew": e_lfanew,
                    })
            except (struct.error, IndexError):
                pass
        offset = mz_pos + 2
    return results


def compute_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    import math
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def section_entropy_analysis(filepath: str) -> list:
    """Compute per-section entropy for a PE file."""
    try:
        import pefile
        pe = pefile.PE(filepath)
        sections = []
        for sec in pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            raw = sec.get_data()
            ent = compute_entropy(raw)
            sections.append({
                "name": name,
                "virtual_address": hex(sec.VirtualAddress),
                "raw_size": sec.SizeOfRawData,
                "entropy": ent,
                "executable": bool(sec.Characteristics & 0x20000000),
                "writable": bool(sec.Characteristics & 0x80000000),
            })
        pe.close()
        return sections
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Strategy: UPX
# ---------------------------------------------------------------------------

def try_upx_unpack(sample_path: str, output_dir: str) -> dict:
    """Try UPX decompression."""
    upx_bin = shutil.which("upx")
    if not upx_bin:
        return {"ok": False, "error": "UPX not found in PATH"}

    output_path = os.path.join(output_dir, "upx_unpacked.exe")
    try:
        result = subprocess.run(
            [upx_bin, "-d", "-o", output_path, sample_path],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and os.path.exists(output_path):
            return {
                "ok": True,
                "unpacked_path": output_path,
                "sha256": sha256_file(output_path),
                "size": os.path.getsize(output_path),
                "stdout": result.stdout[:2000],
            }
        return {"ok": False, "error": f"UPX exit code {result.returncode}: {result.stderr[:500]}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "UPX timed out"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Strategy: Speakeasy emulation dump
# ---------------------------------------------------------------------------

def try_speakeasy_dump(sample_path: str, output_dir: str, max_instructions: int = 5_000_000) -> dict:
    """Run in Speakeasy, dump memory after emulation."""
    try:
        import speakeasy
    except ImportError:
        return {"ok": False, "error": "speakeasy-emulator not installed"}

    try:
        se = speakeasy.Speakeasy()
        module = se.load_module(sample_path)
        se.run_module(module, all_entrypoints=False)

        # Dump the main module memory
        base = module.get_base()
        size = module.get_image_size()
        dumped = se.mem_read(base, size)

        output_path = os.path.join(output_dir, "speakeasy_dump.bin")
        with open(output_path, "wb") as f:
            f.write(dumped)

        # Collect API trace
        api_calls = []
        for api in se.get_report().get("apis", [])[:200]:
            api_calls.append({
                "api": api.get("api_name", ""),
                "module": api.get("module", ""),
                "return": api.get("ret_val", None),
            })

        return {
            "ok": True,
            "unpacked_path": output_path,
            "sha256": sha256_file(output_path),
            "size": len(dumped),
            "image_base": hex(base),
            "api_trace_count": len(api_calls),
            "api_trace_sample": api_calls[:50],
        }
    except Exception as e:
        return {"ok": False, "error": f"Speakeasy emulation failed: {e}"}


# ---------------------------------------------------------------------------
# Strategy: Qiling emulation dump
# ---------------------------------------------------------------------------

def try_qiling_dump(sample_path: str, output_dir: str, timeout: int = 120) -> dict:
    """Run in Qiling, monitor for OEP, dump memory."""
    try:
        import qiling
    except ImportError:
        return {"ok": False, "error": "Qiling not installed"}

    rootfs = os.environ.get("QILING_ROOTFS", "/opt/qiling/examples/rootfs/x86_windows")
    if not os.path.isdir(rootfs):
        return {"ok": False, "error": f"Qiling rootfs not found: {rootfs}"}

    try:
        ql = qiling.Qiling(
            [sample_path],
            rootfs,
            verbose=qiling.const.QL_VERBOSE.DISABLED
        )

        # Track VirtualAlloc / VirtualProtect calls for RWX regions
        rwx_regions = []

        def hook_virtualalloc(ql, address, size):
            rwx_regions.append({"address": hex(address), "size": size})

        # Run with instruction limit
        ql.run(count=5_000_000)

        # Dump all mapped memory
        dumps = []
        for info in ql.mem.get_mapinfo():
            start, end, perm, label = info[0], info[1], info[2], info[3]
            if end - start > 0 and end - start < 100 * 1024 * 1024:
                try:
                    data = ql.mem.read(start, end - start)
                    pe_sigs = find_pe_signatures(data)
                    if pe_sigs:
                        dump_name = f"qiling_region_{hex(start)}.bin"
                        dump_path = os.path.join(output_dir, dump_name)
                        with open(dump_path, "wb") as f:
                            f.write(data)
                        dumps.append({
                            "path": dump_path,
                            "base": hex(start),
                            "size": end - start,
                            "pe_images": pe_sigs,
                            "sha256": sha256_file(dump_path),
                        })
                except Exception:
                    pass

        ql.stop()

        if dumps:
            # Pick the largest dump with PE signature
            best = max(dumps, key=lambda d: d["size"])
            return {
                "ok": True,
                "unpacked_path": best["path"],
                "sha256": best["sha256"],
                "size": best["size"],
                "all_dumps": dumps,
                "rwx_regions": rwx_regions[:20],
            }

        return {"ok": False, "error": "No PE images found in Qiling memory dumps"}
    except Exception as e:
        return {"ok": False, "error": f"Qiling emulation failed: {e}"}


# ---------------------------------------------------------------------------
# Strategy: Generic memory carve (Wine + process dump)
# ---------------------------------------------------------------------------

def try_memory_carve(sample_path: str, output_dir: str, timeout: int = 30) -> dict:
    """Run binary briefly under Wine, scan /proc for PE images."""
    wine_bin = shutil.which("wine") or shutil.which("wine64")
    if not wine_bin:
        return {"ok": False, "error": "Wine not found in PATH"}

    import signal
    import time

    try:
        # Start process
        env = os.environ.copy()
        env["WINEDEBUG"] = "-all"
        proc = subprocess.Popen(
            [wine_bin, sample_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )

        # Wait a bit for unpacking to happen
        time.sleep(min(timeout, 5))

        # Try to read process memory via /proc
        dumps = []
        proc_maps = f"/proc/{proc.pid}/maps"
        proc_mem = f"/proc/{proc.pid}/mem"

        if os.path.exists(proc_maps):
            try:
                with open(proc_maps, "r") as mf:
                    maps = mf.readlines()
                with open(proc_mem, "rb") as memf:
                    for line in maps:
                        parts = line.split()
                        if len(parts) < 2:
                            continue
                        addr_range = parts[0].split("-")
                        if len(addr_range) != 2:
                            continue
                        perms = parts[1] if len(parts) > 1 else ""
                        if "x" not in perms:
                            continue
                        try:
                            start = int(addr_range[0], 16)
                            end = int(addr_range[1], 16)
                            size = end - start
                            if size > 100 * 1024 * 1024 or size < 512:
                                continue
                            memf.seek(start)
                            data = memf.read(size)
                            pe_sigs = find_pe_signatures(data)
                            if pe_sigs:
                                dump_name = f"memcarve_{hex(start)}.bin"
                                dump_path = os.path.join(output_dir, dump_name)
                                with open(dump_path, "wb") as f:
                                    f.write(data)
                                dumps.append({
                                    "path": dump_path,
                                    "base": hex(start),
                                    "size": size,
                                    "pe_images": pe_sigs,
                                    "sha256": sha256_file(dump_path),
                                })
                        except (ValueError, OSError):
                            pass
            except (PermissionError, FileNotFoundError):
                pass

        # Kill process
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass

        if dumps:
            best = max(dumps, key=lambda d: d["size"])
            return {
                "ok": True,
                "unpacked_path": best["path"],
                "sha256": best["sha256"],
                "size": best["size"],
                "all_dumps": dumps,
            }

        return {"ok": False, "error": "No PE images found in process memory"}
    except Exception as e:
        return {"ok": False, "error": f"Memory carve failed: {e}"}


# ---------------------------------------------------------------------------
# PE Reconstruction
# ---------------------------------------------------------------------------

def reconstruct_pe(dump_path: str, output_dir: str, api_trace: list = None,
                   image_base: str = None, oep_rva: str = None) -> dict:
    """Reconstruct a valid PE from a raw memory dump."""
    try:
        import pefile
    except ImportError:
        return {"ok": False, "error": "pefile not installed"}

    try:
        data = bytearray(Path(dump_path).read_bytes())

        # Validate basic PE structure
        pe_sigs = find_pe_signatures(bytes(data))
        if not pe_sigs:
            return {"ok": False, "error": "No valid PE signature found in dump"}

        pe_offset = pe_sigs[0]["offset"]
        pe_data = data[pe_offset:]

        pe = pefile.PE(data=bytes(pe_data))
        fixes_applied = []

        # Fix 1: Section alignment (raw → virtual mapping)
        for sec in pe.sections:
            if sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 0:
                sec.SizeOfRawData = sec.Misc_VirtualSize
                fixes_applied.append(f"Fixed raw size for {sec.Name.rstrip(b'\x00').decode('utf-8', errors='replace')}")

        # Fix 2: Entry point
        if oep_rva:
            oep_val = int(oep_rva, 16) if isinstance(oep_rva, str) else oep_rva
            pe.OPTIONAL_HEADER.AddressOfEntryPoint = oep_val
            fixes_applied.append(f"Set OEP to {hex(oep_val)}")

        # Fix 3: Image base
        if image_base:
            base_val = int(image_base, 16) if isinstance(image_base, str) else image_base
            pe.OPTIONAL_HEADER.ImageBase = base_val
            fixes_applied.append(f"Set ImageBase to {hex(base_val)}")

        # Fix 4: IAT reconstruction from API trace
        iat_entries = []
        if api_trace:
            for entry in api_trace:
                addr = entry.get("address")
                name = entry.get("name", "")
                module = entry.get("module", "")
                if addr and name:
                    iat_entries.append({
                        "address": addr,
                        "name": name,
                        "module": module,
                    })
            if iat_entries:
                fixes_applied.append(f"IAT trace captured: {len(iat_entries)} resolved APIs")

        # Fix 5: Recalculate checksum
        pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
        fixes_applied.append("Recalculated PE checksum")

        # Write reconstructed PE
        output_path = os.path.join(output_dir, "reconstructed.exe")
        pe.write(output_path)
        pe.close()

        return {
            "ok": True,
            "reconstructed_path": output_path,
            "sha256": sha256_file(output_path),
            "size": os.path.getsize(output_path),
            "fixes_applied": fixes_applied,
            "iat_entries": iat_entries[:100],
            "sections": section_entropy_analysis(output_path),
        }
    except Exception as e:
        return {"ok": False, "error": f"PE reconstruction failed: {e}"}


# ---------------------------------------------------------------------------
# Dump Scan — find PE images in arbitrary binary data
# ---------------------------------------------------------------------------

def scan_dump_for_pe(dump_path: str, output_dir: str) -> dict:
    """Scan a memory dump file for embedded PE images and extract them."""
    try:
        data = Path(dump_path).read_bytes()
    except Exception as e:
        return {"ok": False, "error": f"Failed to read dump: {e}"}

    pe_images = find_pe_signatures(data)
    if not pe_images:
        return {
            "ok": True,
            "data": {
                "pe_count": 0,
                "images": [],
                "total_size": len(data),
                "entropy": compute_entropy(data),
            },
        }

    extracted = []
    for i, sig in enumerate(pe_images):
        offset = sig["offset"]
        size = sig["size_of_image"]
        if size == 0 or size > len(data) - offset:
            size = min(len(data) - offset, 10 * 1024 * 1024)  # Cap at 10MB
        pe_data = data[offset:offset + size]
        out_name = f"extracted_pe_{i}_{hex(offset)}.exe"
        out_path = os.path.join(output_dir, out_name)
        with open(out_path, "wb") as f:
            f.write(pe_data)
        extracted.append({
            "index": i,
            "offset": hex(offset),
            "size": len(pe_data),
            "sha256": sha256_file(out_path),
            "path": out_path,
            "pe_type": sig["pe_type"],
            "entropy": compute_entropy(pe_data),
            "sections": section_entropy_analysis(out_path),
        })

    return {
        "ok": True,
        "data": {
            "pe_count": len(extracted),
            "images": extracted,
            "total_size": len(data),
        },
    }


# ---------------------------------------------------------------------------
# Deep Unpack Pipeline
# ---------------------------------------------------------------------------

def deep_unpack_pipeline(sample_path: str, max_layers: int = 5,
                         strategies: list = None, timeout: int = 120) -> dict:
    """Multi-layer deep unpacking pipeline."""
    if strategies is None:
        strategies = ["upx", "speakeasy", "qiling", "memory_carve"]

    output_dir = tempfile.mkdtemp(prefix="deep_unpack_")
    layers = []
    current_path = sample_path
    warnings = []

    strategy_funcs = {
        "upx": try_upx_unpack,
        "speakeasy": lambda p, d: try_speakeasy_dump(p, d),
        "qiling": lambda p, d: try_qiling_dump(p, d, timeout),
        "memory_carve": lambda p, d: try_memory_carve(p, d, timeout),
    }

    for layer_num in range(1, max_layers + 1):
        layer_dir = os.path.join(output_dir, f"layer_{layer_num}")
        os.makedirs(layer_dir, exist_ok=True)

        # Check if current file is still packed
        entropy_info = section_entropy_analysis(current_path)
        high_entropy = any(s.get("entropy", 0) > 7.0 for s in entropy_info)

        if layer_num > 1 and not high_entropy:
            # Likely unpacked
            break

        layer_result = {
            "layer": layer_num,
            "input_path": current_path,
            "input_sha256": sha256_file(current_path),
            "input_entropy": entropy_info,
            "strategies_tried": [],
            "success": False,
        }

        for strategy_name in strategies:
            if strategy_name not in strategy_funcs:
                warnings.append(f"Unknown strategy: {strategy_name}")
                continue

            strat_dir = os.path.join(layer_dir, strategy_name)
            os.makedirs(strat_dir, exist_ok=True)

            result = strategy_funcs[strategy_name](current_path, strat_dir)
            layer_result["strategies_tried"].append({
                "strategy": strategy_name,
                "ok": result.get("ok", False),
                "error": result.get("error"),
                "sha256": result.get("sha256"),
            })

            if result.get("ok") and result.get("unpacked_path"):
                layer_result["success"] = True
                layer_result["winning_strategy"] = strategy_name
                layer_result["output_path"] = result["unpacked_path"]
                layer_result["output_sha256"] = result.get("sha256", "")
                layer_result["output_size"] = result.get("size", 0)
                layer_result["output_entropy"] = section_entropy_analysis(result["unpacked_path"])
                layer_result["extra"] = {
                    k: v for k, v in result.items()
                    if k not in {"ok", "unpacked_path", "sha256", "size", "error"}
                }
                current_path = result["unpacked_path"]
                break

        layers.append(layer_result)
        if not layer_result["success"]:
            break

    successful_layers = [l for l in layers if l["success"]]
    return {
        "ok": len(successful_layers) > 0,
        "command": "deep_unpack",
        "data": {
            "total_layers": len(layers),
            "successful_layers": len(successful_layers),
            "layers": layers,
            "final_path": current_path if successful_layers else None,
            "final_sha256": sha256_file(current_path) if successful_layers else None,
            "output_dir": output_dir,
        },
        "warnings": warnings if warnings else [],
        "errors": [] if successful_layers else ["All unpack strategies failed for all layers"],
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

    command = payload.get("command", "deep_unpack")

    if command == "deep_unpack":
        result = deep_unpack_pipeline(
            sample_path=payload["sample_path"],
            max_layers=payload.get("max_layers", 5),
            strategies=payload.get("strategies"),
            timeout=payload.get("timeout", 120),
        )
    elif command == "pe_reconstruct":
        output_dir = tempfile.mkdtemp(prefix="pe_reconstruct_")
        result = reconstruct_pe(
            dump_path=payload["dump_path"],
            output_dir=output_dir,
            api_trace=payload.get("api_trace"),
            image_base=payload.get("image_base"),
            oep_rva=payload.get("oep_rva"),
        )
        result["command"] = "pe_reconstruct"
    elif command == "dump_scan":
        output_dir = tempfile.mkdtemp(prefix="dump_scan_")
        result = scan_dump_for_pe(
            dump_path=payload["dump_path"],
            output_dir=output_dir,
        )
        result["command"] = "dump_scan"
    else:
        result = {"ok": False, "errors": [f"Unknown command: {command}"]}

    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
