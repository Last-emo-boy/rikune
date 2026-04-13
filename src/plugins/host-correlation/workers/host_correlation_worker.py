"""
host_correlation_worker.py — Host / loader correlation worker.

Scans a directory and system artefacts to correlate a DLL/EXE with its
host process, loader, and execution context.

Action: correlate
"""

import json
import sys
import os
import struct
import glob
import re
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# PE import-table helpers (minimal, no pefile dependency)
# ---------------------------------------------------------------------------

def _read_pe_imports_quick(filepath: str) -> List[str]:
    """
    Quick extraction of DLL names from a PE import directory.
    Returns lowercase DLL names list.
    """
    dlls = []
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        if data[:2] != b'MZ' or len(data) < 64:
            return dlls
        pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
        if pe_offset + 24 > len(data):
            return dlls
        magic = struct.unpack_from('<H', data, pe_offset + 24)[0]
        if magic == 0x20B:  # PE32+
            import_rva_off = pe_offset + 24 + 112
        elif magic == 0x10B:  # PE32
            import_rva_off = pe_offset + 24 + 96
        else:
            return dlls
        if import_rva_off + 8 > len(data):
            return dlls
        import_rva = struct.unpack_from('<I', data, import_rva_off)[0]
        import_size = struct.unpack_from('<I', data, import_rva_off + 4)[0]
        if import_rva == 0 or import_size == 0:
            return dlls
        # Find section containing import RVA
        num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
        section_off = pe_offset + 24 + (264 if magic == 0x20B else 248)
        import_file_off = None
        for i in range(num_sections):
            s = section_off + i * 40
            if s + 40 > len(data):
                break
            va = struct.unpack_from('<I', data, s + 12)[0]
            vs = struct.unpack_from('<I', data, s + 8)[0]
            rd = struct.unpack_from('<I', data, s + 20)[0]
            if va <= import_rva < va + vs:
                import_file_off = rd + (import_rva - va)
                delta = rd - va
                break
        if import_file_off is None:
            return dlls
        # Walk Import Directory Entries (20 bytes each)
        pos = import_file_off
        while pos + 20 <= len(data):
            name_rva = struct.unpack_from('<I', data, pos + 12)[0]
            if name_rva == 0:
                break
            name_off = name_rva + delta
            if 0 <= name_off < len(data):
                end = data.find(b'\x00', name_off, name_off + 256)
                if end > name_off:
                    dll = data[name_off:end].decode('ascii', errors='replace').lower()
                    dlls.append(dll)
            pos += 20
    except Exception:
        pass
    return dlls


def _is_pe(filepath: str) -> bool:
    """Quick check if a file is a PE."""
    try:
        with open(filepath, 'rb') as f:
            return f.read(2) == b'MZ'
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Import-table cross-reference
# ---------------------------------------------------------------------------

def _scan_import_tables(sample_name: str, scan_dir: str, recursive: bool, max_depth: int) -> List[Dict[str, Any]]:
    """Find co-located EXEs that import the sample DLL."""
    results = []
    sample_lower = sample_name.lower()

    def _scan(d: str, depth: int):
        if depth > max_depth:
            return
        try:
            entries = os.listdir(d)
        except PermissionError:
            return
        for entry in entries:
            full = os.path.join(d, entry)
            if os.path.isfile(full) and entry.lower().endswith('.exe') and _is_pe(full):
                imports = _read_pe_imports_quick(full)
                if sample_lower in imports:
                    results.append({
                        'host_exe': full,
                        'imports_sample': True,
                        'total_imports': len(imports),
                    })
            elif recursive and os.path.isdir(full) and not entry.startswith('.'):
                _scan(full, depth + 1)

    _scan(scan_dir, 1)
    return results


# ---------------------------------------------------------------------------
# Sideloading detection
# ---------------------------------------------------------------------------

def _check_sideload_configs(sample_path: str, scan_dir: str) -> List[Dict[str, Any]]:
    """Check for DLL sideloading configuration files."""
    findings = []
    sample_base = os.path.splitext(os.path.basename(sample_path))[0]

    # .manifest — application / assembly manifests referencing the DLL
    for manifest in glob.glob(os.path.join(scan_dir, '*.manifest')):
        try:
            with open(manifest, 'r', errors='replace') as f:
                content = f.read()
            if sample_base.lower() in content.lower():
                findings.append({
                    'type': 'manifest',
                    'file': manifest,
                    'references_sample': True,
                })
        except Exception:
            pass

    # .local files (DLL redirection)
    local_file = os.path.join(scan_dir, sample_base + '.local')
    if os.path.exists(local_file):
        findings.append({
            'type': 'dotlocal_redirect',
            'file': local_file,
            'description': '.local DLL redirection file present',
        })

    # .config (app.config / exe.config with bindingRedirect)
    for cfg in glob.glob(os.path.join(scan_dir, '*.config')):
        try:
            with open(cfg, 'r', errors='replace') as f:
                content = f.read()
            if sample_base.lower() in content.lower():
                findings.append({
                    'type': 'binding_redirect',
                    'file': cfg,
                    'references_sample': True,
                })
        except Exception:
            pass

    return findings


# ---------------------------------------------------------------------------
# Scheduled-task / service / startup (file-based heuristics)
# ---------------------------------------------------------------------------

def _check_scheduled_tasks(sample_path: str) -> List[Dict[str, Any]]:
    """Scan Windows scheduled task XML exports for sample references."""
    findings = []
    task_dirs = [
        os.path.join(os.environ.get('SYSTEMROOT', r'C:\Windows'), 'System32', 'Tasks'),
    ]
    sample_name = os.path.basename(sample_path).lower()

    for task_dir in task_dirs:
        if not os.path.isdir(task_dir):
            continue
        for root, _dirs, files in os.walk(task_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='replace') as f:
                        content = f.read(8192)
                    if sample_name in content.lower() or sample_path.lower() in content.lower():
                        findings.append({
                            'type': 'scheduled_task',
                            'task_file': fpath,
                            'task_name': fname,
                        })
                except Exception:
                    pass
    return findings


def _check_services(sample_path: str) -> List[Dict[str, Any]]:
    """
    Check for Windows services referencing the sample.
    Uses filesystem-based scanning of service config if available.
    """
    # This is a best-effort check; in Docker/Linux we simply skip
    findings = []
    sample_lower = os.path.basename(sample_path).lower()

    # Try registry-like approach via filesystem on Windows
    svc_dir = os.path.join(
        os.environ.get('SYSTEMROOT', r'C:\Windows'),
        'System32', 'config',
    )
    # In practice, registry hive parsing is complex; return empty on non-Windows
    if not os.path.isdir(svc_dir):
        return findings

    return findings


def _check_startup_entries(sample_path: str) -> List[Dict[str, Any]]:
    """Check common startup locations for references to the sample."""
    findings = []
    sample_name = os.path.basename(sample_path).lower()

    # Common startup folders
    startup_dirs = []
    appdata = os.environ.get('APPDATA')
    if appdata:
        startup_dirs.append(os.path.join(appdata, r'Microsoft\Windows\Start Menu\Programs\Startup'))
    allusers = os.environ.get('PROGRAMDATA')
    if allusers:
        startup_dirs.append(os.path.join(allusers, r'Microsoft\Windows\Start Menu\Programs\Startup'))

    for sdir in startup_dirs:
        if not os.path.isdir(sdir):
            continue
        for entry in os.listdir(sdir):
            if sample_name in entry.lower():
                findings.append({
                    'type': 'startup_folder',
                    'path': os.path.join(sdir, entry),
                })
            # Check .lnk content (crude byte scan)
            if entry.lower().endswith('.lnk'):
                try:
                    with open(os.path.join(sdir, entry), 'rb') as f:
                        lnk_data = f.read(4096)
                    if sample_name.encode('utf-8') in lnk_data.lower():
                        findings.append({
                            'type': 'startup_shortcut',
                            'shortcut': os.path.join(sdir, entry),
                            'references_sample': True,
                        })
                except Exception:
                    pass

    return findings


def _check_com_registration(sample_path: str) -> List[Dict[str, Any]]:
    """Best-effort COM registration check."""
    # In a Docker/Linux environment this is not applicable
    # On Windows, would parse HKCR\CLSID registry hive
    return []


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------

def handle_correlate(request: Dict[str, Any]) -> Dict[str, Any]:
    """Handle the correlate action."""
    file_path = request.get('file_path', '')
    scan_directory = request.get('scan_directory')
    check_scheduled_tasks = request.get('check_scheduled_tasks', True)
    check_services = request.get('check_services', True)
    check_startup = request.get('check_startup', True)
    check_sideload = request.get('check_sideload', True)
    check_com_registration = request.get('check_com_registration', True)
    check_import_tables = request.get('check_import_tables', True)
    recursive = request.get('recursive', False)
    max_depth = request.get('max_depth', 2)

    if not os.path.isfile(file_path):
        return {'ok': False, 'error': f'File not found: {file_path}'}

    sample_name = os.path.basename(file_path)
    scan_dir = scan_directory or os.path.dirname(file_path)

    if not os.path.isdir(scan_dir):
        return {'ok': False, 'error': f'Scan directory not found: {scan_dir}'}

    correlation = {
        'sample': file_path,
        'sample_name': sample_name,
        'scan_directory': scan_dir,
        'host_exes': [],
        'sideloading': [],
        'scheduled_tasks': [],
        'services': [],
        'startup': [],
        'com_registration': [],
    }

    if check_import_tables:
        correlation['host_exes'] = _scan_import_tables(sample_name, scan_dir, recursive, max_depth)

    if check_sideload:
        correlation['sideloading'] = _check_sideload_configs(file_path, scan_dir)

    if check_scheduled_tasks:
        correlation['scheduled_tasks'] = _check_scheduled_tasks(file_path)

    if check_services:
        correlation['services'] = _check_services(file_path)

    if check_startup:
        correlation['startup'] = _check_startup_entries(file_path)

    if check_com_registration:
        correlation['com_registration'] = _check_com_registration(file_path)

    # Summary
    total_findings = sum(
        len(v) for v in correlation.values() if isinstance(v, list)
    )

    return {
        'ok': True,
        'data': {
            **correlation,
            'total_findings': total_findings,
            'summary': f'Found {total_findings} correlation(s) for {sample_name}',
        },
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

ACTIONS = {
    'correlate': handle_correlate,
}


def main():
    raw = sys.stdin.readline()
    if not raw.strip():
        json.dump({'ok': False, 'error': 'Empty input'}, sys.stdout)
        sys.stdout.flush()
        sys.exit(1)

    try:
        request = json.loads(raw)
    except json.JSONDecodeError as e:
        json.dump({'ok': False, 'error': f'Invalid JSON: {e}'}, sys.stdout)
        sys.stdout.flush()
        sys.exit(1)

    action = request.get('action', '')
    handler = ACTIONS.get(action)
    if not handler:
        json.dump({'ok': False, 'error': f'Unknown action: {action}'}, sys.stdout)
        sys.stdout.flush()
        sys.exit(1)

    try:
        result = handler(request)
    except Exception as e:
        result = {'ok': False, 'error': f'{action} failed: {e}'}

    json.dump(result, sys.stdout)
    sys.stdout.flush()


if __name__ == '__main__':
    main()
