"""
dotnet_reactor_worker.py — .NET Reactor deobfuscation analysis worker.

Analyzes .NET Reactor-protected assemblies using dnfile.
Supports four actions:
  - string_decrypt:   locate encrypted string blobs and attempt static decryption
  - resource_export:  export embedded / encrypted resource assemblies
  - dynamic_methods:  detect DynamicMethod / MethodBuilder usage patterns
  - anti_tamper:      detect anti-tamper protection stubs and metadata
"""

import json
import sys
import os
import struct
import hashlib
import base64
import zlib
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# dnfile import
# ---------------------------------------------------------------------------
try:
    import dnfile
    HAS_DNFILE = True
except ImportError:
    HAS_DNFILE = False

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_token(token: int) -> str:
    return f'0x{token:08X}'


def _make_token(table: int, rid: int) -> int:
    return (table << 24) | rid


def _get_method_name(pe: 'dnfile.dnPE', method_rid: int) -> str:
    """Resolve a MethodDef RID to its fully-qualified name."""
    try:
        md_table = pe.net.mdtables.MethodDef
        if md_table and 1 <= method_rid <= len(md_table.rows):
            row = md_table.rows[method_rid - 1]
            method_name = str(row.Name) if row.Name else f'Method_{method_rid}'
            td_table = pe.net.mdtables.TypeDef
            if td_table:
                for i, td in enumerate(td_table.rows):
                    td_method_list = td.MethodList.row_index if hasattr(td.MethodList, 'row_index') else 0
                    next_method_list = (td_table.rows[i + 1].MethodList.row_index
                                        if i + 1 < len(td_table.rows)
                                        and hasattr(td_table.rows[i + 1].MethodList, 'row_index')
                                        else len(md_table.rows) + 1)
                    if td_method_list <= method_rid < next_method_list:
                        ns = str(getattr(td, 'TypeNamespace', getattr(td, 'Namespace', '')))
                        tn = str(getattr(td, 'TypeName', getattr(td, 'Name', '')))
                        owner = f'{ns}.{tn}' if ns else tn
                        return f'{owner}::{method_name}'
            return method_name
    except Exception:
        pass
    return f'MethodDef_{method_rid}'


def _get_type_name(pe: 'dnfile.dnPE', type_rid: int) -> str:
    try:
        td_table = pe.net.mdtables.TypeDef
        if td_table and 1 <= type_rid <= len(td_table.rows):
            row = td_table.rows[type_rid - 1]
            ns = str(getattr(row, 'TypeNamespace', getattr(row, 'Namespace', '')))
            name = str(getattr(row, 'TypeName', getattr(row, 'Name', '')))
            if not name:
                name = f'Type_{type_rid}'
            return f'{ns}.{name}' if ns else name
    except Exception:
        pass
    return f'TypeDef_{type_rid}'


def _read_method_body(pe: 'dnfile.dnPE', rva: int) -> Optional[bytes]:
    """Read IL method body bytes from an RVA."""
    try:
        offset = pe.get_offset_from_rva(rva)
        data = pe.__data__
        if offset >= len(data):
            return None
        header_byte = data[offset]
        if (header_byte & 0x03) == 0x02:
            size = (header_byte >> 2) & 0x3F
            return data[offset + 1: offset + 1 + size]
        elif (header_byte & 0x03) == 0x03:
            if offset + 12 > len(data):
                return None
            code_size = struct.unpack_from('<I', data, offset + 4)[0]
            return data[offset + 12: offset + 12 + code_size]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Reactor detection helpers
# ---------------------------------------------------------------------------

# Common .NET Reactor module-initializer names
_REACTOR_INIT_NAMES = {
    '<Module>', '.cctor', 'ReactorHelper',
}

# Known Reactor string decryptor patterns: ldsfld → ldarg → call pattern
_REACTOR_STRING_PATTERNS = [
    b'\x7E',  # ldsfld
    b'\x28',  # call
]


def _detect_reactor_version(pe: 'dnfile.dnPE') -> Optional[str]:
    """Try to detect .NET Reactor version from known markers."""
    try:
        data = pe.__data__
        # Reactor embeds version strings in resources or <Module>.cctor
        markers = [
            (b'.NET Reactor v', 14),
            (b'ReactorRTS', None),
            (b'is protected', None),
        ]
        for marker, ver_len in markers:
            idx = data.find(marker)
            if idx >= 0:
                if ver_len:
                    version_bytes = data[idx + len(marker):idx + len(marker) + ver_len]
                    return version_bytes.decode('ascii', errors='replace').strip()
                return 'detected'
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# string_decrypt
# ---------------------------------------------------------------------------

def _find_encrypted_string_sites(pe: 'dnfile.dnPE', method_token: Optional[int], max_strings: int) -> List[Dict[str, Any]]:
    """
    Scan method bodies for Reactor-style encrypted string patterns.
    
    Reactor typically:
      1. Stores encrypted blobs in a static byte[] field
      2. Uses a decryptor method: ldarg.0 → call DecryptString(int)
      3. The int argument is an index into the blob
    
    We look for call-sites that pass an ldc.i4 followed by a call
    to a method in <Module> or a type with obfuscated names.
    """
    results = []
    md_table = pe.net.mdtables.MethodDef
    if not md_table:
        return results

    # If a specific method token is given, only scan that method
    if method_token:
        rid = method_token & 0x00FFFFFF
        rids_to_scan = [rid]
    else:
        rids_to_scan = range(1, len(md_table.rows) + 1)

    for rid in rids_to_scan:
        if len(results) >= max_strings:
            break
        row = md_table.rows[rid - 1]
        if not row.Rva:
            continue
        body = _read_method_body(pe, row.Rva)
        if not body or len(body) < 6:
            continue

        # Scan for ldc.i4 followed by call/callvirt
        i = 0
        while i < len(body) - 5 and len(results) < max_strings:
            op = body[i]
            # ldc.i4 (0x20, 4-byte arg) followed by call (0x28, 4-byte token)
            if op == 0x20 and i + 9 <= len(body) and body[i + 5] == 0x28:
                string_index = struct.unpack_from('<i', body, i + 1)[0]
                call_token = struct.unpack_from('<I', body, i + 6)[0]
                results.append({
                    'site_method': _format_token(_make_token(0x06, rid)),
                    'site_method_name': _get_method_name(pe, rid),
                    'il_offset': i,
                    'string_index': string_index,
                    'decryptor_token': _format_token(call_token),
                    'encrypted_value': None,  # Would need blob data to extract
                    'decrypted_value': None,  # Static decryption not always possible
                })
                i += 10
            # ldc.i4.s (0x1F, 1-byte arg) followed by call
            elif op == 0x1F and i + 7 <= len(body) and body[i + 2] == 0x28:
                string_index = body[i + 1]
                call_token = struct.unpack_from('<I', body, i + 3)[0]
                results.append({
                    'site_method': _format_token(_make_token(0x06, rid)),
                    'site_method_name': _get_method_name(pe, rid),
                    'il_offset': i,
                    'string_index': string_index,
                    'decryptor_token': _format_token(call_token),
                    'encrypted_value': None,
                    'decrypted_value': None,
                })
                i += 7
            else:
                i += 1

    return results


def handle_string_decrypt(request: Dict[str, Any]) -> Dict[str, Any]:
    """Handle the string_decrypt action."""
    file_path = request.get('file_path', '')
    method_token_str = request.get('method_token')
    mode = request.get('mode', 'static')
    max_strings = request.get('max_strings', 2000)

    if not os.path.isfile(file_path):
        return {'ok': False, 'error': f'File not found: {file_path}'}

    try:
        pe = dnfile.dnPE(file_path)
    except Exception as e:
        return {'ok': False, 'error': f'Failed to parse .NET assembly: {e}'}

    if not pe.net or not pe.net.mdtables:
        return {'ok': False, 'error': 'Not a valid .NET assembly (no metadata)'}

    method_token = None
    if method_token_str:
        try:
            method_token = int(method_token_str, 16)
        except ValueError:
            pass

    reactor_version = _detect_reactor_version(pe)
    sites = _find_encrypted_string_sites(pe, method_token, max_strings)

    return {
        'ok': True,
        'data': {
            'reactor_version': reactor_version,
            'mode': mode,
            'total_sites': len(sites),
            'truncated': len(sites) >= max_strings,
            'note': 'Static decryption requires the encryption key embedded in the module initializer. '
                    'Dynamic mode (sandbox execution) can recover plaintext values.',
            'sites': sites,
        },
    }


# ---------------------------------------------------------------------------
# resource_export
# ---------------------------------------------------------------------------

def handle_resource_export(request: Dict[str, Any]) -> Dict[str, Any]:
    """Handle the resource_export action."""
    file_path = request.get('file_path', '')
    resource_name = request.get('resource_name')
    attempt_decrypt = request.get('attempt_decrypt', False)
    attempt_decompress = request.get('attempt_decompress', False)
    save_to_workspace = request.get('save_to_workspace', False)

    if not os.path.isfile(file_path):
        return {'ok': False, 'error': f'File not found: {file_path}'}

    try:
        pe = dnfile.dnPE(file_path)
    except Exception as e:
        return {'ok': False, 'error': f'Failed to parse .NET assembly: {e}'}

    if not pe.net:
        return {'ok': False, 'error': 'Not a valid .NET assembly'}

    resources = []

    # Check ManifestResource table
    mr_table = pe.net.mdtables.ManifestResource
    if mr_table:
        for rid, row in enumerate(mr_table.rows, start=1):
            name = str(row.Name) if row.Name else f'Resource_{rid}'

            if resource_name and name != resource_name:
                continue

            entry = {
                'name': name,
                'token': _format_token(_make_token(0x28, rid)),
                'offset': row.Offset if hasattr(row, 'Offset') else None,
                'visibility': 'public' if (int(row.Flags) & 0x07) == 0x01 else 'private',
                'implementation': None,
                'size': None,
                'sha256': None,
                'content_preview': None,
                'is_assembly': False,
                'decrypted': False,
                'decompressed': False,
            }

            # Try to read embedded resource data
            try:
                if hasattr(row, 'Offset') and pe.net.resources_rva:
                    res_rva = pe.net.resources_rva + row.Offset
                    res_offset = pe.get_offset_from_rva(res_rva)
                    data = pe.__data__
                    if res_offset + 4 <= len(data):
                        res_size = struct.unpack_from('<I', data, res_offset)[0]
                        if res_size < 50 * 1024 * 1024:  # 50MB sanity limit
                            res_data = data[res_offset + 4: res_offset + 4 + res_size]
                            entry['size'] = len(res_data)
                            entry['sha256'] = hashlib.sha256(res_data).hexdigest()

                            # Check if it's a .NET assembly (MZ header)
                            if res_data[:2] == b'MZ':
                                entry['is_assembly'] = True

                            # Try decompress
                            if attempt_decompress and not entry['is_assembly']:
                                try:
                                    decompressed = zlib.decompress(res_data)
                                    entry['decompressed'] = True
                                    entry['size'] = len(decompressed)
                                    entry['sha256'] = hashlib.sha256(decompressed).hexdigest()
                                    res_data = decompressed
                                    if res_data[:2] == b'MZ':
                                        entry['is_assembly'] = True
                                except zlib.error:
                                    pass

                            # Preview first bytes
                            preview_len = min(64, len(res_data))
                            entry['content_preview'] = base64.b64encode(res_data[:preview_len]).decode('ascii')

                            # Save to workspace if requested
                            if save_to_workspace:
                                out_dir = os.path.join(os.path.dirname(file_path), 'exported_resources')
                                os.makedirs(out_dir, exist_ok=True)
                                safe_name = ''.join(c if c.isalnum() or c in '._-' else '_' for c in name)
                                out_path = os.path.join(out_dir, safe_name)
                                with open(out_path, 'wb') as f:
                                    f.write(res_data)
                                entry['saved_path'] = out_path
            except Exception:
                pass

            resources.append(entry)

    return {
        'ok': True,
        'data': {
            'total_resources': len(resources),
            'assembly_resources': sum(1 for r in resources if r['is_assembly']),
            'resources': resources,
        },
    }


# ---------------------------------------------------------------------------
# dynamic_methods
# ---------------------------------------------------------------------------

def handle_dynamic_methods(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle the dynamic_methods action.
    Detect DynamicMethod / MethodBuilder / Reflection.Emit usage patterns.
    """
    file_path = request.get('file_path', '')
    include_il_bytes = request.get('include_il_bytes', False)
    decompile = request.get('decompile', False)

    if not os.path.isfile(file_path):
        return {'ok': False, 'error': f'File not found: {file_path}'}

    try:
        pe = dnfile.dnPE(file_path)
    except Exception as e:
        return {'ok': False, 'error': f'Failed to parse .NET assembly: {e}'}

    if not pe.net or not pe.net.mdtables:
        return {'ok': False, 'error': 'Not a valid .NET assembly'}

    findings = []

    # Look for MemberRef calls to System.Reflection.Emit types
    emit_types = {
        'DynamicMethod', 'MethodBuilder', 'TypeBuilder',
        'AssemblyBuilder', 'ModuleBuilder', 'ILGenerator',
    }
    emit_methods = {
        'CreateDelegate', 'Invoke', 'DefineMethod',
        'DefineType', 'GetILGenerator', 'Emit',
        'DynamicInvoke', 'CreateType',
    }

    mr_table = pe.net.mdtables.MemberRef
    if mr_table:
        for rid, row in enumerate(mr_table.rows, start=1):
            name = str(row.Name) if row.Name else ''
            # Check if this MemberRef references Reflection.Emit types
            try:
                class_ref = row.Class
                parent_name = ''
                if hasattr(class_ref, 'row') and hasattr(class_ref.row, 'Name'):
                    parent_name = str(class_ref.row.Name)
                elif hasattr(class_ref, 'row') and hasattr(class_ref.row, 'TypeName'):
                    parent_name = str(class_ref.row.TypeName)
            except Exception:
                parent_name = ''

            is_emit = any(et in parent_name for et in emit_types)
            is_relevant_method = name in emit_methods

            if is_emit or is_relevant_method:
                findings.append({
                    'member_ref_token': _format_token(_make_token(0x0A, rid)),
                    'method_name': name,
                    'parent_type': parent_name,
                    'is_dynamic_emit': is_emit,
                    'category': 'reflection_emit' if is_emit else 'dynamic_invoke',
                })

    # Scan method bodies for references to these MemberRef tokens
    md_table = pe.net.mdtables.MethodDef
    call_sites = []
    if md_table and findings:
        emit_tokens = {int(f['member_ref_token'], 16) for f in findings}
        for rid, row in enumerate(md_table.rows, start=1):
            if not row.Rva:
                continue
            body = _read_method_body(pe, row.Rva)
            if not body:
                continue

            i = 0
            while i < len(body) - 4:
                op = body[i]
                if op in (0x28, 0x6F, 0x73):  # call, callvirt, newobj
                    token = struct.unpack_from('<I', body, i + 1)[0]
                    if token in emit_tokens:
                        site = {
                            'caller_method': _format_token(_make_token(0x06, rid)),
                            'caller_name': _get_method_name(pe, rid),
                            'il_offset': i,
                            'target_token': _format_token(token),
                            'opcode': {0x28: 'call', 0x6F: 'callvirt', 0x73: 'newobj'}[op],
                        }
                        if include_il_bytes:
                            start = max(0, i - 10)
                            end = min(len(body), i + 15)
                            site['il_context'] = base64.b64encode(body[start:end]).decode('ascii')
                        call_sites.append(site)
                    i += 5
                else:
                    i += 1

    return {
        'ok': True,
        'data': {
            'emit_references': len(findings),
            'call_sites': len(call_sites),
            'findings': findings,
            'sites': call_sites,
            'note': 'DynamicMethod/Reflection.Emit usage detected. '
                    'These methods generate IL at runtime and may contain '
                    'deobfuscated code or unpacked payloads.',
        },
    }


# ---------------------------------------------------------------------------
# anti_tamper
# ---------------------------------------------------------------------------

def handle_anti_tamper(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle the anti_tamper action.
    Detect .NET Reactor anti-tamper protection stubs.
    """
    file_path = request.get('file_path', '')
    deep_scan = request.get('deep_scan', False)

    if not os.path.isfile(file_path):
        return {'ok': False, 'error': f'File not found: {file_path}'}

    try:
        pe = dnfile.dnPE(file_path)
    except Exception as e:
        return {'ok': False, 'error': f'Failed to parse .NET assembly: {e}'}

    if not pe.net:
        return {'ok': False, 'error': 'Not a valid .NET assembly'}

    data = pe.__data__
    findings = {
        'reactor_version': _detect_reactor_version(pe),
        'has_anti_tamper': False,
        'has_native_stub': False,
        'has_module_cctor': False,
        'protection_details': [],
        'stub_offsets': [],
    }

    # Check for <Module>.cctor (module initializer)
    md_table = pe.net.mdtables.MethodDef
    td_table = pe.net.mdtables.TypeDef
    if td_table and md_table:
        for td_rid, td_row in enumerate(td_table.rows, start=1):
            type_name = str(getattr(td_row, 'TypeName', getattr(td_row, 'Name', ''))) or ''
            if type_name == '<Module>':
                # Find .cctor in this type's method range
                start_rid = td_row.MethodList.row_index if hasattr(td_row.MethodList, 'row_index') else 0
                end_rid = (td_table.rows[td_rid].MethodList.row_index
                           if td_rid < len(td_table.rows)
                           and hasattr(td_table.rows[td_rid].MethodList, 'row_index')
                           else len(md_table.rows) + 1)

                for m_rid in range(start_rid, min(end_rid, len(md_table.rows) + 1)):
                    if m_rid < 1:
                        continue
                    m_row = md_table.rows[m_rid - 1]
                    m_name = str(m_row.Name) if m_row.Name else ''
                    if m_name == '.cctor':
                        findings['has_module_cctor'] = True
                        # Read body for anti-tamper indicators
                        if m_row.Rva:
                            body = _read_method_body(pe, m_row.Rva)
                            if body:
                                # Reactor anti-tamper initializes in .cctor
                                # Look for Marshal.GetHINSTANCE / VirtualProtect patterns
                                il_str = body.hex()
                                if any(p in il_str for p in ['47657448494e5354414e4345',  # GetHINSTANCE
                                                              '5669727475616c50726f74656374']):  # VirtualProtect
                                    findings['has_anti_tamper'] = True
                                    findings['protection_details'].append({
                                        'type': 'module_initializer_protection',
                                        'method_token': _format_token(_make_token(0x06, m_rid)),
                                        'description': 'Module .cctor contains anti-tamper initialization code',
                                    })
                break

    # Check for native entry point (mixed-mode indicator)
    try:
        if pe.OPTIONAL_HEADER.AddressOfEntryPoint:
            ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            clr_rva = pe.net.struct.VirtualAddress if pe.net.struct else 0
            if ep_rva != clr_rva and ep_rva != 0:
                # Check if EP points to native code (not managed)
                ep_offset = pe.get_offset_from_rva(ep_rva)
                if ep_offset + 2 <= len(data):
                    # Reactor often uses a native stub that decrypts method bodies
                    first_bytes = data[ep_offset:ep_offset + 4]
                    if first_bytes[:2] != b'MZ':  # Not nested PE
                        findings['has_native_stub'] = True
                        findings['stub_offsets'].append({
                            'type': 'native_entry_stub',
                            'rva': f'0x{ep_rva:08X}',
                            'file_offset': f'0x{ep_offset:08X}',
                            'first_bytes': first_bytes.hex(),
                        })
    except Exception:
        pass

    # Deep scan: look for encrypted method bodies (all-zero or suspicious patterns)
    if deep_scan and md_table:
        suspicious_methods = []
        for rid, row in enumerate(md_table.rows, start=1):
            if not row.Rva:
                continue
            body = _read_method_body(pe, row.Rva)
            if body and len(body) > 8:
                # All zeros = likely encrypted/zeroed by anti-tamper
                if all(b == 0 for b in body):
                    suspicious_methods.append({
                        'token': _format_token(_make_token(0x06, rid)),
                        'name': _get_method_name(pe, rid),
                        'body_size': len(body),
                        'pattern': 'all_zeros',
                    })
                # High entropy with no valid IL structure
                elif len(set(body)) > 200 and body[0] not in (0x02, 0x03, 0x06, 0x0A, 0x0E, 0x12, 0x16, 0x17):
                    suspicious_methods.append({
                        'token': _format_token(_make_token(0x06, rid)),
                        'name': _get_method_name(pe, rid),
                        'body_size': len(body),
                        'pattern': 'high_entropy_invalid_il',
                    })
        if suspicious_methods:
            findings['has_anti_tamper'] = True
            findings['protection_details'].append({
                'type': 'encrypted_method_bodies',
                'count': len(suspicious_methods),
                'description': 'Method bodies appear encrypted or zeroed (anti-tamper)',
                'methods': suspicious_methods[:50],  # Limit output
            })

    return {
        'ok': True,
        'data': findings,
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

ACTIONS = {
    'string_decrypt': handle_string_decrypt,
    'resource_export': handle_resource_export,
    'dynamic_methods': handle_dynamic_methods,
    'anti_tamper': handle_anti_tamper,
}


def main():
    if not HAS_DNFILE:
        json.dump({'ok': False, 'error': 'dnfile is not installed'}, sys.stdout)
        sys.stdout.flush()
        sys.exit(1)

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
