"""
managed_il_xrefs_worker.py — IL-level cross-reference analysis worker.

Scans .NET assembly method bodies for field/method/type references using dnfile.
Supports two actions:
  - il_xrefs:    flat list of cross-references to a given token
  - token_xrefs: bidirectional reference graph rooted at a token
"""

import json
import sys
import os
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# dnfile import
# ---------------------------------------------------------------------------
try:
    import dnfile
    from dnfile.mdtable import MethodDefRow, TypeDefRow, FieldRow, MemberRefRow
    HAS_DNFILE = True
except ImportError:
    HAS_DNFILE = False

# ---------------------------------------------------------------------------
# IL opcode constants (single-byte subset relevant to xref scanning)
# ---------------------------------------------------------------------------
_IL_CALL      = 0x28  # call <method>
_IL_CALLVIRT  = 0x6F  # callvirt <method>
_IL_NEWOBJ    = 0x73  # newobj <ctor>
_IL_LDFLD     = 0x7B  # ldfld <field>
_IL_LDFLDA    = 0x7C  # ldflda <field>
_IL_STFLD     = 0x7D  # stfld <field>
_IL_LDSFLD    = 0x7E  # ldsfld <field>
_IL_LDSFLDA   = 0x7F  # ldsflda <field>
_IL_STSFLD    = 0x80  # stsfld <field>
_IL_LDTOKEN   = 0xD0  # ldtoken <token>

_FIELD_OPS  = {_IL_LDFLD, _IL_LDFLDA, _IL_STFLD, _IL_LDSFLD, _IL_LDSFLDA, _IL_STSFLD}
_METHOD_OPS = {_IL_CALL, _IL_CALLVIRT, _IL_NEWOBJ}
_TYPE_OPS   = {_IL_LDTOKEN}

_ALL_REF_OPS = _FIELD_OPS | _METHOD_OPS | _TYPE_OPS

# Map from opcode to human-readable name
_OPCODE_NAMES = {
    _IL_CALL:    'call',
    _IL_CALLVIRT:'callvirt',
    _IL_NEWOBJ:  'newobj',
    _IL_LDFLD:   'ldfld',
    _IL_LDFLDA:  'ldflda',
    _IL_STFLD:   'stfld',
    _IL_LDSFLD:  'ldsfld',
    _IL_LDSFLDA: 'ldsflda',
    _IL_STSFLD:  'stsfld',
    _IL_LDTOKEN: 'ldtoken',
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_token(token_str: str) -> Optional[int]:
    """Parse a metadata token string like '0x06000001' into an integer."""
    try:
        return int(token_str, 16)
    except (ValueError, TypeError):
        return None


def _token_table(token: int) -> int:
    """Return the table index from a metadata token."""
    return (token >> 24) & 0xFF


def _token_rid(token: int) -> int:
    """Return the row id from a metadata token."""
    return token & 0x00FFFFFF


def _make_token(table: int, rid: int) -> int:
    return (table << 24) | rid


def _format_token(token: int) -> str:
    return f'0x{token:08X}'


def _get_method_name(pe: 'dnfile.dnPE', method_rid: int) -> str:
    """Resolve a MethodDef RID to its fully-qualified name."""
    try:
        md_table = pe.net.mdtables.MethodDef
        if md_table and 1 <= method_rid <= len(md_table.rows):
            row = md_table.rows[method_rid - 1]
            method_name = str(row.Name) if row.Name else f'Method_{method_rid}'
            # Find owning type
            td_table = pe.net.mdtables.TypeDef
            if td_table:
                owner_type = ''
                for i, td in enumerate(td_table.rows):
                    td_method_list = td.MethodList.row_index if hasattr(td.MethodList, 'row_index') else 0
                    next_method_list = (td_table.rows[i + 1].MethodList.row_index
                                        if i + 1 < len(td_table.rows)
                                        and hasattr(td_table.rows[i + 1].MethodList, 'row_index')
                                        else len(md_table.rows) + 1)
                    if td_method_list <= method_rid < next_method_list:
                        ns = str(td.Namespace) if td.Namespace else ''
                        tn = str(td.Name) if td.Name else ''
                        owner_type = f'{ns}.{tn}' if ns else tn
                        break
                if owner_type:
                    return f'{owner_type}::{method_name}'
            return method_name
    except Exception:
        pass
    return f'MethodDef_{method_rid}'


def _get_type_name(pe: 'dnfile.dnPE', type_rid: int) -> str:
    """Resolve a TypeDef RID to its fully-qualified name."""
    try:
        td_table = pe.net.mdtables.TypeDef
        if td_table and 1 <= type_rid <= len(td_table.rows):
            row = td_table.rows[type_rid - 1]
            ns = str(row.Namespace) if row.Namespace else ''
            name = str(row.Name) if row.Name else f'Type_{type_rid}'
            return f'{ns}.{name}' if ns else name
    except Exception:
        pass
    return f'TypeDef_{type_rid}'


def _get_field_name(pe: 'dnfile.dnPE', field_rid: int) -> str:
    """Resolve a Field RID to its name."""
    try:
        fd_table = pe.net.mdtables.Field
        if fd_table and 1 <= field_rid <= len(fd_table.rows):
            row = fd_table.rows[field_rid - 1]
            return str(row.Name) if row.Name else f'Field_{field_rid}'
    except Exception:
        pass
    return f'Field_{field_rid}'


def _get_member_ref_name(pe: 'dnfile.dnPE', rid: int) -> str:
    """Resolve a MemberRef RID to its name."""
    try:
        mr_table = pe.net.mdtables.MemberRef
        if mr_table and 1 <= rid <= len(mr_table.rows):
            row = mr_table.rows[rid - 1]
            return str(row.Name) if row.Name else f'MemberRef_{rid}'
    except Exception:
        pass
    return f'MemberRef_{rid}'


def _resolve_token_name(pe: 'dnfile.dnPE', token: int) -> str:
    """Resolve any metadata token to a human-readable name."""
    table = _token_table(token)
    rid = _token_rid(token)
    if table == 0x06:
        return _get_method_name(pe, rid)
    elif table == 0x02:
        return _get_type_name(pe, rid)
    elif table == 0x04:
        return _get_field_name(pe, rid)
    elif table == 0x0A:
        return _get_member_ref_name(pe, rid)
    return _format_token(token)


def _find_token_by_name(pe: 'dnfile.dnPE', name: str, token_type: str) -> Optional[int]:
    """Try to find a metadata token by its qualified name."""
    name_lower = name.lower()

    if token_type == 'method':
        md_table = pe.net.mdtables.MethodDef
        if md_table:
            for i, row in enumerate(md_table.rows):
                full = _get_method_name(pe, i + 1).lower()
                if full == name_lower or (row.Name and str(row.Name).lower() == name_lower):
                    return _make_token(0x06, i + 1)
    elif token_type == 'type':
        td_table = pe.net.mdtables.TypeDef
        if td_table:
            for i, row in enumerate(td_table.rows):
                full = _get_type_name(pe, i + 1).lower()
                if full == name_lower:
                    return _make_token(0x02, i + 1)
    elif token_type == 'field':
        fd_table = pe.net.mdtables.Field
        if fd_table:
            for i, row in enumerate(fd_table.rows):
                if row.Name and str(row.Name).lower() == name_lower:
                    return _make_token(0x04, i + 1)

    return None


# ---------------------------------------------------------------------------
# IL body scanner
# ---------------------------------------------------------------------------

def _read_method_body(pe: 'dnfile.dnPE', rva: int) -> Optional[bytes]:
    """Read the IL method body bytes starting at the given RVA."""
    try:
        offset = pe.get_offset_from_rva(rva)
        data = pe.__data__
        if offset >= len(data):
            return None

        header_byte = data[offset]
        # Tiny format: lower 2 bits == 0b10
        if (header_byte & 0x03) == 0x02:
            size = (header_byte >> 2) & 0x3F
            return data[offset + 1: offset + 1 + size]
        # Fat format: lower 2 bits == 0b11
        elif (header_byte & 0x03) == 0x03:
            if offset + 12 > len(data):
                return None
            code_size = struct.unpack_from('<I', data, offset + 4)[0]
            return data[offset + 12: offset + 12 + code_size]
    except Exception:
        pass
    return None


def _scan_il_body(il_bytes: bytes) -> List[Tuple[int, int, str]]:
    """
    Scan IL bytes for reference opcodes.
    Returns list of (offset, referenced_token, opcode_name).
    """
    refs = []
    i = 0
    length = len(il_bytes)
    while i < length:
        op = il_bytes[i]
        if op in _ALL_REF_OPS:
            if i + 4 < length:
                token = struct.unpack_from('<I', il_bytes, i + 1)[0]
                refs.append((i, token, _OPCODE_NAMES.get(op, f'op_{op:02X}')))
            i += 5
        elif op == 0xFE and i + 1 < length:
            # Two-byte opcode prefix — skip
            i += 2
        else:
            # Most single-byte opcodes; use a rough skip table
            i += 1
    return refs


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def _build_xref_index(pe: 'dnfile.dnPE') -> Dict[int, List[Dict[str, Any]]]:
    """
    Build a complete cross-reference index: target_token → [xref_entries].
    Each entry has: source_method (token), offset, opcode.
    """
    index: Dict[int, List[Dict[str, Any]]] = {}

    md_table = pe.net.mdtables.MethodDef
    if not md_table:
        return index

    for rid, row in enumerate(md_table.rows, start=1):
        rva = row.Rva
        if not rva:
            continue
        body = _read_method_body(pe, rva)
        if not body:
            continue

        source_token = _make_token(0x06, rid)
        for offset, target_token, opcode in _scan_il_body(body):
            entry = {
                'source_method': _format_token(source_token),
                'source_method_name': _get_method_name(pe, rid),
                'il_offset': offset,
                'opcode': opcode,
            }
            index.setdefault(target_token, []).append(entry)

    return index


def handle_il_xrefs(request: Dict[str, Any]) -> Dict[str, Any]:
    """Handle the il_xrefs action."""
    file_path = request.get('file_path', '')
    token_str = request.get('token', '')
    token_type = request.get('token_type', 'method')
    include_generic = request.get('include_generic_instantiations', True)
    max_results = request.get('max_results', 500)

    if not os.path.isfile(file_path):
        return {'ok': False, 'error': f'File not found: {file_path}'}

    try:
        pe = dnfile.dnPE(file_path)
    except Exception as e:
        return {'ok': False, 'error': f'Failed to parse .NET assembly: {e}'}

    if not pe.net or not pe.net.mdtables:
        return {'ok': False, 'error': 'Not a valid .NET assembly (no metadata)'}

    # Resolve the target token
    target = _parse_token(token_str)
    if target is None:
        target = _find_token_by_name(pe, token_str, token_type)
    if target is None:
        return {'ok': False, 'error': f'Could not resolve token: {token_str}'}

    # Build xref index and look up the target
    xref_index = _build_xref_index(pe)
    xrefs = xref_index.get(target, [])

    # Also check MemberRef tokens that might reference the same entity
    if include_generic:
        mr_table = pe.net.mdtables.MemberRef
        if mr_table:
            for mr_rid, mr_row in enumerate(mr_table.rows, start=1):
                mr_token = _make_token(0x0A, mr_rid)
                mr_name = str(mr_row.Name) if mr_row.Name else ''
                target_name = _resolve_token_name(pe, target)
                # Simple name matching for generic instantiations
                if mr_name and target_name and mr_name in target_name:
                    xrefs.extend(xref_index.get(mr_token, []))

    # Deduplicate and limit
    seen: Set[Tuple[str, int]] = set()
    unique_xrefs = []
    for xref in xrefs:
        key = (xref['source_method'], xref['il_offset'])
        if key not in seen:
            seen.add(key)
            unique_xrefs.append(xref)
            if len(unique_xrefs) >= max_results:
                break

    return {
        'ok': True,
        'data': {
            'target_token': _format_token(target),
            'target_name': _resolve_token_name(pe, target),
            'target_type': token_type,
            'xref_count': len(unique_xrefs),
            'truncated': len(xrefs) > max_results,
            'xrefs': unique_xrefs,
        },
    }


def handle_token_xrefs(request: Dict[str, Any]) -> Dict[str, Any]:
    """Handle the token_xrefs action — bidirectional reference graph."""
    file_path = request.get('file_path', '')
    token_str = request.get('token', '')
    depth = min(max(request.get('depth', 1), 1), 5)
    direction = request.get('direction', 'both')
    include_system = request.get('include_system_refs', False)
    max_nodes = request.get('max_nodes', 500)

    if not os.path.isfile(file_path):
        return {'ok': False, 'error': f'File not found: {file_path}'}

    try:
        pe = dnfile.dnPE(file_path)
    except Exception as e:
        return {'ok': False, 'error': f'Failed to parse .NET assembly: {e}'}

    if not pe.net or not pe.net.mdtables:
        return {'ok': False, 'error': 'Not a valid .NET assembly (no metadata)'}

    # Resolve root token
    root = _parse_token(token_str)
    if root is None:
        root = _find_token_by_name(pe, token_str, 'method')
    if root is None:
        return {'ok': False, 'error': f'Could not resolve token: {token_str}'}

    # Build full xref index
    xref_index = _build_xref_index(pe)

    # Build reverse index: source_token → [target_tokens]
    outgoing_index: Dict[int, Set[int]] = {}
    for target_token, entries in xref_index.items():
        for entry in entries:
            src = _parse_token(entry['source_method'])
            if src is not None:
                outgoing_index.setdefault(src, set()).add(target_token)

    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, str]] = []
    visited: Set[int] = set()

    def _add_node(token: int) -> str:
        token_hex = _format_token(token)
        if token_hex not in nodes:
            name = _resolve_token_name(pe, token)
            if not include_system and name.startswith('System.'):
                return token_hex
            nodes[token_hex] = {
                'token': token_hex,
                'name': name,
                'table': _token_table(token),
            }
        return token_hex

    def _walk(token: int, current_depth: int):
        if current_depth > depth or token in visited or len(nodes) >= max_nodes:
            return
        visited.add(token)
        _add_node(token)

        # Incoming: who references this token
        if direction in ('both', 'incoming'):
            for entry in xref_index.get(token, []):
                src = _parse_token(entry['source_method'])
                if src is not None:
                    src_name = _resolve_token_name(pe, src)
                    if not include_system and src_name.startswith('System.'):
                        continue
                    _add_node(src)
                    edges.append({
                        'from': entry['source_method'],
                        'to': _format_token(token),
                        'opcode': entry.get('opcode', ''),
                    })
                    if current_depth < depth:
                        _walk(src, current_depth + 1)

        # Outgoing: what does this token reference (only for methods)
        if direction in ('both', 'outgoing') and _token_table(token) == 0x06:
            for target in outgoing_index.get(token, set()):
                target_name = _resolve_token_name(pe, target)
                if not include_system and target_name.startswith('System.'):
                    continue
                _add_node(target)
                edges.append({
                    'from': _format_token(token),
                    'to': _format_token(target),
                    'opcode': 'call',
                })
                if current_depth < depth:
                    _walk(target, current_depth + 1)

    _walk(root, 1)

    return {
        'ok': True,
        'data': {
            'root_token': _format_token(root),
            'root_name': _resolve_token_name(pe, root),
            'depth': depth,
            'direction': direction,
            'node_count': len(nodes),
            'edge_count': len(edges),
            'truncated': len(nodes) >= max_nodes,
            'nodes': list(nodes.values()),
            'edges': edges,
        },
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

ACTIONS = {
    'il_xrefs': handle_il_xrefs,
    'token_xrefs': handle_token_xrefs,
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
