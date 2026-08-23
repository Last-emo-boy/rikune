#!/usr/bin/env python3
"""Bounded, passive PDF static-analysis worker.

The worker uses only the Python standard library. It reads one bounded JSON
request from stdin, inspects a bounded prefix of the sample, and emits one
bounded JSON object. It never executes document content, writes files, or opens
network connections.
"""

import json
import re
import sys
import zlib


MAX_REQUEST_BYTES = 16 * 1024
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_OBJECTS = 5_000
MAX_OBJECT_SCAN_BYTES = 2 * 1024 * 1024
MAX_COMPRESSED_STREAM_BYTES = 4 * 1024 * 1024
MAX_STREAM_BYTES = 512 * 1024

MAX_JS_ENTRIES = 500
MAX_JS_CHARS = 32_000
MAX_TOTAL_JS_CHARS = 1024 * 1024
MAX_URIS = 500
MAX_URI_CHARS = 2_048
MAX_TOTAL_URI_CHARS = 256 * 1024
MAX_ACTIONS = 50
MAX_ACTION_CHARS = 4_096
MAX_TOTAL_ACTION_CHARS = 128 * 1024
MAX_EMBEDDED_FILES = 50
MAX_EMBEDDED_FILE_CHARS = 4_096
MAX_TOTAL_EMBEDDED_FILE_CHARS = 128 * 1024
MAX_WARNINGS = 50
MAX_WARNING_CHARS = 2_048


def emit(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.flush()


def add_warning(warnings, message):
    bounded = str(message)[:MAX_WARNING_CHARS]
    if bounded and bounded not in warnings and len(warnings) < MAX_WARNINGS:
        warnings.append(bounded)


def bounded_limit(value, default, maximum):
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return max(1, min(value, maximum))


def empty_result():
    return {
        "status": "ready",
        "pdf_version": None,
        "structure": None,
        "javascript": [],
        "uris": [],
        "open_actions": [],
        "embedded_files": [],
        "js_count": 0,
        "uri_count": 0,
        "warnings": [],
    }


def parse_objects(raw, warnings):
    """Return bounded ``(object number, generation, body)`` tuples."""
    objects = []
    pattern = re.compile(rb"(\d+)\s+(\d+)\s+obj\b(.*?)\bendobj", re.DOTALL)
    for match in pattern.finditer(raw):
        if len(objects) >= MAX_OBJECTS:
            add_warning(warnings, f"Object inventory truncated at {MAX_OBJECTS} entries.")
            break
        objects.append((int(match.group(1)), int(match.group(2)), match.group(3)))
    return objects


def extract_stream(body, warnings):
    """Return a bounded stream body, or ``None`` when no stream is present."""
    match = re.search(rb"stream\r?\n(.*?)\r?\nendstream", body, re.DOTALL)
    if not match:
        return None
    stream = match.group(1)
    if len(stream) > MAX_COMPRESSED_STREAM_BYTES:
        add_warning(
            warnings,
            f"Compressed stream input truncated at {MAX_COMPRESSED_STREAM_BYTES} bytes.",
        )
    return stream[:MAX_COMPRESSED_STREAM_BYTES]


def maybe_inflate(stream_bytes, warnings):
    """Inflate at most ``MAX_STREAM_BYTES`` without allocating a full bomb."""
    if stream_bytes is None:
        return None, False
    try:
        inflater = zlib.decompressobj()
        inflated = inflater.decompress(stream_bytes, MAX_STREAM_BYTES + 1)
        was_truncated = len(inflated) > MAX_STREAM_BYTES or bool(inflater.unconsumed_tail)
        if was_truncated:
            add_warning(
                warnings,
                f"Inflated stream output truncated at {MAX_STREAM_BYTES} bytes.",
            )
        return inflated[:MAX_STREAM_BYTES], True
    except zlib.error:
        return stream_bytes[:MAX_STREAM_BYTES], False


def decode_pdf_string(token, max_chars):
    """Decode one bounded PDF literal or hexadecimal string token."""
    token = token.strip()
    if token.startswith(b"<") and token.endswith(b">"):
        hex_body = token[1:-1][: max_chars * 2]
        hex_body = re.sub(rb"\s+", b"", hex_body)
        if len(hex_body) % 2:
            hex_body += b"0"
        try:
            return bytes.fromhex(hex_body.decode("ascii")).decode("latin-1", "replace")[
                :max_chars
            ]
        except (UnicodeDecodeError, ValueError):
            return token.decode("latin-1", "replace")[:max_chars]
    if token.startswith(b"(") and token.endswith(b")"):
        value = token[1:-1][: max_chars * 4]
        value = re.sub(rb"\\([()\\])", rb"\1", value)
        return value.decode("latin-1", "replace")[:max_chars]
    return token[: max_chars * 4].decode("latin-1", "replace")[:max_chars]


def append_bounded_string(
    output,
    seen,
    value,
    max_items,
    max_chars,
    max_total_chars,
):
    if len(output) >= max_items:
        return False
    remaining = max_total_chars - sum(len(item) for item in output)
    if remaining <= 0:
        return False
    bounded = str(value)[: min(max_chars, remaining)]
    if not bounded or bounded in seen:
        return True
    output.append(bounded)
    seen.add(bounded)
    return len(output) < max_items and sum(len(item) for item in output) < max_total_chars


def extract_javascript(objects, max_entries, warnings):
    """Find bounded /JS literals and /JavaScript stream bodies."""
    entries = []
    seen = set()
    total_chars = 0
    token_pattern = re.compile(
        rb"/JS\s*(\((?:[^()\\]|\\.){0,128000}\)|<[0-9A-Fa-f\s]{1,64000}>)"
    )

    def append_entry(object_number, source, value):
        nonlocal total_chars
        if len(entries) >= max_entries or total_chars >= MAX_TOTAL_JS_CHARS:
            return False
        remaining = MAX_TOTAL_JS_CHARS - total_chars
        bounded = value[: min(MAX_JS_CHARS, remaining)]
        key = (object_number, source, bounded)
        if not bounded or key in seen:
            return True
        entries.append({"object": object_number, "source": source, "js": bounded})
        seen.add(key)
        total_chars += len(bounded)
        return len(entries) < max_entries and total_chars < MAX_TOTAL_JS_CHARS

    for object_number, _generation, full_body in objects:
        if len(entries) >= max_entries or total_chars >= MAX_TOTAL_JS_CHARS:
            break
        body = full_body[:MAX_OBJECT_SCAN_BYTES]
        if b"/JS" not in body and b"/JavaScript" not in body:
            continue

        stream = extract_stream(body, warnings)
        if stream is not None and b"/FlateDecode" in body:
            stream_content, _was_inflated = maybe_inflate(stream, warnings)
        else:
            stream_content = stream[:MAX_STREAM_BYTES] if stream is not None else None

        search_areas = [body]
        if stream_content:
            search_areas.append(stream_content)
        for search_area in search_areas:
            for match in token_pattern.finditer(search_area):
                javascript = decode_pdf_string(match.group(1), MAX_JS_CHARS)
                if javascript and not append_entry(object_number, "name", javascript):
                    break
            if len(entries) >= max_entries or total_chars >= MAX_TOTAL_JS_CHARS:
                break

        if b"/JavaScript" in body and stream_content:
            javascript = stream_content.decode("utf-8", "replace")[:MAX_JS_CHARS]
            if javascript.strip():
                append_entry(object_number, "stream", javascript)

    if total_chars >= MAX_TOTAL_JS_CHARS:
        add_warning(
            warnings,
            f"JavaScript output truncated at {MAX_TOTAL_JS_CHARS} total characters.",
        )
    return entries


def extract_uris(raw, max_uris):
    """Find bounded, unique /URI entries."""
    uris = []
    seen = set()
    pattern = re.compile(rb"/URI\s*(\((?:[^()\\]|\\.){0,8192}\)|<[0-9A-Fa-f\s]{1,4096}>)")
    for match in pattern.finditer(raw):
        uri = decode_pdf_string(match.group(1), MAX_URI_CHARS)
        if not append_bounded_string(
            uris,
            seen,
            uri,
            max_uris,
            MAX_URI_CHARS,
            MAX_TOTAL_URI_CHARS,
        ):
            break
    return uris


def extract_actions(raw):
    """Inventory bounded OpenAction, additional-action, and named action entries."""
    actions = []
    seen = set()

    def append(value):
        return append_bounded_string(
            actions,
            seen,
            value,
            MAX_ACTIONS,
            MAX_ACTION_CHARS,
            MAX_TOTAL_ACTION_CHARS,
        )

    for match in re.finditer(rb"/OpenAction\s*(\d+\s+\d+\s+R|<<[^>]{0,16384}>>)", raw):
        if not append("OpenAction: " + match.group(1).decode("latin-1", "replace").strip()):
            return actions

    action_pattern = re.compile(
        rb"/S\s*/(Launch|SubmitForm|GoToR)\b(?:.{0,512}?/F\s*(\((?:[^()\\]|\\.){0,8192}\)|<[0-9A-Fa-f\s]{1,4096}>|\d+\s+\d+\s+R))?",
        re.DOTALL,
    )
    for match in action_pattern.finditer(raw):
        action = match.group(1).decode("ascii")
        target = decode_pdf_string(match.group(2), MAX_ACTION_CHARS) if match.group(2) else ""
        if not append(f"{action}: {target}" if target else action):
            return actions

    for match in re.finditer(rb"/AA\s*<<([^>]{0,16384})>>", raw):
        value = "AA<<" + match.group(1).decode("latin-1", "replace").strip() + ">>"
        if not append(value):
            break
    return actions


def extract_embedded_files(raw):
    """Find bounded /EF dictionaries and /EmbeddedFile markers."""
    embedded = []
    seen = set()

    def append(value):
        return append_bounded_string(
            embedded,
            seen,
            value,
            MAX_EMBEDDED_FILES,
            MAX_EMBEDDED_FILE_CHARS,
            MAX_TOTAL_EMBEDDED_FILE_CHARS,
        )

    for match in re.finditer(rb"/EF\s*<<([^>]{0,16384})>>", raw):
        value = match.group(1).decode("latin-1", "replace").strip()
        if not append(value):
            return embedded
    for match in re.finditer(rb"/EmbeddedFile\b", raw):
        if not append(f"EmbeddedFile marker at byte {match.start()}"):
            break
    return embedded


def count_structure(raw, objects):
    """Summarise structural markers without interpreting document content."""
    return {
        "object_count": len(objects),
        "page_count": sum(1 for _ in re.finditer(rb"/Type\s*/Page(?!s\b)", raw)),
        "xref_count": raw.count(b"xref"),
        "trailer_count": raw.count(b"trailer"),
        "has_encrypt": b"/Encrypt" in raw,
        "has_js": b"/JavaScript" in raw or b"/JS" in raw,
        "has_launch_action": b"/Launch" in raw,
        "has_submitform": b"/SubmitForm" in raw,
        "has_goitore": b"/GoToR" in raw,
    }


def main():
    request_bytes = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(request_bytes) > MAX_REQUEST_BYTES:
        raise ValueError(f"request exceeds {MAX_REQUEST_BYTES} byte limit")
    payload = json.loads(request_bytes.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("request must be a JSON object")

    sample_path = payload.get("sample_path")
    if not isinstance(sample_path, str) or not sample_path or len(sample_path) > 4_096:
        raise ValueError("sample_path must be a non-empty bounded string")
    max_js_entries = bounded_limit(payload.get("max_js_entries"), 50, MAX_JS_ENTRIES)
    max_uris = bounded_limit(payload.get("max_uris"), 200, MAX_URIS)

    result = empty_result()
    with open(sample_path, "rb") as sample_file:
        raw = sample_file.read(MAX_INPUT_BYTES + 1)

    if len(raw) > MAX_INPUT_BYTES:
        result["status"] = "input_too_large"
        add_warning(result["warnings"], f"PDF input exceeds {MAX_INPUT_BYTES} byte limit.")
        emit(result)
        return

    if not raw.startswith(b"%PDF-"):
        result["status"] = "invalid_pdf"
        add_warning(result["warnings"], "File does not start with %PDF- header.")
        emit(result)
        return

    version_match = re.match(rb"%PDF-(\d+\.\d+)", raw)
    if version_match:
        result["pdf_version"] = version_match.group(1).decode("ascii")

    objects = parse_objects(raw, result["warnings"])
    result["structure"] = count_structure(raw, objects)
    result["javascript"] = extract_javascript(objects, max_js_entries, result["warnings"])
    result["uris"] = extract_uris(raw, max_uris)
    result["open_actions"] = extract_actions(raw)
    result["embedded_files"] = extract_embedded_files(raw)
    result["js_count"] = len(result["javascript"])
    result["uri_count"] = len(result["uris"])

    if result["structure"]["has_encrypt"]:
        add_warning(
            result["warnings"],
            "PDF is encrypted; stream contents may be inaccessible.",
        )
    emit(result)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        sys.stderr.write(f"pdf-analysis worker error: {error}\n")
        sys.exit(1)
