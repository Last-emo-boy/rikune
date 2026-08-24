#!/usr/bin/env python3
"""Linux-only dirfd/openat2 helper for sample quarantine renames.

Every path component is resolved beneath a frozen root directory descriptor
with symlink resolution disabled. Unsupported kernels/platforms fail closed.
"""

import ctypes
import errno
import hashlib
import json
import os
import platform
import stat
import sys
import time
import uuid


RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
RENAME_NOREPLACE = 1


class OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_ulonglong),
        ("mode", ctypes.c_ulonglong),
        ("resolve", ctypes.c_ulonglong),
    ]


def fail(message):
    raise RuntimeError(f"E_SECURE_QUARANTINE: {message}")


def syscall_number(name):
    machine = platform.machine().lower()
    table = {
        "x86_64": {"openat2": 437},
        "amd64": {"openat2": 437},
        "aarch64": {"openat2": 437},
        "arm64": {"openat2": 437},
    }
    value = table.get(machine, {}).get(name)
    if value is None:
        fail(f"unsupported Linux architecture for {name}: {machine}")
    return value


LIBC = ctypes.CDLL(None, use_errno=True)


def openat2(directory_fd, relative):
    how = OpenHow(
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        0,
        RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    )
    encoded = os.fsencode(relative)
    result = LIBC.syscall(
        syscall_number("openat2"),
        directory_fd,
        ctypes.c_char_p(encoded),
        ctypes.byref(how),
        ctypes.sizeof(how),
    )
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), relative)
    return result


def relative_parts(value):
    if not isinstance(value, str) or not value or "\x00" in value or value.startswith("/"):
        fail("path must be a non-empty relative Linux path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        fail("path contains an empty, dot, or parent component")
    return parts


def open_directory_chain(root_fd, parts, create=False):
    current = os.dup(root_fd)
    try:
        for part in parts:
            try:
                child = openat2(current, part)
            except OSError as error:
                if not create or error.errno != errno.ENOENT:
                    raise
                os.mkdir(part, mode=0o700, dir_fd=current)
                os.fsync(current)
                child = openat2(current, part)
            os.close(current)
            current = child
        return current
    except Exception:
        os.close(current)
        raise


def stat_entry(parent_fd, basename):
    try:
        return os.stat(basename, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def validate_identity(candidate, request):
    if candidate is None:
        return
    expected_type = request["expected_type"]
    actual_type = "directory" if stat.S_ISDIR(candidate.st_mode) else "file" if stat.S_ISREG(candidate.st_mode) else "unsupported"
    if actual_type != expected_type:
        fail(f"target type changed: expected {expected_type}, received {actual_type}")
    if candidate.st_dev != request["expected_device"] or candidate.st_ino != request["expected_inode"]:
        fail("target device/inode changed after journal preparation")
    if actual_type == "file" and candidate.st_nlink != 1:
        fail("target file is hard-linked")


def validate_root(request):
    root = request.get("root")
    if not isinstance(root, str) or not os.path.isabs(root):
        fail("root must be absolute")
    for field in ("root_device", "root_inode"):
        if not isinstance(request.get(field), int) or request[field] < 0:
            fail(f"{field} must be a non-negative integer")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    root_stat = os.fstat(root_fd)
    if root_stat.st_dev != request["root_device"] or root_stat.st_ino != request["root_inode"]:
        os.close(root_fd)
        fail("trusted root identity changed")
    return root_fd


def single_name(value, label):
    parts = relative_parts(value)
    if len(parts) != 1:
        fail(f"{label} must be a single filename")
    return parts[0]


def hash_file_descriptor(descriptor):
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def validate_regular_file(parent_fd, name, expected_sha256, expected_size):
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        candidate = os.fstat(descriptor)
        if not stat.S_ISREG(candidate.st_mode) or candidate.st_nlink != 1:
            fail("ingest target must be a single-link regular file")
        if candidate.st_size != expected_size:
            fail("ingest target size does not match expected payload")
        if hash_file_descriptor(descriptor) != expected_sha256:
            fail("ingest target hash does not match expected payload")
        return candidate
    finally:
        os.close(descriptor)


def validate_owned_temp(parent_fd, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        candidate = os.fstat(descriptor)
        if not stat.S_ISREG(candidate.st_mode) or candidate.st_nlink != 1:
            fail("ingest temp must be a single-link regular file")
        return candidate
    finally:
        os.close(descriptor)


def find_matching_file(request):
    expected_sha256 = request.get("expected_sha256")
    expected_size = request.get("expected_size")
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        fail("expected_sha256 must be SHA-256")
    if not isinstance(expected_size, int) or expected_size < 0:
        fail("expected_size must be a non-negative integer")
    directory_parts = relative_parts(request.get("directory_relative"))
    root_fd = validate_root(request)
    try:
        directory_fd = open_directory_chain(root_fd, directory_parts, create=False)
        try:
            for name in sorted(os.listdir(directory_fd)):
                if name.startswith(".rikune-"):
                    continue
                try:
                    candidate = validate_regular_file(
                        directory_fd, name, expected_sha256, expected_size
                    )
                except (RuntimeError, OSError):
                    continue
                return {
                    "status": "matched",
                    "name": name,
                    "device": candidate.st_dev,
                    "inode": candidate.st_ino,
                }
            return {"status": "missing"}
        finally:
            os.close(directory_fd)
    finally:
        os.close(root_fd)


def remove_owned_name(parent_fd, name, expected_device, expected_inode):
    quarantine_name = f".rikune-remove-{hashlib.sha256(name.encode('utf-8')).hexdigest()}"
    source = stat_entry(parent_fd, name)
    quarantined = stat_entry(parent_fd, quarantine_name)
    if source is not None and quarantined is not None:
        fail("owned cleanup source and quarantine both exist")
    if source is None and quarantined is None:
        return
    if source is not None:
        renameat2(parent_fd, name, parent_fd, quarantine_name)
    candidate = stat_entry(parent_fd, quarantine_name)
    if candidate is None:
        fail("owned cleanup rename disappeared")
    if candidate.st_dev != expected_device or candidate.st_ino != expected_inode:
        # Fail closed: an attacker-controlled replacement is quarantined but
        # never deleted. This is safer than trying to rename it back through a
        # concurrently mutable namespace.
        fail("owned cleanup identity changed during atomic rename")
    os.unlink(quarantine_name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def cleanup_ingest_temp(request):
    expected_sha256 = request.get("expected_sha256")
    expected_size = request.get("expected_size")
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        fail("expected_sha256 must be lowercase SHA-256")
    if not isinstance(expected_size, int) or expected_size < 0:
        fail("expected_size must be a non-negative integer")
    directory_parts = relative_parts(request.get("directory_relative"))
    temp_name = single_name(request.get("temp_name"), "temp_name")
    quarantine_name = f".rikune-remove-{hashlib.sha256(temp_name.encode('utf-8')).hexdigest()}"

    root_fd = validate_root(request)
    try:
        directory_fd = open_directory_chain(root_fd, directory_parts, create=False)
        try:
            source = stat_entry(directory_fd, temp_name)
            quarantined = stat_entry(directory_fd, quarantine_name)
            if source is not None and quarantined is not None:
                fail("ingest temp source and cleanup claim both exist")
            if source is None and quarantined is None:
                return {"status": "missing"}
            candidate_name = temp_name if source is not None else quarantine_name
            candidate = validate_owned_temp(directory_fd, candidate_name)
            remove_owned_name(directory_fd, temp_name, candidate.st_dev, candidate.st_ino)
            return {"status": "removed"}
        finally:
            os.close(directory_fd)
    finally:
        os.close(root_fd)


def renameat2(source_parent_fd, source_name, destination_parent_fd, destination_name):
    function = getattr(LIBC, "renameat2", None)
    if function is None:
        fail("renameat2 is unavailable")
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    result = function(
        source_parent_fd,
        ctypes.c_char_p(os.fsencode(source_name)),
        destination_parent_fd,
        ctypes.c_char_p(os.fsencode(destination_name)),
        RENAME_NOREPLACE,
    )
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def test_barrier(request):
    ready = request.get("ready_file")
    continuation = request.get("continue_file")
    if ready is None and continuation is None:
        return
    if not isinstance(ready, str) or not os.path.isabs(ready):
        fail("ready_file must be an absolute test path")
    if not isinstance(continuation, str) or not os.path.isabs(continuation):
        fail("continue_file must be an absolute test path")
    descriptor = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    os.close(descriptor)
    deadline = time.monotonic() + 10.0
    while not os.path.exists(continuation):
        if time.monotonic() >= deadline:
            fail("timed out waiting at test barrier")
        time.sleep(0.005)


def quarantine_rename(request):
    root = request.get("root")
    if not isinstance(root, str) or not os.path.isabs(root):
        fail("root must be absolute")
    source_parts = relative_parts(request.get("source_relative"))
    destination_parts = relative_parts(request.get("destination_relative"))
    for field in ("root_device", "root_inode", "expected_device", "expected_inode"):
        if not isinstance(request.get(field), int) or request[field] < 0:
            fail(f"{field} must be a non-negative integer")
    if request.get("expected_type") not in ("file", "directory"):
        fail("expected_type must be file or directory")

    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        root_stat = os.fstat(root_fd)
        if root_stat.st_dev != request["root_device"] or root_stat.st_ino != request["root_inode"]:
            fail("trusted root identity changed")

        destination_parent_fd = open_directory_chain(root_fd, destination_parts[:-1], create=True)
        try:
            try:
                source_parent_fd = open_directory_chain(root_fd, source_parts[:-1], create=False)
            except FileNotFoundError:
                source_parent_fd = None
            try:
                source_stat = (
                    stat_entry(source_parent_fd, source_parts[-1])
                    if source_parent_fd is not None
                    else None
                )
                destination_stat = stat_entry(destination_parent_fd, destination_parts[-1])
                if source_stat is not None and destination_stat is not None:
                    fail("source and quarantine destination both exist")
                if source_stat is None and destination_stat is None:
                    return {"status": "missing"}
                if destination_stat is not None:
                    validate_identity(destination_stat, request)
                    return {"status": "already_quarantined"}

                validate_identity(source_stat, request)
                test_barrier(request)
                renameat2(
                    source_parent_fd,
                    source_parts[-1],
                    destination_parent_fd,
                    destination_parts[-1],
                )
                os.fsync(source_parent_fd)
                os.fsync(destination_parent_fd)
                destination_stat = stat_entry(destination_parent_fd, destination_parts[-1])
                validate_identity(destination_stat, request)
                return {"status": "renamed"}
            finally:
                if source_parent_fd is not None:
                    os.close(source_parent_fd)
        finally:
            os.close(destination_parent_fd)
    finally:
        os.close(root_fd)


def validate_directory(request):
    root_fd = validate_root(request)
    directory_parts = relative_parts(request.get("directory_relative"))
    try:
        directory_fd = open_directory_chain(root_fd, directory_parts, create=False)
        try:
            candidate = os.fstat(directory_fd)
            return {
                "status": "validated",
                "device": candidate.st_dev,
                "inode": candidate.st_ino,
            }
        finally:
            os.close(directory_fd)
    finally:
        os.close(root_fd)


def inspect_file(request):
    root_fd = validate_root(request)
    directory_parts = relative_parts(request.get("directory_relative"))
    name = single_name(request.get("name"), "name")
    try:
        directory_fd = open_directory_chain(root_fd, directory_parts, create=False)
        try:
            candidate = stat_entry(directory_fd, name)
            if candidate is None:
                return {"status": "missing"}
            if not stat.S_ISREG(candidate.st_mode):
                fail("inspected path is not a regular file")
            return {
                "status": "found",
                "device": candidate.st_dev,
                "inode": candidate.st_ino,
                "size": candidate.st_size,
            }
        finally:
            os.close(directory_fd)
    finally:
        os.close(root_fd)


def ingest_publish(request):
    expected_sha256 = request.get("expected_sha256")
    expected_size = request.get("expected_size")
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        fail("expected_sha256 must be lowercase SHA-256")
    if not isinstance(expected_size, int) or expected_size < 0:
        fail("expected_size must be a non-negative integer")

    directory_parts = relative_parts(request.get("directory_relative"))
    temp_name = single_name(request.get("temp_name"), "temp_name")
    final_name = single_name(request.get("final_name"), "final_name")
    if temp_name == final_name:
        fail("temporary and final names must differ")

    root_fd = validate_root(request)
    try:
        directory_fd = open_directory_chain(root_fd, directory_parts, create=False)
        try:
            existing = stat_entry(directory_fd, final_name)
            if existing is not None:
                candidate = validate_regular_file(
                    directory_fd, final_name, expected_sha256, expected_size
                )
                cleanup_name = f".rikune-remove-{hashlib.sha256(temp_name.encode('utf-8')).hexdigest()}"
                staged = stat_entry(directory_fd, temp_name)
                claimed = stat_entry(directory_fd, cleanup_name)
                if staged is not None and claimed is not None:
                    fail("ingest temp source and cleanup claim both exist")
                if staged is not None or claimed is not None:
                    candidate_name = temp_name if staged is not None else cleanup_name
                    owned = validate_owned_temp(directory_fd, candidate_name)
                    remove_owned_name(directory_fd, temp_name, owned.st_dev, owned.st_ino)
                return {
                    "status": "already_present",
                    "device": candidate.st_dev,
                    "inode": candidate.st_ino,
                }

            descriptor = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o400,
                dir_fd=directory_fd,
            )
            temp_stat = None
            try:
                digest = hashlib.sha256()
                written = 0
                while written < expected_size:
                    chunk = sys.stdin.buffer.read(min(1024 * 1024, expected_size - written))
                    if not chunk:
                        fail("ingest payload ended before expected_size")
                    view = memoryview(chunk)
                    while view:
                        count = os.write(descriptor, view)
                        view = view[count:]
                    digest.update(chunk)
                    written += len(chunk)
                if sys.stdin.buffer.read(1):
                    fail("ingest payload exceeded expected_size")
                if digest.hexdigest() != expected_sha256:
                    fail("ingest payload hash mismatch")
                os.fchmod(descriptor, 0o400)
                os.fsync(descriptor)
                temp_stat = os.fstat(descriptor)
            finally:
                os.close(descriptor)

            try:
                renameat2(directory_fd, temp_name, directory_fd, final_name)
                published = True
            except FileExistsError:
                published = False

            if published:
                final_stat = os.stat(final_name, dir_fd=directory_fd, follow_symlinks=False)
                if (
                    final_stat.st_dev != temp_stat.st_dev
                    or final_stat.st_ino != temp_stat.st_ino
                    or not stat.S_ISREG(final_stat.st_mode)
                ):
                    fail("published ingest inode does not match staged inode")
                os.fsync(directory_fd)
                final_stat = validate_regular_file(
                    directory_fd, final_name, expected_sha256, expected_size
                )
                return {
                    "status": "published",
                    "device": final_stat.st_dev,
                    "inode": final_stat.st_ino,
                }

            existing_stat = validate_regular_file(
                directory_fd, final_name, expected_sha256, expected_size
            )
            remove_owned_name(directory_fd, temp_name, temp_stat.st_dev, temp_stat.st_ino)
            return {
                "status": "already_present",
                "device": existing_stat.st_dev,
                "inode": existing_stat.st_ino,
            }
        finally:
            os.close(directory_fd)
    finally:
        os.close(root_fd)


def remove_identity(request):
    for field in ("expected_device", "expected_inode"):
        if not isinstance(request.get(field), int) or request[field] < 0:
            fail(f"{field} must be a non-negative integer")
    directory_parts = relative_parts(request.get("directory_relative"))
    source_name = single_name(request.get("source_name"), "source_name")
    quarantine_name = single_name(request.get("quarantine_name"), "quarantine_name")
    if source_name == quarantine_name:
        fail("source and quarantine names must differ")

    root_fd = validate_root(request)
    try:
        directory_fd = open_directory_chain(root_fd, directory_parts, create=False)
        try:
            candidate = stat_entry(directory_fd, source_name)
            quarantined = stat_entry(directory_fd, quarantine_name)
            if candidate is not None and quarantined is not None:
                fail("remove source and quarantine both exist")
            if candidate is None and quarantined is None:
                return {"status": "missing"}
            if candidate is None:
                candidate = quarantined
            if not stat.S_ISREG(candidate.st_mode):
                fail("remove target is not a regular file")
            if (
                candidate.st_dev != request["expected_device"]
                or candidate.st_ino != request["expected_inode"]
            ):
                fail("remove target identity changed before atomic rename")
            if quarantined is None:
                test_barrier(request)
                renameat2(directory_fd, source_name, directory_fd, quarantine_name)
            moved = stat_entry(directory_fd, quarantine_name)
            if (
                moved is None
                or not stat.S_ISREG(moved.st_mode)
                or moved.st_dev != request["expected_device"]
                or moved.st_ino != request["expected_inode"]
            ):
                fail("remove target identity changed during atomic rename")
            os.fsync(directory_fd)
            os.unlink(quarantine_name, dir_fd=directory_fd)
            os.fsync(directory_fd)
            return {"status": "removed"}
        finally:
            os.close(directory_fd)
    finally:
        os.close(root_fd)


def deterministic_purge_claim(relative):
    digest = hashlib.sha256(relative.encode("utf-8")).hexdigest()
    return f".rikune-purge-{digest}"


def open_purge_logical_directory(root_fd, parts):
    current = os.dup(root_fd)
    logical = []
    try:
        for part in parts:
            logical.append(part)
            relative = "/".join(logical)
            claim_name = deterministic_purge_claim(relative)
            original = stat_entry(current, part)
            claimed = stat_entry(current, claim_name)
            if original is not None and claimed is not None:
                fail(f"quarantine purge original and atomic claim both exist: {relative}")
            if original is None and claimed is None:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), relative)
            child = openat2(current, claim_name if claimed is not None else part)
            os.close(current)
            current = child
        return current
    except Exception:
        os.close(current)
        raise


def open_purge_root(request):
    directory_parts = relative_parts(request.get("directory_relative"))
    if len(directory_parts) < 2:
        fail("quarantine purge requires a nested directory")
    root_fd = validate_root(request)
    try:
        parent_fd = open_directory_chain(root_fd, directory_parts[:-1], create=False)
    except Exception:
        os.close(root_fd)
        raise
    try:
        original_name = directory_parts[-1]
        purge_name = f".purging-{original_name}"
        original = stat_entry(parent_fd, original_name)
        purging = stat_entry(parent_fd, purge_name)
        if original is not None and purging is not None:
            fail("quarantine original and purge target both exist")
        if original is None and purging is None:
            return root_fd, parent_fd, None, purge_name
        if original is not None:
            if not stat.S_ISDIR(original.st_mode):
                fail("quarantine purge target is not a directory")
            renameat2(parent_fd, original_name, parent_fd, purge_name)
            os.fsync(parent_fd)
        purge_fd = openat2(parent_fd, purge_name)
        return root_fd, parent_fd, purge_fd, purge_name
    except Exception:
        os.close(parent_fd)
        os.close(root_fd)
        raise


def purge_quarantine_chunk(request):
    raw_entries = request.get("entries")
    if not isinstance(raw_entries, list):
        fail("quarantine purge chunk entries must be an array")
    if len(raw_entries) > 4096:
        fail("quarantine purge chunk contains too many entries")
    delay_ms = request.get("test_delay_ms")
    if delay_ms is not None and (
        not isinstance(delay_ms, int)
        or isinstance(delay_ms, bool)
        or delay_ms < 0
        or delay_ms > 60_000
    ):
        fail("test_delay_ms must be an integer between 0 and 60000")

    entries = []
    seen = set()
    previous_depth = None
    for raw in raw_entries:
        if not isinstance(raw, dict):
            fail("quarantine purge chunk entry must be an object")
        relative = "/".join(relative_parts(raw.get("relative_path")))
        if relative in seen:
            fail("quarantine purge chunk contains duplicate entries")
        seen.add(relative)
        depth = len(relative.split("/"))
        if previous_depth is not None and depth > previous_depth:
            fail("quarantine purge chunk entries must be deepest-first")
        previous_depth = depth
        kind = raw.get("kind")
        if kind not in ("exact", "scaffold"):
            fail("quarantine purge chunk entry kind is invalid")
        if kind == "scaffold":
            if raw.get("type") != "directory":
                fail("quarantine purge scaffold must be a directory")
        else:
            if raw.get("type") not in ("file", "directory"):
                fail("quarantine purge exact entry type is invalid")
            for field in ("device", "inode", "size"):
                if (
                    not isinstance(raw.get(field), int)
                    or isinstance(raw.get(field), bool)
                    or raw[field] < 0
                ):
                    fail(f"quarantine purge exact entry {field} is invalid")
        entries.append((relative, raw))

    root_fd, parent_fd, purge_fd, _purge_name = open_purge_root(request)
    try:
        if purge_fd is None:
            return {"status": "missing"}
        if delay_ms:
            time.sleep(delay_ms / 1000)
        for relative, entry in entries:
            parts = relative_parts(relative)
            try:
                entry_parent_fd = open_purge_logical_directory(purge_fd, parts[:-1])
            except OSError as error:
                if error.errno == errno.ENOENT:
                    # A deepest-first prior attempt may already have removed
                    # the exact parent after removing this descendant.
                    continue
                raise
            try:
                basename = parts[-1]
                claim_name = deterministic_purge_claim(relative)
                original = stat_entry(entry_parent_fd, basename)
                claimed = stat_entry(entry_parent_fd, claim_name)
                if original is not None and claimed is not None:
                    fail(f"quarantine purge original and atomic claim both exist: {relative}")
                if original is None and claimed is None:
                    continue
                if original is not None:
                    renameat2(entry_parent_fd, basename, entry_parent_fd, claim_name)
                    os.fsync(entry_parent_fd)

                candidate = os.stat(claim_name, dir_fd=entry_parent_fd, follow_symlinks=False)
                if stat.S_ISLNK(candidate.st_mode):
                    fail("quarantine purge encountered a symlink")
                actual_type = (
                    "directory"
                    if stat.S_ISDIR(candidate.st_mode)
                    else "file"
                    if stat.S_ISREG(candidate.st_mode)
                    else "unsupported"
                )
                if entry["kind"] == "scaffold":
                    if actual_type != "directory":
                        fail(f"quarantine purge scaffold type changed: {relative}")
                else:
                    if actual_type != entry["type"]:
                        fail(f"quarantine purge type changed: {relative}")
                    if candidate.st_dev != entry["device"] or candidate.st_ino != entry["inode"]:
                        fail(f"quarantine purge identity changed: {relative}")
                    if actual_type == "file" and (
                        candidate.st_size != entry["size"] or candidate.st_nlink != 1
                    ):
                        fail(f"quarantine purge file metadata changed: {relative}")

                if actual_type == "directory":
                    child_fd = openat2(entry_parent_fd, claim_name)
                    try:
                        if os.listdir(child_fd):
                            fail(f"quarantine purge directory is not empty: {relative}")
                    finally:
                        os.close(child_fd)
                    os.rmdir(claim_name, dir_fd=entry_parent_fd)
                elif actual_type == "file":
                    os.unlink(claim_name, dir_fd=entry_parent_fd)
                else:
                    fail(f"quarantine purge encountered unsupported entry: {relative}")
                os.fsync(entry_parent_fd)
            finally:
                os.close(entry_parent_fd)
        return {"status": "processed"}
    finally:
        if purge_fd is not None:
            os.close(purge_fd)
        os.close(parent_fd)
        os.close(root_fd)


def purge_quarantine_finish(request):
    root_fd, parent_fd, purge_fd, purge_name = open_purge_root(request)
    try:
        if purge_fd is None:
            return {"status": "missing"}
        remaining = sorted(os.listdir(purge_fd))
        if remaining:
            fail(f"quarantine purge encountered unprocessed path: {remaining[0]}")
        os.close(purge_fd)
        purge_fd = None
        os.rmdir(purge_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        return {"status": "purged"}
    finally:
        if purge_fd is not None:
            os.close(purge_fd)
        os.close(parent_fd)
        os.close(root_fd)


def purge_quarantine(request):
    directory_parts = relative_parts(request.get("directory_relative"))
    if len(directory_parts) < 2:
        fail("quarantine purge requires a nested directory")
    raw_entries = request.get("entries")
    if not isinstance(raw_entries, list):
        fail("quarantine purge entries must be an array")

    expected = {}
    scaffolds = set()
    for raw in raw_entries:
        if not isinstance(raw, dict):
            fail("quarantine purge entry must be an object")
        relative = "/".join(relative_parts(raw.get("relative_path")))
        if raw.get("type") not in ("file", "directory"):
            fail("quarantine purge entry type is invalid")
        for field in ("device", "inode", "size"):
            if not isinstance(raw.get(field), int) or raw[field] < 0:
                fail(f"quarantine purge entry {field} is invalid")
        if relative in expected:
            fail("quarantine purge contains duplicate entries")
        expected[relative] = raw
        if raw.get("quarantine_target") is True:
            parent = os.path.dirname(relative)
            while parent not in ("", "."):
                scaffolds.add(parent)
                parent = os.path.dirname(parent)

    fail_after = request.get("test_fail_after_unlinks")
    if fail_after is not None and (
        not isinstance(fail_after, int) or isinstance(fail_after, bool) or fail_after < 1
    ):
        fail("test_fail_after_unlinks must be a positive integer")
    removed_count = [0]
    barrier_used = [False]
    known_paths = set(expected) | scaffolds

    def maybe_fail_for_test():
        removed_count[0] += 1
        if fail_after is not None and removed_count[0] == fail_after:
            fail("test purge crash after journaled unlink")

    def direct_children(prefix):
        children = set()
        prefix_with_separator = f"{prefix}/" if prefix else ""
        for relative in known_paths:
            if not relative.startswith(prefix_with_separator):
                continue
            remainder = relative[len(prefix_with_separator):]
            if not remainder:
                continue
            child = remainder.split("/", 1)[0]
            children.add(f"{prefix_with_separator}{child}")
        return sorted(children)

    def validate_and_purge(directory_fd, prefix, seen, resumed_run):
        actual_names = set(os.listdir(directory_fd))
        logical_children = direct_children(prefix)
        allowed_names = set()
        for relative in logical_children:
            basename = relative.rsplit("/", 1)[-1]
            allowed_names.add(basename)
            allowed_names.add(deterministic_purge_claim(relative))
        unexpected = sorted(actual_names - allowed_names)
        if unexpected:
            relative = f"{prefix}/{unexpected[0]}" if prefix else unexpected[0]
            fail(f"quarantine purge encountered unexpected path: {relative}")

        for relative in logical_children:
            basename = relative.rsplit("/", 1)[-1]
            claim_name = deterministic_purge_claim(relative)
            original_present = basename in actual_names
            claim_present = claim_name in actual_names
            if original_present and claim_present:
                fail(f"quarantine purge original and atomic claim both exist: {relative}")
            if not original_present and not claim_present:
                continue

            already_claimed = claim_present
            if original_present:
                # The pre-claim stat exists only to create a deterministic race
                # barrier in tests.  Identity is authoritative only after the
                # atomic NOREPLACE rename has moved the basename into our claim.
                os.stat(basename, dir_fd=directory_fd, follow_symlinks=False)
                if not barrier_used[0]:
                    test_barrier(request)
                    barrier_used[0] = True
                renameat2(directory_fd, basename, directory_fd, claim_name)
                os.fsync(directory_fd)

            candidate = os.stat(claim_name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(candidate.st_mode):
                fail("quarantine purge encountered a symlink")
            entry = expected.get(relative)
            if entry is None:
                if relative not in scaffolds or not stat.S_ISDIR(candidate.st_mode):
                    fail(f"quarantine purge encountered unexpected path: {relative}")
            else:
                actual_type = "directory" if stat.S_ISDIR(candidate.st_mode) else "file" if stat.S_ISREG(candidate.st_mode) else "unsupported"
                if actual_type != entry["type"]:
                    fail(f"quarantine purge type changed: {relative}")
                if candidate.st_dev != entry["device"] or candidate.st_ino != entry["inode"]:
                    fail(f"quarantine purge identity changed: {relative}")
                if actual_type == "file" and (
                    candidate.st_size != entry["size"] or candidate.st_nlink != 1
                ):
                    fail(f"quarantine purge file metadata changed: {relative}")
                seen.add(relative)

            if stat.S_ISDIR(candidate.st_mode):
                child_seen_before = len(seen)
                child_fd = openat2(directory_fd, claim_name)
                try:
                    validate_and_purge(child_fd, relative, seen, resumed_run)
                finally:
                    os.close(child_fd)
                # A scaffold that was not already claimed cannot disappear and
                # reappear empty between crash attempts.  At least one exact
                # journal descendant must prove its provenance.
                if entry is None and resumed_run and not already_claimed and len(seen) == child_seen_before:
                    fail(f"quarantine purge cannot prove resumed scaffold identity: {relative}")
                os.rmdir(claim_name, dir_fd=directory_fd)
                maybe_fail_for_test()
            elif stat.S_ISREG(candidate.st_mode):
                os.unlink(claim_name, dir_fd=directory_fd)
                maybe_fail_for_test()
            else:
                fail(f"quarantine purge encountered unsupported entry: {relative}")
        os.fsync(directory_fd)

    root_fd = validate_root(request)
    try:
        parent_fd = open_directory_chain(root_fd, directory_parts[:-1], create=False)
        try:
            original_name = directory_parts[-1]
            purge_name = f".purging-{original_name}"
            original = stat_entry(parent_fd, original_name)
            purging = stat_entry(parent_fd, purge_name)
            if original is not None and purging is not None:
                fail("quarantine original and purge target both exist")
            if original is None and purging is None:
                return {"status": "missing"}
            resumed = original is None and purging is not None
            if original is not None:
                if not stat.S_ISDIR(original.st_mode):
                    fail("quarantine purge target is not a directory")
                renameat2(parent_fd, original_name, parent_fd, purge_name)
                os.fsync(parent_fd)

            purge_fd = openat2(parent_fd, purge_name)
            try:
                seen = set()
                validate_and_purge(purge_fd, "", seen, resumed)
                # Missing journaled paths are already absent and therefore
                # safe on both the first pass and a resumed partial purge.
                # Every existing path is still exact-identity checked and any
                # unjournaled path remains a fail-closed error.
            finally:
                os.close(purge_fd)
            os.rmdir(purge_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
            return {"status": "purged"}
        finally:
            os.close(parent_fd)
    finally:
        os.close(root_fd)


def main():
    if sys.platform != "linux":
        fail(f"unsupported platform: {sys.platform}")
    if len(sys.argv) != 2:
        fail("exactly one JSON request argument is required")
    if sys.argv[1] == "--json-stdin":
        raw_request = sys.stdin.buffer.read(16 * 1024 * 1024 + 1)
        if len(raw_request) > 16 * 1024 * 1024:
            fail("JSON request exceeds 16 MiB")
        request = json.loads(raw_request.decode("utf-8"))
    else:
        request = json.loads(sys.argv[1])
    if not isinstance(request, dict):
        fail("request must be an object")
    action = request.get("action")
    if action == "quarantine_rename":
        result = quarantine_rename(request)
    elif action == "validate_directory":
        result = validate_directory(request)
    elif action == "inspect_file":
        result = inspect_file(request)
    elif action == "ingest_publish":
        result = ingest_publish(request)
    elif action == "cleanup_ingest_temp":
        result = cleanup_ingest_temp(request)
    elif action == "find_matching_file":
        result = find_matching_file(request)
    elif action == "remove_identity":
        result = remove_identity(request)
    elif action == "purge_quarantine":
        result = purge_quarantine(request)
    elif action == "purge_quarantine_chunk":
        result = purge_quarantine_chunk(request)
    elif action == "purge_quarantine_finish":
        result = purge_quarantine_finish(request)
    else:
        fail("unsupported request action")
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        sys.stderr.write(str(error) + "\n")
        sys.exit(70)
