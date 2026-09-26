"""Exercise real dirfd operations with native and ENOSYS directory opens."""

import ctypes
import errno
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "secure_fs", Path(__file__).resolve().parents[2] / "scripts/secure-fs-helper.py"
)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def unavailable(*_args):
    ctypes.set_errno(errno.ENOSYS)
    return -1


class SecureDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(sys.platform, "linux", "Run secure filesystem tests on Linux")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "root"
        self.root.mkdir()
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        info = os.fstat(self.fd)
        self.request = {
            "root": str(self.root),
            "root_device": info.st_dev,
            "root_inode": info.st_ino,
        }

    def test_unmodified_syscall_path_opens_directory(self):
        (self.root / "child").mkdir()
        fd = helper.openat2(self.fd, "child")
        try:
            self.assertEqual(os.fstat(fd).st_ino, (self.root / "child").stat().st_ino)
            self.assertFalse(os.get_inheritable(fd))
        finally:
            os.close(fd)

    def test_successful_openat2_does_not_use_fallback(self):
        (self.root / "child").mkdir()
        fd = os.open(self.root / "child", os.O_RDONLY | os.O_DIRECTORY)
        try:
            with mock.patch.object(helper.LIBC, "syscall", return_value=fd), mock.patch.object(
                helper.os, "open", side_effect=AssertionError("unexpected fallback")
            ):
                self.assertEqual(helper.openat2(self.fd, "child"), fd)
        finally:
            os.close(fd)

    def test_enosys_creates_and_pins_nested_directories(self):
        with mock.patch.object(helper.LIBC, "syscall", side_effect=unavailable):
            fd = helper.open_directory_chain(self.fd, ["aa", "bb"], create=True)
            try:
                self.assertTrue(stat.S_ISDIR(os.fstat(fd).st_mode))
                self.assertEqual(os.fstat(fd).st_ino, (self.root / "aa/bb").stat().st_ino)
                self.assertFalse(os.get_inheritable(fd))
            finally:
                os.close(fd)

    def test_invalid_components_rejected_before_either_syscall(self):
        with mock.patch.object(helper.LIBC, "syscall", side_effect=AssertionError("syscall reached")):
            for name in ("", ".", "..", "a/b", "a/../b", "/tmp", "a/", "a\x00b"):
                with self.subTest(name=name), self.assertRaises(RuntimeError):
                    helper.openat2(self.fd, name)

    def test_non_enosys_errors_are_not_downgraded(self):
        for code in (errno.EPERM, errno.EACCES, errno.ELOOP, errno.EXDEV, errno.EINVAL, errno.EIO):
            def rejected(*_args):
                ctypes.set_errno(code)
                return -1

            with self.subTest(errno=code), mock.patch.object(helper.LIBC, "syscall", side_effect=rejected), mock.patch.object(
                helper.os, "open", side_effect=AssertionError("unexpected fallback")
            ):
                with self.assertRaises(OSError) as caught:
                    helper.openat2(self.fd, "child")
                self.assertEqual(caught.exception.errno, code)

    def test_enosys_rejects_symlinks_files_and_missing_paths(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (self.root / "link").symlink_to(outside)
        (self.root / "dangling").symlink_to(outside / "missing")
        (self.root / "file").write_bytes(b"not a directory")
        with mock.patch.object(helper.LIBC, "syscall", side_effect=unavailable):
            for name in ("link", "dangling", "file", "missing"):
                with self.subTest(name=name), self.assertRaises(OSError):
                    helper.openat2(self.fd, name)
            with self.assertRaises(OSError):
                helper.open_directory_chain(self.fd, ["link", "escape"], create=True)
        self.assertEqual(list(outside.iterdir()), [])

    def test_enosys_rejects_procfs_magic_link(self):
        proc_fd = os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY)
        try:
            with mock.patch.object(helper.LIBC, "syscall", side_effect=unavailable):
                with self.assertRaises(OSError):
                    helper.openat2(proc_fd, str(self.fd))
        finally:
            os.close(proc_fd)

    def test_enosys_ancestor_swap_keeps_original_directory_pinned(self):
        (self.root / "parent/leaf").mkdir(parents=True)
        expected = (self.root / "parent/leaf").stat().st_ino
        outside = Path(self.temp.name) / "outside"
        (outside / "leaf").mkdir(parents=True)
        real_open = os.open

        def swap(name, flags, *args, **kwargs):
            if name == "leaf":
                (self.root / "parent").rename(self.root / "original")
                (self.root / "parent").symlink_to(outside)
            return real_open(name, flags, *args, **kwargs)

        with mock.patch.object(helper.LIBC, "syscall", side_effect=unavailable), mock.patch.object(helper.os, "open", side_effect=swap):
            fd = helper.open_directory_chain(self.fd, ["parent", "leaf"])
            try:
                self.assertEqual(os.fstat(fd).st_ino, expected)
                self.assertNotEqual(os.fstat(fd).st_ino, (outside / "leaf").stat().st_ino)
            finally:
                os.close(fd)

    def test_enosys_repeated_failures_do_not_leak_descriptors(self):
        (self.root / "parent").mkdir()
        before = len(os.listdir("/proc/self/fd"))
        with mock.patch.object(helper.LIBC, "syscall", side_effect=unavailable):
            for _ in range(20):
                with self.assertRaises(FileNotFoundError):
                    helper.open_directory_chain(self.fd, ["parent", "missing"])
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_enosys_publish_deduplicate_inspect_and_quarantine(self):
        (self.root / "samples/hash").mkdir(parents=True)
        payload = b"MZ benign upload regression fixture\x00"
        request = {
            **self.request,
            "directory_relative": "samples/hash",
            "temp_name": ".rikune-upload-temp",
            "final_name": "sample.exe",
            "expected_size": len(payload),
            "expected_sha256": hashlib.sha256(payload).hexdigest(),
        }
        with mock.patch.object(helper.LIBC, "syscall", side_effect=unavailable):
            with mock.patch.object(helper.sys, "stdin", io.TextIOWrapper(io.BytesIO(payload))):
                result = helper.ingest_publish(request)
            self.assertEqual(result["status"], "published")
            self.assertEqual((self.root / "samples/hash/sample.exe").read_bytes(), payload)
            self.assertEqual(helper.ingest_publish(request)["status"], "already_present")
            self.assertEqual(helper.find_matching_file(request)["status"], "matched")
            self.assertEqual(helper.inspect_file({**request, "name": "sample.exe"})["status"], "found")
            moved = helper.quarantine_rename({
                **self.request,
                "source_relative": "samples/hash/sample.exe",
                "destination_relative": ".trash/check/sample.exe",
                "expected_device": result["device"],
                "expected_inode": result["inode"],
                "expected_type": "file",
            })
            self.assertEqual(moved["status"], "renamed")
            self.assertEqual((self.root / ".trash/check/sample.exe").read_bytes(), payload)
            removed = helper.remove_identity({
                **self.request,
                "directory_relative": ".trash/check",
                "source_name": "sample.exe",
                "quarantine_name": ".rikune-remove-check",
                "expected_device": result["device"],
                "expected_inode": result["inode"],
            })
            self.assertEqual(removed["status"], "removed")
            self.assertFalse((self.root / ".trash/check/sample.exe").exists())


if __name__ == "__main__":
    unittest.main()
