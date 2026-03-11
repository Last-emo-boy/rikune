"""
Compatibility helpers for environments where the installed speakeasy-emulator
distribution exposes a namespace package without the top-level Speakeasy class.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Optional, Tuple


def _resolve_package_root(module: ModuleType) -> Path:
    module_path = getattr(module, "__file__", None)
    if module_path:
        return Path(module_path).resolve().parent

    module_search_paths = list(getattr(module, "__path__", []))
    if module_search_paths:
        return Path(module_search_paths[0]).resolve()

    raise RuntimeError("Unable to resolve speakeasy package root")


def _load_default_config(package_root: Path) -> Dict[str, Any]:
    config_path = package_root / "configs" / "default.json"
    if not config_path.is_file():
        raise RuntimeError(f"Speakeasy default config not found: {config_path}")
    return json.loads(config_path.read_text(encoding="utf-8"))


def load_speakeasy_module() -> Tuple[ModuleType, Dict[str, Any]]:
    """
    Return an importable speakeasy module plus diagnostics.

    On some environments the wheel installs `speakeasy` as a namespace package
    without exporting `Speakeasy` from the top level. In that case we inject a
    small compatibility wrapper that recreates the public API used by this
    project.
    """

    module = importlib.import_module("speakeasy")
    package_root = _resolve_package_root(module)
    module_path = getattr(module, "__file__", None) or str(package_root)

    if hasattr(module, "Speakeasy"):
        return module, {
            "import_mode": "direct",
            "module_path": module_path,
            "package_root": str(package_root),
            "warnings": [],
        }

    from speakeasy.windows.common import PeFile
    from speakeasy.windows.kernel import WinKernelEmulator
    from speakeasy.windows.win32 import Win32Emulator

    default_config = _load_default_config(package_root)

    class SpeakeasyCompat:
        """Small adapter that recreates the top-level Speakeasy API."""

        def __init__(
            self,
            config: Optional[Dict[str, Any]] = None,
            logger: Any = None,
            argv: Optional[list[str]] = None,
            exit_event: Any = None,
            debug: bool = False,
        ) -> None:
            if config is None:
                config_obj = dict(default_config)
            elif isinstance(config, str):
                config_obj = json.loads(config)
            else:
                config_obj = config

            self.config = config_obj
            self.logger = logger
            self.argv = list(argv or [])
            self.exit_event = exit_event
            self.debug = debug
            self._emu: Any = None
            self._loaded_module: Any = None

        def _ensure_emu(self) -> Any:
            if self._emu is None:
                raise RuntimeError("No module or shellcode has been loaded into SpeakeasyCompat")
            return self._emu

        def load_module(self, path: Optional[str] = None, data: Optional[bytes] = None) -> Any:
            pe = PeFile(path=path, data=data)
            if pe.is_driver():
                emu = WinKernelEmulator(
                    self.config,
                    debug=self.debug,
                    logger=self.logger,
                    exit_event=self.exit_event,
                )
            else:
                emu = Win32Emulator(
                    self.config,
                    argv=self.argv,
                    debug=self.debug,
                    logger=self.logger,
                    exit_event=self.exit_event,
                )
            module_obj = emu.load_module(path=path, data=data)
            self._emu = emu
            self._loaded_module = module_obj
            return module_obj

        def run_module(
            self,
            module_obj: Any = None,
            all_entrypoints: bool = False,
            emulate_children: bool = False,
        ) -> Any:
            emu = self._ensure_emu()
            target = module_obj if module_obj is not None else self._loaded_module
            if isinstance(emu, WinKernelEmulator):
                return emu.run_module(target, all_entrypoints=all_entrypoints)
            return emu.run_module(
                target,
                all_entrypoints=all_entrypoints,
                emulate_children=emulate_children,
            )

        def load_shellcode(self, path: str, arch: str, data: Optional[bytes] = None) -> Any:
            emu = Win32Emulator(
                self.config,
                argv=self.argv,
                debug=self.debug,
                logger=self.logger,
                exit_event=self.exit_event,
            )
            shellcode_addr = emu.load_shellcode(path, arch, data=data)
            self._emu = emu
            self._loaded_module = None
            return shellcode_addr

        def run_shellcode(self, shellcode_addr: int, offset: int = 0) -> Any:
            emu = self._ensure_emu()
            return emu.run_shellcode(shellcode_addr, offset=offset)

        def get_report(self) -> Any:
            emu = self._ensure_emu()
            return emu.get_report()

        def get_json_report(self) -> Any:
            emu = self._ensure_emu()
            return emu.get_json_report()

        def create_memdump_archive(self) -> Optional[bytes]:
            return None

        def create_file_archive(self) -> Optional[bytes]:
            return None

    module.Speakeasy = SpeakeasyCompat
    module.Win32Emulator = Win32Emulator
    module.WinKernelEmulator = WinKernelEmulator
    module.PeFile = PeFile

    return module, {
        "import_mode": "compat_shim",
        "module_path": module_path,
        "package_root": str(package_root),
        "warnings": [
            "Installed speakeasy-emulator exposes a namespace package without top-level Speakeasy; activated local compatibility shim."
        ],
    }

