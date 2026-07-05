# Kernel Driver Surface Iteration

## Intent

Add a passive kernel driver surface inventory plugin for Windows `.sys` and Linux `.ko` artifacts without loading drivers/modules, opening devices, sending IOCTLs, calling syscalls, attaching probes, starting debuggers, invoking external tools, mutating samples, or using network.

## Branch

`feat/kernel-driver-surface` from `beta`.

## Split Research

- Mencius: recommended `kernel-driver-surface` as the next gap after C++ ABI, because existing tools identify driver role and PE/Linux structure but do not produce a unified IOCTL/device/module surface artifact.
- Gibbs: confirmed the passive/static plugin pattern: `index.ts`, `tools/<tool>.ts`, dedicated unit tests, SDK taxonomy, `workflow.search`, plugin matrix, docs, tool catalog, and Docker generation.
- Hypatia: compared Windows IOCTL/IRP mapping, Linux module/eBPF metadata, and UEFI/SMM triage. Windows/Linux driver surface is suitable for a bounded static first version; runtime probing must remain opt-in only.

## Initial Scope

- Plugin id: `kernel-driver-surface`
- Tool: `kernel.driver.surface.inventory`
- Artifact: `kernel_driver_surface_inventory`
- Recipe: `kernel.driver-surface-static-inventory`
- Static evidence:
  - Windows: `DriverEntry`, `IRP_MJ_DEVICE_CONTROL`, WDM/KMDF hints, device path strings, candidate `CTL_CODE` values, `METHOD_NEITHER`, `FILE_ANY_ACCESS`, risky primitives such as `MmMapIoSpace`.
  - Linux: `.modinfo`-style `vermagic`, `license`, `depends`, `parm`, `name`, `file_operations`, `unlocked_ioctl`, `compat_ioctl`, `/dev` paths, `copy_from_user`, `ioremap`.

## Safety Boundary

The plugin is passive-only. Runtime validation is represented only through `windows.runtime.plan` / `linux.runtime.plan` handoff and does not mark this tool as `runtime_opt_in_required`.
