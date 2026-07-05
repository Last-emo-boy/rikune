# Windows Interface Surface Iteration

Date: 2026-06-26
Branch: feat/windows-interface-surface
Base: beta

## Intent

Continue Rikune frontier tool-surface expansion with a passive/static Windows
userland interface inventory. The target is COM/DCOM CLSID/IID evidence, RPC
interface UUID and endpoint hints, ALPC and named-pipe IPC strings, ETW provider
GUIDs and event API references, WMI namespaces/classes, service-control
surfaces, and static workflow handoff.

## External Signals

- Windows interface boundaries remain relevant for modern malware triage and
  lateral-movement analysis because COM/RPC/WMI/ETW/named-pipe evidence often
  exposes orchestration and IPC surfaces before dynamic execution.
- Microsoft documentation defines stable identifiers and metadata patterns for
  COM CLSID/IID, RPC UUID/interface endpoints, ETW provider GUIDs, and WMI
  namespaces that can be passively identified from binaries and strings.

## Safety Boundary

The first version is passive/static bounded-read only. It must not execute the
sample, activate COM objects, contact RPC endpoints, connect to ALPC or named
pipes, query WMI, start services, register ETW providers, attach a debugger,
invoke external tools, use the network, or mutate samples.

## Selected Direction

Tool: windows.interface.surface.inventory
Plugin: windows-interface-surface
Artifact: windows_interface_surface_inventory
