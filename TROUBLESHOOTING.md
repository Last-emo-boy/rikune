# Rikune Troubleshooting Guide

Common errors and how to fix them when deploying or running the Analyzer-Runtime split architecture.

---

## Error Code Index

| Code / Keyword | Section | Typical Cause |
|----------------|---------|---------------|
| `E1001` | [Windows Sandbox not available](#e1001-windows-sandbox-not-available) | Windows Home edition or feature not enabled |
| `E1002` | [Host Agent port unreachable](#e1002-host-agent-port-unreachable) | Windows Firewall blocking TCP 18082 |
| `E1003` | [Portproxy conflict](#e1003-portproxy-conflict) | Multiple Sandboxes competing for the same port |
| `E1004` | [Runtime isolation check failed](#e1004-runtime-isolation-check-failed) | Runtime Node started outside Windows Sandbox without `ALLOW_UNSAFE_RUNTIME` |
| `E2001` | [Python worker not found](#e2001-python-worker-not-found) | `workers/` directory missing or not built |
| `E2002` | [Sample upload failed](#e2002-sample-upload-failed) | Cross-host file copy attempted instead of HTTP upload |
| `E3001` | [Analyzer cannot reach Runtime](#e3001-analyzer-cannot-reach-runtime) | Network misconfiguration or Runtime not started |
| `E3002` | [Sandbox crashed / 502 error](#e3002-sandbox-crashed--502-error) | Windows Sandbox process terminated unexpectedly |
| `E4001` | [MCP tool timeout](#e4001-mcp-tool-timeout) | Long-running dynamic analysis exceeded default timeout |

---

## E1001: Windows Sandbox not available

**Symptom:**
```
Windows Sandbox is not available on Windows Home. Use Windows 10/11 Pro or Enterprise.
```

**Fix:**
1. Confirm your Windows edition is **Pro** or **Enterprise** (`winver`).
2. Enable the feature (requires Administrator + reboot):
   ```powershell
   Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClient" -All
   ```
3. Restart the computer if prompted.

---

## E1002: Host Agent port unreachable

**Symptom:**
`diagnose-hybrid.sh` reports:
```
[FAIL] TCP port 18082 on 192.168.x.x is unreachable
```

**Fix:**
1. Ensure the Host Agent process is running on Windows:
   ```powershell
   Get-Process | Where-Object { $_.ProcessName -eq "node" -and $_.CommandLine -like "*host-agent*" }
   ```
2. Add an inbound firewall rule:
   ```powershell
   # Administrator
   netsh advfirewall firewall add rule name="RikuneHostAgent" dir=in action=allow protocol=tcp localport=18082
   ```
3. If the Windows host is a VM, ensure the hypervisor/virtual-network allows traffic between the Linux and Windows guests.

---

## E1003: Portproxy conflict

**Symptom:**
Multiple concurrent `sandbox.execute` calls fail, or the second Sandbox is unreachable.

**Fix:**
This was fixed in a recent update by using dynamic listen ports (18081–19000). If you are on an old version:
- Upgrade to the latest branch.
- Or manually clear stale rules:
  ```powershell
  netsh interface portproxy show v4tov4
  netsh interface portproxy delete v4tov4 listenport=<stale-port>
  ```

---

## E1004: Runtime isolation check failed

**Symptom:**
```
Runtime Node reports unverified isolation. Ensure it is running inside Windows Sandbox.
Process exited with code 1.
```

**Fix:**
- **Intended behavior:** The Runtime Node refuses to start if it detects it is not inside an isolated environment (Windows Sandbox / VM). This prevents accidental execution of malware on a physical machine.
- If you are **deliberately** testing on a physical machine (dangerous), set:
  ```powershell
  $env:ALLOW_UNSAFE_RUNTIME="true"
  ```
- For production, always run the Runtime Node inside Windows Sandbox or a VM.

---

## E2001: Python worker not found

**Symptom:**
```
Required runtime paths are missing. runtimeEntryHost=... (exists=false)
```

**Fix:**
1. Make sure you ran the build steps:
   ```bash
   npm run build:runtime
   npm run build:host-agent
   ```
2. Verify `packages/runtime-node/dist/index.js` and `workers/static_worker.py` exist.
3. If running from a global install or different working directory, the Host Agent will try to auto-discover the project root by walking up from `__dirname`. Ensure the `workers/` and `packages/` directories are present at the expected location.

---

## E2002: Sample upload failed

**Symptom:**
```
Error: ENOENT: no such file or directory, copyfile ...
```

**Fix:**
- This happens when the Analyzer assumes the Runtime inbox is on the same local filesystem (old behavior).
- Ensure both the Analyzer and Runtime Node are on the latest branch.
- In cross-host mode, the Analyzer will automatically switch to HTTP upload (`POST /upload`).
- If you still see `copyFile` errors, verify the Runtime Node `/upload` endpoint is reachable and the `inbox` directory is writable.

---

## E3001: Analyzer cannot reach Runtime

**Symptom:**
`system.health` returns:
```json
{ "runtimeConnected": false }
```

**Fix:**
1. Check that the Runtime Node (or Host Agent) is actually running and listening on the configured port.
2. Verify there are no typos in `RUNTIME_ENDPOINT` or `RUNTIME_HOST_AGENT_ENDPOINT`.
3. Test connectivity manually from the Analyzer container:
   ```bash
   docker exec -it rikune-analyzer curl -v http://windows-ip:18082/sandbox/health
   ```
4. If using `remote-sandbox`, ensure the Host Agent successfully started the Sandbox (check Host Agent logs).

---

## E3002: Sandbox crashed / 502 error

**Symptom:**
```
Runtime returned 502 / ECONNREFUSED
Dynamic analysis runtime is not available.
```

**Fix:**
1. Check Windows Event Viewer for Windows Sandbox crashes.
2. Look at the Host Agent logs to see if the Sandbox process exited.
3. Ensure the Windows host has enough free RAM (Windows Sandbox needs ~4 GB).
4. The Analyzer now has a 1-time auto-retry. If it still fails, restart the Host Agent or manually trigger a new Sandbox start.

---

## E4001: MCP tool timeout

**Symptom:**
The AI client reports that the tool call timed out after 120 seconds, but the Sandbox is still running.

**Fix:**
- The Analyzer-side `delegation-server.ts` now polls the Runtime asynchronously and reports progress via MCP `notifications/progress`.
- If your MCP client does not support progress notifications, increase the client-side timeout, or break the analysis into smaller steps.
- You can also cancel a long-running task from the Runtime Node:
  ```bash
  curl -X POST -H "Authorization: Bearer $API_KEY" http://runtime:18081/tasks/<taskId>/cancel
  ```

---

## Diagnostics Checklist

Run the diagnostic script first:

```bash
./diagnose-hybrid.sh -w <windows-ip>
```

If the problem persists, collect the following information before opening an issue:

1. **Linux side**
   - Output of `docker compose -f docker-compose.hybrid.yml logs analyzer`
   - Output of `./diagnose-hybrid.sh -w <windows-ip>`

2. **Windows side**
   - Host Agent logs (`pm2 logs rikune-host-agent` or service logs)
   - Output of `Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClient`
   - Output of `netsh interface portproxy show v4tov4`
   - Output of `Get-NetFirewallRule -DisplayName "RikuneHostAgent"`

3. **Network**
   - Can you `ping` / `curl` from Linux to Windows on port 18082?
   - Is there a corporate VPN or firewall between the two hosts?
