# Frida Script Resources

This directory contains bundled Frida JavaScript helpers. They are exposed through MCP resources when the server registers script resources.

## Resource URIs

| URI | File | Purpose |
| --- | --- | --- |
| `script://frida/anti_debug_bypass` | `anti_debug_bypass.js` | Bypass common anti-debug checks |
| `script://frida/api_trace` | `api_trace.js` | Trace Windows API calls |
| `script://frida/crypto_finder` | `crypto_finder.js` | Detect crypto API usage |
| `script://frida/file_registry_monitor` | `file_registry_monitor.js` | Monitor file and registry access |
| `script://frida/string_decoder` | `string_decoder.js` | Assist runtime string decoding |

Android Frida helper resources are defined in `src/plugins/android/scripts/` and registered by the same script manifest.

## Resolution

Resource paths are resolved by `src/core/tool-registry/script-resource-manifest.ts`.

The resolver checks:

1. `RIKUNE_RESOURCE_ROOT` when set.
2. The package or repository root discovered from the entry point.
3. Source paths such as `src/plugins/frida/scripts/*.js`.
4. Built package paths such as `dist/resources/scripts/frida/*.js`.

## Usage

MCP clients can list and read these scripts through `resources/list` and `resources/read`. Tools may also use them as templates for Frida instrumentation plans.

These scripts are helpers. Live instrumentation still requires an available Frida backend, a runtime plan, and the appropriate execution semantics.

## Adding Scripts

1. Add the script file in this directory.
2. Add an entry in `script-resource-manifest.ts`.
3. Ensure `scripts/copy-static-assets.mjs` copies the asset into the built package if needed.
4. Add or update tests for resource registration.
5. Document the new URI here.

## Troubleshooting

If a resource is missing:

- run `npm run build`;
- check `RIKUNE_RESOURCE_ROOT`;
- verify the source and `dist/resources/scripts` paths;
- call `resources/list` to confirm the URI;
- check package installation paths when running from a global install.
