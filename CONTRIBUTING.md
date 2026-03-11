# Contributing

## Development setup

1. Install Node.js 22 or newer.
2. Install Python 3.11 or newer.
3. Install dependencies:

```powershell
npm ci
python -m pip install -r requirements.txt
python -m pip install -r workers/requirements-dynamic.txt
```

4. Build the TypeScript sources:

```powershell
npm run build
```

## Recommended validation

Run the checks below before opening a pull request:

```powershell
npm run build
python -m py_compile workers/static_worker.py workers/speakeasy_compat.py
npm test -- --runInBand
npm run pack:dry-run
```

If you changed Ghidra, .NET, packaging, or runtime orchestration code, prefer
running the closest focused tests in `tests/unit/` instead of relying only on
full-suite execution.

## Repository conventions

- Keep MCP tool schemas, tool descriptions, and `tool.help` output aligned.
- Prefer stable artifacts over untracked workspace files.
- Preserve provenance fields when adding new report or workflow outputs.
- When adding a new MCP tool or prompt, register it in `src/index.ts` and make
  sure route coverage tests still pass.
- Avoid committing generated workspace outputs, caches, and temporary reports.

## Release flow

1. Update `CHANGELOG.md`.
2. Run `npm run release:check`.
3. Bump the package version:

```powershell
npm version patch
```

4. Push the commit and tag:

```powershell
git push origin main --follow-tags
```

The `publish-npm.yml` workflow publishes tagged releases.
