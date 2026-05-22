# TASK-001 Summary

Status: completed

Implemented the cross-plugin workflow backplane for the next plugin capability iteration.

- Added `WorkflowRecipeSpec` / `workflowRecipes` to the plugin SDK and server tool definitions.
- Propagated workflow recipe metadata through `plugin.list`, `tools.discover`, `tool.help`, `tool.readiness`, `sample.profile.get`, and `tool-aspect-matrix`.
- Added matrix indexing via `by_workflow` and `workflow_recipe_count`.
- Documented the shared workflow/artifact/evidence vocabulary in `docs/PLUGINS.md`.

Verification:

- `npm test -- --runTestsByPath tests/unit/packages/plugin-sdk.test.ts tests/unit/tools-discover.test.ts tests/unit/tool-help.test.ts tests/unit/plugin-list.test.ts tests/unit/tool-readiness.test.ts tests/unit/sample-profile-get.test.ts tests/unit/plugin-format-matrix.test.ts`
- `npm run typecheck`
- `npm run lint`
