# Rikune SDK 标准化与全插件迁移计划

## 目标

稳定 `@rikune/plugin-sdk`，形成一个所有内置插件都遵守的非破坏性标准，并让 `plugin.list`、`tools.discover`、`tool.help`、`tool.readiness`、contract tests 和文档共同守住这个标准。

## 标准边界

- 所有插件必须声明基础 metadata、`executionDomain`、`aspects`、`surfaceRules`。
- 所有工具必须有 `inputSchema`、`outputSchema`，并在产生分析结果时声明 `artifacts` 或 `evidence`。
- dynamic/runtime 工具必须有 `runtimePolicy` 和 runtime contract，或明确声明为 plan-only/passive。
- 缺失字段先进入 `qualityWarnings`，迁移完成后再决定哪些 warning 升级为 error。
- `src/plugins/sdk.ts` 继续作为兼容 re-export，不强迫一次性改 import。

## 执行波次

1. **Wave 1：Standard Contract Barrier**
   - `TASK-001` 定义插件标准和文档。
   - `TASK-002` 建立插件审计和测试门禁。

2. **Wave 2：SDK and Tool Surface Implementation**
   - `TASK-003` 稳定 SDK / shared runtime contract / scaffold。
   - `TASK-004` 让 orchestrator 和 tool surface 消费统一标准。
   - `TASK-005` 让 discovery/help/readiness/plugin-list 展示标准状态。

3. **Wave 3：Static Plugin Migration**
   - `TASK-006` 迁移核心静态分析插件。
   - `TASK-007` 迁移格式、包、容器、字节码和报告类静态插件。

4. **Wave 4：Runtime and New Matrix Plugin Migration**
   - `TASK-008` 迁移 dynamic/runtime 插件，保持默认 passive。
   - `TASK-009` 迁移新增平台/格式插件目录。

5. **Wave 5：Release Guard**
   - `TASK-010` 文档、fixture matrix、最终验证和 changelog 收口。

## 执行约束

- 当前工作树已有大量 SDK / plugin WIP，执行者不得覆盖未读文件。
- 每个任务只拥有自己的文件范围。
- 每个任务完成后至少运行对应 `runTestsByPath`。
- 全部任务完成后运行 `npm run typecheck`、`npm run lint` 和插件审计。
