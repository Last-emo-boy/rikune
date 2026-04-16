import type { MCPServer } from '../server.js'
import type { ToolDeps } from '../tool-registry.js'
import { taskStatusToolDefinition, createTaskStatusHandler } from '../../tools/task-status.js'
import { taskCancelToolDefinition, createTaskCancelHandler } from '../../tools/task-cancel.js'
import { taskSweepToolDefinition, createTaskSweepHandler } from '../../tools/task-sweep.js'

export function registerTaskTools(server: MCPServer, deps: ToolDeps): void {
  const { jobQueue, database } = deps
  server.registerTool(taskStatusToolDefinition, createTaskStatusHandler(jobQueue, database))
  server.registerTool(taskCancelToolDefinition, createTaskCancelHandler(jobQueue))
  server.registerTool(taskSweepToolDefinition, createTaskSweepHandler(jobQueue, database))
}
