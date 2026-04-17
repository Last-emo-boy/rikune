import { z } from 'zod'

export const DynamicAnalysisStageSchema = z.enum([
  'preflight',
  'simulation',
  'trace_capture',
  'correlation',
  'digest',
])

export type DynamicAnalysisStage = z.infer<typeof DynamicAnalysisStageSchema>
