import type { ApiBootstrapper } from './api-bootstrapper.js'

export const defaultApiBootstrapper: ApiBootstrapper = {
  async bootstrap({ server, database, workspaceManager, storageManager }) {
    const { initDashboard } = await import('./routes/dashboard-api.js')
    initDashboard({ server, database, workspaceManager })

    const { setHealthDependencies } = await import('./routes/health.js')
    setHealthDependencies({ database, storageManager })
  },
}
