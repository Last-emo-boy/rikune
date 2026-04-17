import pino from 'pino'

// Keep service logs off stdout so protocol clients never see non-protocol data
// if the agent is launched under a stdio-aware supervisor.
export const logger = pino(
  {
    level: process.env.LOG_LEVEL || 'info',
    name: 'windows-host-agent',
  },
  pino.destination({ dest: 2, sync: false }),
)
