import pino from 'pino'
import { config } from './config.js'

// Keep service logs off stdout so this package remains safe if embedded
// behind a stdio transport or supervised by a protocol-aware parent.
export const logger = pino(
  { level: config.logging.level },
  pino.destination({ dest: 2, sync: false }),
)
