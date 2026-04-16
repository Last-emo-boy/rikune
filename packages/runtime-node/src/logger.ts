import pino from 'pino'
import { config } from './config.js'

export const logger = pino({
  level: config.logging.level,
})
