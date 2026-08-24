const path = require('node:path')

const projectRoot = path.resolve(__dirname, '..', '..')

module.exports = {
  apps: [
    {
      name: 'rikune-host-agent',
      script: path.join(projectRoot, 'packages', 'windows-host-agent', 'dist', 'bootstrap.js'),
      cwd: projectRoot,
      instances: 1,
      autorestart: true,
      max_memory_restart: '512M',
      env: {
        NODE_ENV: 'production',
      },
      log_file: path.join(projectRoot, 'logs', 'host-agent-combined.log'),
      out_file: path.join(projectRoot, 'logs', 'host-agent-out.log'),
      error_file: path.join(projectRoot, 'logs', 'host-agent-error.log'),
      merge_logs: true,
      time: true,
    },
  ],
}
