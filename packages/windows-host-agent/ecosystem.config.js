module.exports = {
  apps: [
    {
      name: 'rikune-host-agent',
      script: './packages/windows-host-agent/dist/index.js',
      cwd: '.',
      instances: 1,
      autorestart: true,
      max_memory_restart: '512M',
      env: {
        NODE_ENV: 'production',
      },
      log_file: './logs/host-agent-combined.log',
      out_file: './logs/host-agent-out.log',
      error_file: './logs/host-agent-error.log',
      merge_logs: true,
      time: true,
    },
  ],
}
