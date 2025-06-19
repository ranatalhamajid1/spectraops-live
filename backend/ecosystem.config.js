module.exports = {
  apps: [
    {
      name: 'spectraops-backend',
      script: 'server.js',
      cwd: '/var/www/spectraops/backend',
      instances: 'max',
      exec_mode: 'cluster',
      env: {
        NODE_ENV: 'production',
        PORT: 3000
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 3000
      },
      // Logging
      log_file: './logs/combined.log',
      out_file: './logs/out.log',
      error_file: './logs/error.log',
      log_date_format: 'YYYY-MM-DD HH:mm Z',
      
      // Process management
      min_uptime: '10s',
      max_restarts: 10,
      autorestart: true,
      
      // Advanced features
      watch: false,
      ignore_watch: ['node_modules', 'logs', 'data'],
      
      // Memory and CPU limits
      max_memory_restart: '500M',
      
      // Health monitoring
      health_check_url: 'http://localhost:3000/api/health',
      health_check_grace_period: 3000,
      
      // Graceful shutdown
      kill_timeout: 5000,
      listen_timeout: 8000,
      
      // Environment variables
      env_file: '.env'
    },
    {
      name: 'spectraops-monitor',
      script: 'scripts/monitor.js',
      cwd: '/var/www/spectraops/backend',
      instances: 1,
      autorestart: true,
      env: {
        NODE_ENV: 'production'
      }
    }
  ]
};