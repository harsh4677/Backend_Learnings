const { createLogger, format, transports } = require('winston');
const { combine, timestamp, printf } = format;

// Custom log format
const logFormat = printf(({ level, message, timestamp }) => {
  return `${timestamp} [${level.toUpperCase()}]: ${message}`;
});

// Create the Winston logger instance
const logger = createLogger({
  level: 'info', // Default log level
  format: combine(
    timestamp(),   // Add timestamp to log messages
    logFormat      // Apply custom format
  ),
  transports: [
    // Log to console
    new transports.Console(),
    // Optionally log to a file
    new transports.File({ filename: 'logs/error.log', level: 'error' }),
    new transports.File({ filename: 'logs/combined.log' })
  ]
});

module.exports = logger;
