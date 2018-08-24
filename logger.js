const { transports, format, createLogger } = require('winston')

const LOG_PATH = process.env.LOG_PATH
  ? process.env.LOG_PATH.endsWith('/')
    ? process.env.LOG_PATH
    : process.env.LOG_PATH + '/'
  : __dirname + '/'

const LOGGER = createLogger({
  level: 'info',
  format: format.combine(
    format.colorize(),
    format.json()
  ),
  exitOnError: false,
  exceptionHandlers: [
    new transports.File({ filename: `${LOG_PATH}exceptions.log` })
  ],
  transports: [
    new transports.File({ filename: `${LOG_PATH}silly.log`, level: 'silly' }),
    new transports.File({ filename: `${LOG_PATH}combined.log`, level: 'info' }),
    new transports.File({ filename: `${LOG_PATH}errors.log`, level: 'error' })
  ]
})

if (process.env.NODE_ENV !== 'production') {
  LOGGER.add(new transports.Console({
    format: format.simple()
  }))
}

LOGGER.stream = {
  write: function(message, encoding) {
    LOGGER.info(message);
  },
}

module.exports = LOGGER
