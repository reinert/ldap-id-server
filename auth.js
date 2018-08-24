const { promisify } = require('util')
const ldap = require('ldapjs')

const LOGGER = require('./logger')
const CONFIG = require(process.env.CONFIG || './config')

const getClient = options => new Promise((resolve, reject) => {
  const client = ldap.createClient(options)

  const res = e => {
    client.removeListener('connectError', reject)
    client.removeListener('setupError', reject)
    client.removeListener('end', reject)
    client.removeListener('socketTimeout', reject)
    client.removeListener('connectTimeout', reject)
    client.removeListener('error', reject)
    resolve(client)
  }

  client.once('connect', res)
  client.once('connectError', reject)
  client.once('setupError', reject)
  client.once('end', reject)
  client.once('socketTimeout', reject)
  client.once('connectTimeout', reject)
  client.once('error', reject)
})

// const bind = (client, dn, pwd) => new Promise((resolve, reject) => {
//   client.bind(dn, pwd, err => {
//     if (err) {
//       reject(err)
//     } else {
//       resolve()
//     }
//   })
// })
//
// const unbind = client => new Promise((resolve, reject) => {
//   client.unbind(err => {
//     if (err) {
//       reject(err)
//     } else {
//       resolve()
//     }
//   })
// })
//
// const search = (client, dn, options) => new Promise((resolve, reject) => {
//   client.search(dn, options, (err, response) => {
//     if (err) {
//       return reject(err)
//     }
//
//     let payload = null
//
//     response.on('searchEntry', (entry) => {
//       payload = entry.object
//     })
//
//     response.on('error', error => {
//       reject(error)
//     })
//
//     response.on('end', result => {
//       resolve(payload)
//     })
//   })
// })

async function authenticate(usr, pwd, cb) {
  let payload = null

  LOGGER.info(`Attempt to authenticate user '${usr}'`)

  let client = null
  try {
    client = await getClient(CONFIG.client.options)
  } catch (err) {
    LOGGER.error(`Failed to connect to LDAP server (see exceptions log for more details)`)
    process.emit('uncaughtException', err)

    LOGGER.info(`Authentication ended unsuccessfully`)
    cb(err)

    return
  }

  LOGGER.debug(`Binding to LDAP server...`)

  const bindDn = CONFIG.bind.dn.replace('$USER', usr)
  LOGGER.silly(`Bind DN: "${bindDn}"`)

  client.bind(bindDn, pwd, err => {
    if (err) {
      LOGGER.error(`Failed to authenticate user '${usr}' (see exceptions log for more details)`)
      process.emit('uncaughtException', err)

      LOGGER.debug(`Unbinding from LDAP server...`)
      client.unbind(unbindErr => {
        if (unbindErr) {
          LOGGER.error(`Failed to unbind (see exceptions log for more details)`)
          process.emit('uncaughtException', unbindErr)
        }

        LOGGER.info(`Authentication ended unsuccessfully`)
        cb(err)
      })

      return
    }

    LOGGER.debug(`Bind success for user '${usr}'`)

    LOGGER.debug(`Searching for '${usr}' user data...`)

    const searchDn = CONFIG.search.dn.replace('$USER', usr)
    LOGGER.silly(`Search DN: "${searchDn}"`)

    const searchOpt = Object.assign({}, CONFIG.search.options)
    searchOpt.filter = searchOpt.filter.replace('$USER', usr)
    LOGGER.silly(`Search options: ${JSON.stringify(searchOpt)}`)

    client.search(searchDn, searchOpt, (err, res) => {
      if (err) {
        LOGGER.error(`Failed to search (see exceptions log for more details)`)
        process.emit('uncaughtException', err)

        LOGGER.debug(`Unbinding from LDAP server...`)
        client.unbind(unbindErr => {
          if (unbindErr) {
            LOGGER.error(`Failed to unbind (see exceptions log for more details)`)
            process.emit('uncaughtException', unbindErr)
          }

          LOGGER.warn(`Authentication ended successfully but with no results for user '${usr}'`)
          cb(undefined)
        })

        return
      }

      res.on('searchEntry', (entry) => {
        LOGGER.debug(`Search returned entry for user '${usr}'`)

        // Fulfill payload
        payload = entry.object
      })

      res.on('error', (error) => {
        LOGGER.error(`Search returned error for user '${usr}' (see exceptions log for more details)`)
        process.emit('uncaughtException', error)

        LOGGER.debug(`Unbinding from LDAP server...`)
        client.unbind(unbindErr => {
          if (unbindErr) {
            LOGGER.error(`Failed to unbind (see exceptions log for more details)`)
            process.emit('uncaughtException', unbindErr)
          }

          LOGGER.warn(`Authentication ended successfully but with no results for user '${usr}'`)
          cb(undefined)
        })
      })

      res.on('end', (result) => {
        LOGGER.debug(`Search returned result status ${result.status} for user '${usr}'`)

        LOGGER.debug(`Unbinding from LDAP server...`)
        client.unbind(unbindErr => {
          if (unbindErr) {
            LOGGER.error(`Failed to unbind (see exceptions log for more details)`)
            process.emit('uncaughtException', unbindErr)
          }

          if (payload) {
            LOGGER.info(`Authentication ended successfully for user '${usr}'`)
          } else {
            LOGGER.warn(`Authentication ended successfully but with no results for user '${usr}'`)
          }
          cb(undefined, payload)
        })
      })
    })
  })
}

module.exports = promisify(authenticate)
