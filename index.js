const http = require('http')
const auth = require('./auth')

const parseIp = (req) =>
    req.headers['x-forwarded-for']?.split(',').shift()
    || req.socket?.remoteAddress

const handler = async (req, res) => {
  if (!req.headers.authorization) {
    res.setHeader('WWW-Authenticate', 'Basic realm="User Visible Realm"')
    res.writeHead(401)
    return res.end('Missing Authorization header')
  }

  const [ scheme, credentials ] = req.headers.authorization.split(' ')
  if (scheme.toLowerCase() !== 'basic') {
    res.setHeader('WWW-Authenticate', 'Basic realm="User Visible Realm"')
    res.writeHead(401)
    return res.end('Only Basic authentication is supported')
  }

  const [ usr, pwd ] = Buffer.from(credentials, 'base64').toString('ascii').split(':')
  try {
    const userData = await auth(usr, pwd)
    res.writeHead(userData ? 200 : 204)
    return res.end(JSON.stringify(userData))
  } catch (e) {
    if (e.name === 'InvalidCredentialsError') {
      res.writeHead(401)
      return res.end('Invalid credentials')
    }
    res.writeHead(500)
    return res.end()
  }
}

const server = http.createServer(handler)
server.listen(3000)
