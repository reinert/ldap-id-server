const { send } = require('micro')
const auth = require('./auth')

module.exports = async (req, res) => {
  if (!req.headers.authorization) {
    res.setHeader('WWW-Authenticate', 'Basic realm="User Visible Realm"')
    return send(res, 401, 'Missing Authorization header')
  }

  const [ type, credentials ] = req.headers.authorization.split(' ')
  if (type.toLowerCase() !== 'basic') {
    res.setHeader('WWW-Authenticate', 'Basic realm="User Visible Realm"')
    return send(res, 401, 'Only Basic authentication is supported')
  }

  const [ usr, pwd ] = Buffer.from(credentials, 'base64').toString('ascii').split(':')
  try {
    const userData = await auth(usr, pwd)
    send(res, userData ? 200 : 204, userData)
  } catch (e) {
    if (e.name === 'InvalidCredentialsError')
      return send(res, 401, 'Invalid credentials')
    send(res, 500)
  }
}
