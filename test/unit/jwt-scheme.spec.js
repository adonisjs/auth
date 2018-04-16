'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

require('@adonisjs/lucid/lib/iocResolver').setFold(require('@adonisjs/fold'))

const test = require('japa')
const { ioc } = require('@adonisjs/fold')
const jwtLib = require('jsonwebtoken')

const { jwt: Jwt } = require('../../src/Schemes')
const { lucid: LucidSerializer, database: DatabaseSerializer } = require('../../src/Serializers')
const helpers = require('./helpers')
const setup = require('./setup')
const SECRET = 'averylongsecretkey'

const Encryption = {
  encrypt (token) {
    return `e${token}`
  },

  decrypt (token) {
    return token.replace(/^e/, '')
  }
}

const verifyToken = function (token, options) {
  return new Promise((resolve, reject) => {
    return jwtLib.verify(token, SECRET, options, (error, payload) => {
      if (error) {
        reject(error)
      } else {
        resolve(payload)
      }
    })
  })
}

const generateToken = function (payload, options) {
  return new Promise((resolve, reject) => {
    return jwtLib.sign(payload, SECRET, options, (error, token) => {
      if (error) {
        reject(error)
      } else {
        resolve(token)
      }
    })
  })
}

test.group('Schemes - Jwt', (group) => {
  setup.databaseHook(group)
  setup.hashHook(group)

  test('throw exception when unable to validate credentials', async (assert) => {
    assert.plan(1)

    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      scheme: 'jwt'
    }

    const lucid = new LucidSerializer()
    lucid.setConfig(config)

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)

    try {
      await jwt.validate('foo@bar.com', 'secret')
    } catch ({ message }) {
      assert.equal(message, 'E_USER_NOT_FOUND: Cannot find user with email as foo@bar.com')
    }
  })

  test('throw exception when password mismatches', async (assert) => {
    assert.plan(1)

    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      scheme: 'jwt'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)

    try {
      await jwt.validate('foo@bar.com', 'supersecret')
    } catch ({ message }) {
      assert.equal(message, 'E_PASSWORD_MISMATCH: Cannot verify user password')
    }
  })

  test('return true when able to validate credentials', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    const validated = await jwt.validate('foo@bar.com', 'secret')
    assert.isTrue(validated)
  })

  test('generate token for user', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    const tokenPayload = await jwt.generate(user)
    const payload = await verifyToken(tokenPayload.token)

    assert.property(tokenPayload, 'token')
    assert.isNull(tokenPayload.refreshToken)
    assert.equal(tokenPayload.type, 'bearer')
    assert.equal(payload.uid, 1)
  })

  test('generate token for user and attach user to it', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    const { token } = await jwt.generate(user, true)
    const payload = await verifyToken(token)

    assert.equal(payload.uid, 1)
    assert.equal(payload.data.id, 1)
    assert.equal(payload.data.email, 'foo@bar.com')
    assert.isUndefined(payload.data.password)
  })

  test('generate token for user and attach custom data to it', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    const { token } = await jwt.generate(user, { isAdmin: true })
    const payload = await verifyToken(token)

    assert.equal(payload.uid, 1)
    assert.equal(payload.data.isAdmin, true)
  })

  test('set jwt options', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET,
        issuer: 'adonisjs'
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    const { token } = await jwt.generate(user)
    const payload = await verifyToken(token)

    assert.equal(payload.iss, 'adonisjs')
  })

  test('generate jwt token with refresh token', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET,
        issuer: 'adonisjs'
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    const { refreshToken } = await jwt.withRefreshToken().generate(user)
    assert.isDefined(refreshToken)
    const userTokens = await user.tokens().fetch()
    assert.equal(userTokens.size(), 1)
    assert.equal(`e${userTokens.first().token}`, refreshToken)
    assert.equal(userTokens.first().is_revoked, 0)
    assert.equal(userTokens.first().type, 'jwt_refresh_token')
  })

  test('verify user token from header', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })
    const token = await generateToken({ uid: 1 })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    jwt.setCtx({
      request: {
        header (key) {
          return `Bearer ${token}`
        }
      }
    })

    const isLoggedIn = await jwt.check()
    assert.isTrue(isLoggedIn)
    assert.instanceOf(jwt.user, User)
    assert.equal(jwt.jwtPayload.uid, jwt.user.id)
  })

  test('throw exception when jwt token is invalid', async (assert) => {
    assert.plan(2)
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    jwt.setCtx({
      request: {
        header (key) {
          return 'Bearer 20'
        }
      }
    })

    try {
      await jwt.check()
    } catch ({ name, message }) {
      assert.equal(message, 'E_INVALID_JWT_TOKEN: jwt malformed')
      assert.equal(name, 'InvalidJwtToken')
    }
  })

  test('throw exception when user doesn\'t exist', async (assert) => {
    assert.plan(2)
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)
    const token = await generateToken({ uid: 1 })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    jwt.setCtx({
      request: {
        header (key) {
          return `Bearer ${token}`
        }
      }
    })

    try {
      await jwt.check()
    } catch ({ name, message }) {
      assert.equal(message, 'E_INVALID_JWT_TOKEN: The Jwt token is invalid')
      assert.equal(name, 'InvalidJwtToken')
    }
  })

  test('throw exception when options mismatches', async (assert) => {
    assert.plan(2)
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET,
        issuer: 'adonisjs'
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })
    const token = await generateToken({ uid: 1 })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    jwt.setCtx({
      request: {
        header (key) {
          return `Bearer ${token}`
        }
      }
    })

    try {
      await jwt.check()
    } catch ({ name, message }) {
      assert.equal(message, 'E_INVALID_JWT_TOKEN: jwt issuer invalid. expected: adonisjs')
      assert.equal(name, 'InvalidJwtToken')
    }
  })

  test('throw exception when token has been expired', async (assert) => {
    assert.plan(2)
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })
    const token = await generateToken({ uid: 1 }, { expiresIn: 1 })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    jwt.setCtx({
      request: {
        header (key) {
          return `Bearer ${token}`
        }
      }
    })

    await helpers.sleep(1000)
    try {
      await jwt.check()
    } catch ({ name, message }) {
      assert.equal(message, 'E_JWT_TOKEN_EXPIRED: The jwt token has been expired. Generate a new one to continue')
      assert.equal(name, 'ExpiredJwtToken')
    }
  }).timeout(0)

  test('return user when token is correct', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })
    const token = await generateToken({ uid: 1 })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    jwt.setCtx({
      request: {
        header (key) {
          return `Bearer ${token}`
        }
      }
    })

    const user = await jwt.getUser()
    assert.instanceOf(user, User)
  })

  test('find user for a refresh token', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    await user.tokens().create({ token: '20', is_revoked: false, type: 'jwt_refresh_token' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)

    const { token } = await jwt.generateForRefreshToken('20', false, { expiresIn: '1m' })
    assert.isDefined(token)

    const payload = await verifyToken(token)
    assert.equal(payload.uid, 1)
    assert.isDefined(payload.exp)
    const firstToken = await user.tokens().where('token', '20').first()
    assert.equal(firstToken.is_revoked, 0)
  })

  test('on generating token with refreshToken remove the old one', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    await user.tokens().create({ token: '20', is_revoked: false, type: 'jwt_refresh_token' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)

    const { token, refreshToken } = await jwt.newRefreshToken().generateForRefreshToken('20')
    assert.isDefined(token)

    const payload = await verifyToken(token)
    assert.equal(payload.uid, 1)
    assert.notEqual(refreshToken, '20')
    const firstToken = await user.tokens().where('token', '20').first()
    assert.isNull(firstToken)
  })

  test('generate token using credentials', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)

    const { token, refreshToken } = await jwt.attempt('foo@bar.com', 'secret')
    assert.isDefined(token)

    const payload = await verifyToken(token)
    assert.equal(payload.uid, 1)
    assert.notEqual(refreshToken, '20')
  })

  test('throw exception when user is not found for a refreshToken', async (assert) => {
    assert.plan(2)
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)

    try {
      await jwt.generateForRefreshToken('20')
    } catch ({ name, message }) {
      assert.equal(name, 'InvalidRefreshToken')
      assert.equal(message, 'E_INVALID_JWT_REFRESH_TOKEN: Invalid refresh token 20')
    }
  })

  test('throw exception when jwtSecret is missing', async (assert) => {
    assert.plan(2)
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {}
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)

    try {
      await jwt.generate({})
    } catch ({ name, message }) {
      assert.equal(name, 'RuntimeException')
      assert.match(message, /^E_INCOMPLETE_CONFIG: Make sure to define secret on jwt inside config\/auth.js/)
    }
  })

  test('throw exception when user doesn\'t have an id', async (assert) => {
    assert.plan(2)
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: 'SECRET'
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)

    try {
      await jwt.generate({})
    } catch ({ name, message }) {
      assert.equal(name, 'RuntimeException')
      assert.match(message, /^E_RUNTIME_ERROR: Primary key value is missing for user/)
    }
  })

  test('calling check twice should return true', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })
    const token = await generateToken({ uid: 1 })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    jwt.setCtx({
      request: {
        header (key) {
          return `Bearer ${token}`
        }
      }
    })

    await jwt.check()
    jwt._verifyToken = function () {
      throw new Error('Unexpected call')
    }
    await jwt.check()
  })

  test('read token from request input', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })
    const token = await generateToken({ uid: 1 }, { expiresIn: 1 })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    jwt.setCtx({
      request: {
        header () {
          return null
        },
        input () {
          return token
        }
      }
    })

    const isLogged = await jwt.check()
    assert.isTrue(isLogged)
  })

  test('parse token only when token is bearer type', async (assert) => {
    assert.plan(1)
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })
    const token = await generateToken({ uid: 1 }, { expiresIn: 1 })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    jwt.setCtx({
      request: {
        header () {
          return token
        }
      }
    })

    try {
      await jwt.check()
    } catch ({ message }) {
      assert.equal(message, 'E_INVALID_JWT_TOKEN: jwt must be provided')
    }
  })

  test('pass runtime options to generate token', async (assert) => {
    assert.plan(1)
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)

    const { token } = await jwt.generate(user, {}, { issuer: 'adonisjs' })
    const { iss } = await verifyToken(token)
    assert.equal(iss, 'adonisjs')
  })

  test('throw exception when calling login()', async (assert) => {
    assert.plan(1)
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      scheme: 'jwt',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)

    try {
      jwt.login(user)
    } catch ({ message }) {
      assert.match(message, /^E_INVALID_METHOD: login method is not implemented by jwt scheme/)
    }
  })

  test('list refresh tokens', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)

    const payload = await jwt.withRefreshToken().generate(user)
    const tokensList = await jwt.listTokensForUser(user)
    assert.equal(tokensList.length, 1)
    assert.equal(tokensList[0].token, payload.refreshToken)
  })

  test('return empty array when tokens doesn\'t exists', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)

    const tokensList = await jwt.listTokens(user)
    assert.lengthOf(tokensList, 0)
  })

  test('return empty array when user has not been defined', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    await jwt.withRefreshToken().generate(user)

    const tokensList = await jwt.listTokens()
    assert.lengthOf(tokensList, 0)
  })

  test('return encrypted tokens via database serializer', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      primaryKey: 'id',
      table: 'users',
      tokensTable: 'tokens',
      uid: 'email',
      foreignKey: 'user_id',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const database = new DatabaseSerializer(ioc.use('Hash'))
    database.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, database)
    const payload = await jwt.withRefreshToken().generate(user)

    const tokensList = await jwt.listTokensForUser({ id: 1 }, 'jwt_refresh_token')
    assert.deepEqual(tokensList[0].token, payload.refreshToken)
  })

  test('login as client', async (assert) => {
    assert.plan(2)

    const config = {
      primaryKey: 'id',
      table: 'users',
      tokensTable: 'tokens',
      uid: 'email',
      foreignKey: 'user_id',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const database = new DatabaseSerializer(ioc.use('Hash'))
    database.setConfig(config)

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, database)

    const headerFn = function (key, value) {
      assert.equal(key, 'authorization')
      assert.include(value, 'Bearer')
    }

    await jwt.clientLogin(headerFn, null, { id: 1 })
  })

  test('revoke tokens for a given user', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    await user.tokens().create({ type: 'jwt_refresh_token', token: '22', is_revoked: false })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)
    await jwt.revokeTokensForUser(user, ['22'])

    const token = await user.tokens().first()
    assert.equal(token.is_revoked, true)
    assert.equal(token.token, '22')
  })

  test('revoke all tokens for the current user', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)

    const payload = await jwt.withRefreshToken().generate(user)

    jwt.setCtx({
      request: {
        header (key) {
          return `Bearer ${payload.token}`
        }
      }
    })

    await jwt.check()
    await jwt.revokeTokens()

    const token = await user.tokens().first()
    assert.equal(token.is_revoked, true)
    assert.equal(`e${token.token}`, payload.refreshToken)
  })

  test('delete tokens instead of revoking it', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      options: {
        secret: SECRET
      }
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })

    const jwt = new Jwt(Encryption)
    jwt.setOptions(config, lucid)

    const payload = await jwt.generate(user)

    jwt.setCtx({
      request: {
        header (key) {
          return `Bearer ${payload.token}`
        }
      }
    })

    await jwt.check()
    await jwt.revokeTokens(null, true)

    const token = await user.tokens().first()
    assert.isNull(token)
  })
})
