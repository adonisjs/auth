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

const { api: Api } = require('../../src/Schemes')
const { lucid: LucidSerializer, database: DatabaseSerializer } = require('../../src/Serializers')
const helpers = require('./helpers')
const setup = require('./setup')

const Encryption = {
  encrypt (token) {
    return `e${token}`
  },

  decrypt (token) {
    return token.replace(/^e/, '')
  }
}

test.group('Schemes - Api', (group) => {
  setup.databaseHook(group)
  setup.hashHook(group)

  test('throw exception when unable to validate credentials', async (assert) => {
    assert.plan(2)

    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      scheme: 'api'
    }

    const lucid = new LucidSerializer()
    lucid.setConfig(config)

    const api = new Api(Encryption)
    api.setOptions(config, lucid)

    try {
      await api.validate('foo@bar.com', 'secret')
    } catch ({ message, uidField, password }) {
      assert.equal(message, 'E_USER_NOT_FOUND: Cannot find user with email as foo@bar.com')
      assert.equal(uidField, 'email')
    }
  })

  test('throw exception when password mismatches', async (assert) => {
    assert.plan(1)

    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      scheme: 'api'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })

    const api = new Api(Encryption)
    api.setOptions(config, lucid)

    try {
      await api.validate('foo@bar.com', 'supersecret')
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

    const api = new Api(Encryption)
    api.setOptions(config, lucid)
    const validated = await api.validate('foo@bar.com', 'secret')
    assert.isTrue(validated)
  })

  test('throw exception when user doesn\'t have an id', async (assert) => {
    assert.plan(2)
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const api = new Api(Encryption)
    api.setOptions(config, lucid)

    try {
      await api.generate({})
    } catch ({ name, message }) {
      assert.equal(name, 'RuntimeException')
      assert.match(message, /^E_RUNTIME_ERROR: Primary key value is missing for user/)
    }
  })

  test('generate token for user', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })

    const api = new Api(Encryption)
    api.setOptions(config, lucid)
    const tokenPayload = await api.generate(user)

    assert.isDefined(tokenPayload.token)
    assert.equal(tokenPayload.type, 'bearer')
  })

  test('verify user token from header', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    await user.tokens().create({ type: 'api_token', token: '22', is_revoked: false })

    const api = new Api(Encryption)
    api.setOptions(config, lucid)
    api.setCtx({
      request: {
        header (key) {
          return `Bearer e22`
        }
      }
    })

    const isLoggedIn = await api.check()
    assert.isTrue(isLoggedIn)
    assert.instanceOf(api.user, User)
  })

  test('throw exception when api token is invalid', async (assert) => {
    assert.plan(2)
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })

    const api = new Api(Encryption)
    api.setOptions(config, lucid)
    api.setCtx({
      request: {
        header (key) {
          return `Bearer 22`
        }
      }
    })

    try {
      await api.check()
    } catch ({ name, message }) {
      assert.equal(message, 'E_INVALID_API_TOKEN: The api token is missing or invalid')
      assert.equal(name, 'InvalidApiToken')
    }
  })

  test('return user when token is correct', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    await user.tokens().create({ type: 'api_token', token: 22, is_revoked: false })

    const api = new Api(Encryption)
    api.setOptions(config, lucid)
    api.setCtx({
      request: {
        header (key) {
          return `Bearer 22`
        }
      }
    })

    const fetchedUser = await api.getUser()
    assert.instanceOf(fetchedUser, User)
  })

  test('read token from request input', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    await user.tokens().create({ type: 'api_token', token: 22, is_revoked: false })

    const api = new Api(Encryption)
    api.setOptions(config, lucid)
    api.setCtx({
      request: {
        header () {
          return null
        },
        input () {
          return '22'
        }
      }
    })

    const isLogged = await api.check()
    assert.isTrue(isLogged)
  })

  test('throw exception when token is missing', async (assert) => {
    assert.plan(3)
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    await user.tokens().create({ type: 'api_token', token: 22, is_revoked: false })

    const api = new Api(Encryption)
    api.setOptions(config, lucid)
    api.setCtx({
      request: {
        header () {
          return null
        },
        input () {
          return null
        }
      }
    })

    try {
      await api.check()
    } catch ({ name, message, status }) {
      assert.equal(name, 'InvalidApiToken')
      assert.equal(message, 'E_INVALID_API_TOKEN: The api token is missing or invalid')
      assert.equal(status, 401)
    }
  })

  test('return a list of tokens for a given user', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    const api = new Api(Encryption)
    api.setOptions(config, lucid)
    const payload = await api.generate(user)
    const tokensList = await api.listTokensForUser(user)

    assert.lengthOf(tokensList, 1)
    assert.equal(tokensList[0].token, payload.token)
  })

  test('return empty array when no tokens exists', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    const api = new Api(Encryption)
    api.setOptions(config, lucid)
    const tokensList = await api.listTokensForUser(user)
    assert.lengthOf(tokensList, 0)
  })

  test('return empty array when user is not defined', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    const api = new Api(Encryption)
    api.setOptions(config, lucid)
    await api.generate(user)
    const tokensList = await api.listTokensForUser()
    assert.lengthOf(tokensList, 0)
  })

  test('return a list of tokens via database serializer', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      primaryKey: 'id',
      table: 'users',
      tokensTable: 'tokens',
      uid: 'email',
      foreignKey: 'user_id',
      password: 'password'
    }

    const database = new DatabaseSerializer(ioc.use('Hash'))
    database.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    const api = new Api(Encryption)
    api.setOptions(config, database)
    const payload = await api.generate(user)
    const tokensList = await api.listTokensForUser(user)
    assert.lengthOf(tokensList, 1)
    assert.equal(tokensList[0].token, payload.token)
  })

  test('return a list of tokens for currently logged in user', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      primaryKey: 'id',
      table: 'users',
      tokensTable: 'tokens',
      uid: 'email',
      foreignKey: 'user_id',
      password: 'password'
    }

    const database = new DatabaseSerializer(ioc.use('Hash'))
    database.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    await user.tokens().create({ token: '22', type: 'api_token', is_revoked: false })

    const api = new Api(Encryption)

    api.setOptions(config, database)
    api.setCtx({
      request: {
        header () {
          return null
        },
        input () {
          return Encryption.encrypt('22')
        }
      }
    })

    await api.check()

    const tokensList = await api.listTokens()
    assert.lengthOf(tokensList, 1)
  })

  test('generate token via user credentials', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })

    const api = new Api(Encryption)
    api.setOptions(config, lucid)
    const tokenPayload = await api.attempt('foo@bar.com', 'secret')

    assert.isDefined(tokenPayload.token)
    assert.equal(tokenPayload.type, 'bearer')
  })

  test('login as client', async (assert) => {
    assert.plan(2)
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password',
      headerKey: 'api'
    }

    const database = new DatabaseSerializer(ioc.use('Hash'))
    database.setConfig(config)

    const api = new Api(Encryption)
    api.setOptions(config, database)

    const headerFn = function (key, value) {
      assert.equal(key, config.headerKey)
      assert.include(value, 'Bearer')
    }

    await api.clientLogin(headerFn, null, '1')
  })

  test('revoke tokens for a given user', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    await user.tokens().create({ type: 'api_token', token: '22', is_revoked: false })

    const api = new Api(Encryption)
    api.setOptions(config, lucid)
    await api.revokeTokensForUser(user, ['22'])

    const token = await user.tokens().first()
    assert.equal(token.is_revoked, true)
    assert.equal(token.token, '22')
  })

  test('revoke all tokens for the current user', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })

    const api = new Api(Encryption)
    api.setOptions(config, lucid)

    const payload = await api.generate(user)

    api.setCtx({
      request: {
        header (key) {
          return `Bearer ${payload.token}`
        }
      }
    })

    await api.check()
    await api.revokeTokens()

    const token = await user.tokens().first()
    assert.equal(token.is_revoked, true)
    assert.equal(`e${token.token}`, payload.token)
  })

  test('delete tokens instead of revoking it', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })

    const api = new Api(Encryption)
    api.setOptions(config, lucid)

    const payload = await api.generate(user)

    api.setCtx({
      request: {
        header (key) {
          return `Bearer ${payload.token}`
        }
      }
    })

    await api.check()
    await api.revokeTokens(null, true)

    const token = await user.tokens().first()
    assert.isNull(token)
  })

  test('set user property when token exists', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    await user.tokens().create({ type: 'api_token', token: '22', is_revoked: false })

    const api = new Api(Encryption)
    api.setOptions(config, lucid)
    api.setCtx({
      request: {
        header (key) {
          return `Bearer e22`
        }
      }
    })

    const isLoggedIn = await api.loginIfCan()
    assert.isTrue(isLoggedIn)
    assert.instanceOf(api.user, User)
  })

  test('silently ignore when token header is missing', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    await user.tokens().create({ type: 'api_token', token: '22', is_revoked: false })

    const api = new Api(Encryption)
    api.setOptions(config, lucid)
    api.setCtx({
      request: {
        header (key) {
          return null
        },

        input () {
          return null
        }
      }
    })

    const isLoggedIn = await api.loginIfCan()
    assert.isFalse(isLoggedIn)
    assert.isNull(api.user, null)
  })

  test('silently ignore when token exists but is invalid', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    await user.tokens().create({ type: 'api_token', token: '22', is_revoked: false })

    const api = new Api(Encryption)
    api.setOptions(config, lucid)
    api.setCtx({
      request: {
        header (key) {
          return 'Bearer 40'
        }
      }
    })

    const isLoggedIn = await api.loginIfCan()
    assert.isFalse(isLoggedIn)
    assert.isNull(api.user, null)
  })

  test('verify user token from when type is token and not bearer', async (assert) => {
    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const user = await User.create({ email: 'foo@bar.com', password: 'secret' })
    await user.tokens().create({ type: 'api_token', token: '22', is_revoked: false })

    const api = new Api(Encryption)
    api.setOptions(config, lucid)
    api.setCtx({
      request: {
        header (key) {
          return `Token e22`
        }
      }
    })

    const isLoggedIn = await api.check()
    assert.isTrue(isLoggedIn)
    assert.instanceOf(api.user, User)
  })
})
