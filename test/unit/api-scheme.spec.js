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
    assert.plan(1)

    const User = helpers.getUserModel()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer()
    lucid.setConfig(config)

    const api = new Api(Encryption)
    api.setOptions(config, lucid)

    try {
      await api.validate('foo@bar.com', 'secret')
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
      password: 'password'
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
    const tokensList = await api.listTokens(user)
    assert.equal(tokensList.size(), 1)
    assert.equal(tokensList.first().token, payload.token)
  })

  test('return fake response when no tokens exists', async (assert) => {
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
    const tokensList = await api.listTokens(user)
    assert.equal(tokensList.size(), 0)
  })

  test('return fake response when user is not defined', async (assert) => {
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
    const tokensList = await api.listTokens()
    assert.equal(tokensList.size(), 0)
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
    const tokensList = await api.listTokens(user)
    assert.lengthOf(tokensList, 1)
    assert.equal(tokensList[0].token, payload.token)
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
})
