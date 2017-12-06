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

const { token: Token } = require('../../src/Schemes')
const { lucid: LucidSerializer } = require('../../src/Serializers')
const helpers = require('./helpers')
const setup = require('./setup')

const Encryption = {
  encrypt (v) {
    return v
  },

  decrypt (v) {
    return v
  }
}

test.group('Schemes - Token Api', (group) => {
  setup.databaseHook(group)
  setup.hashHook(group)

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

    const token = new Token(Encryption)
    token.setOptions(config, lucid)
    const tokenPayload = await token.generate(user)

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
    await user.tokens().create({ type: 'plain_token', token: '22', is_revoked: false })

    const token = new Token(Encryption)
    token.setOptions(config, lucid)
    token.setCtx({
      request: {
        header (key) {
          return `Bearer 22`
        }
      }
    })

    const isLoggedIn = await token.check()
    assert.isTrue(isLoggedIn)
    assert.instanceOf(token.user, User)
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

    const token = new Token(Encryption)
    token.setOptions(config, lucid)
    token.setCtx({
      request: {
        header (key) {
          return `Bearer 22`
        }
      }
    })

    try {
      await token.check()
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
    await user.tokens().create({ type: 'plain_token', token: 22, is_revoked: false })

    const token = new Token(Encryption)
    token.setOptions(config, lucid)
    token.setCtx({
      request: {
        header (key) {
          return `Bearer 22`
        }
      }
    })

    const fetchedUser = await token.getUser()
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
    await user.tokens().create({ type: 'plain_token', token: 22, is_revoked: false })

    const token = new Token(Encryption)
    token.setOptions(config, lucid)
    token.setCtx({
      request: {
        header () {
          return null
        },
        input () {
          return '22'
        }
      }
    })

    const isLogged = await token.check()
    assert.isTrue(isLogged)
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

    const token = new Token(Encryption)
    token.setOptions(config, lucid)
    const tokenPayload = await token.attempt('foo@bar.com', 'secret')

    assert.isDefined(tokenPayload.token)
    assert.equal(tokenPayload.type, 'bearer')
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
    const token = new Token(Encryption)
    token.setOptions(config, lucid)
    const payload = await token.generate(user)
    const tokensList = await token.listTokens(user)
    assert.equal(tokensList.size(), 1)
    assert.equal(tokensList.first().token, payload.token)
  })
})
