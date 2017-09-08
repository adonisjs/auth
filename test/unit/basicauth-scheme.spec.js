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
const Model = require('@adonisjs/lucid/src/Lucid/Model')

const { basic: BasicAuth } = require('../../src/Schemes')
const { lucid: LucidSerializer } = require('../../src/Serializers')
const setup = require('./setup')

test.group('Schemes - BasicAuth', (group) => {
  setup.databaseHook(group)
  setup.hashHook(group)

  test('throw exception when unable to validate credentials', async (assert) => {
    assert.plan(1)

    class User extends Model {
      static get makePlain () {
        return true
      }
    }
    User._bootIfNotBooted()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer()
    lucid.setConfig(config)

    const basic = new BasicAuth()
    basic.setOptions(config, lucid)

    try {
      await basic.validate('foo@bar.com', 'secret')
    } catch ({ message }) {
      assert.equal(message, 'E_USER_NOT_FOUND: Cannot find user with email as foo@bar.com')
    }
  })

  test('throw exception when password mismatches', async (assert) => {
    assert.plan(1)

    class User extends Model {
      static get makePlain () {
        return true
      }
    }
    User._bootIfNotBooted()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })

    const basic = new BasicAuth()
    basic.setOptions(config, lucid)

    try {
      await basic.validate('foo@bar.com', 'supersecret')
    } catch ({ message }) {
      assert.equal(message, 'E_PASSWORD_MISMATCH: Cannot verify user password')
    }
  })

  test('return true when able to validate credentials', async (assert) => {
    class User extends Model {
      static get makePlain () {
        return true
      }
    }
    User._bootIfNotBooted()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })

    const basic = new BasicAuth()
    basic.setOptions(config, lucid)
    const validated = await basic.validate('foo@bar.com', 'secret')
    assert.isTrue(validated)
  })

  test('valid user credentials via request headers', async (assert) => {
    class User extends Model {
      static get makePlain () {
        return true
      }
    }
    User._bootIfNotBooted()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })

    const basic = new BasicAuth()
    basic.setOptions(config, lucid)
    basic.setCtx({ request: {
      request: {
        headers: {
          authorization: `Basic ${Buffer.from('foo@bar.com:secret').toString('base64')}`
        }
      }
    } })

    const isLogged = await basic.check()
    assert.isTrue(isLogged)
  })

  test('throw exception when unable to verify user credentials', async (assert) => {
    assert.plan(2)

    class User extends Model {
      static get makePlain () {
        return true
      }
    }
    User._bootIfNotBooted()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })

    const basic = new BasicAuth()
    basic.setOptions(config, lucid)
    basic.setCtx({ request: {
      request: {
        headers: {
          authorization: `Basic ${Buffer.from('foo@bar.com:supersecret').toString('base64')}`
        }
      }
    } })

    try {
      await basic.check()
    } catch ({ message, name }) {
      assert.equal(message, 'E_PASSWORD_MISMATCH: Cannot verify user password')
      assert.equal(name, 'PasswordMisMatchException')
    }
  })

  test('return user via getUser', async (assert) => {
    class User extends Model {
      static get makePlain () {
        return true
      }
    }
    User._bootIfNotBooted()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    await User.create({ email: 'foo@bar.com', password: 'secret' })

    const basic = new BasicAuth()
    basic.setOptions(config, lucid)
    basic.setCtx({ request: {
      request: {
        headers: {
          authorization: `Basic ${Buffer.from('foo@bar.com:secret').toString('base64')}`
        }
      }
    } })

    const user = await basic.getUser()
    assert.instanceOf(user, User)
  })

  test('login as client', async (assert) => {
    assert.plan(2)

    class User extends Model {
      static get makePlain () {
        return true
      }
    }
    User._bootIfNotBooted()

    const config = {
      model: User,
      uid: 'email',
      password: 'password'
    }

    const lucid = new LucidSerializer(ioc.use('Hash'))
    lucid.setConfig(config)

    const basic = new BasicAuth()
    basic.setOptions(config, lucid)

    const headerFn = function (key, value) {
      assert.equal(key, 'authorization')
      assert.equal(value, `Basic ${Buffer.from('foo:secret').toString('base64')}`)
    }

    await basic.clientLogin(headerFn, null, 'foo', 'secret')
  })
})
