'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const { ioc } = require('@adonisjs/fold')
const test = require('japa')
const Macroable = require('macroable')
const Binding = require('../../src/VowBindings/Request')
const setup = require('./setup')
const groupSetup = require('../unit/setup')

class Request extends Macroable {
  static before (fn) {
    this._hooks.push(fn)
  }
}

Request._macros = {}
Request._getters = {}
Request._hooks = []

test.group('Vow Request', (group) => {
  groupSetup.hashHook(group)

  group.before(async () => {
    await setup()
    Binding(Request, ioc.use('Adonis/Src/Config'))
  })

  test('add login via macro', (assert) => {
    const request = new Request()
    assert.isFunction(request.loginVia)
  })

  test('set login authenticator as empty string when undefined', (assert) => {
    const request = new Request()
    request.loginVia({})
    assert.deepEqual(request._loginArgs, { authenticator: '', options: [{}] })
  })

  test('set before hook', (assert) => {
    assert.lengthOf(Request._hooks, 1)
  })

  test('set session when hook is executed', async (assert) => {
    assert.plan(2)

    const request = new Request()
    request.session = function (key, value) {
      assert.equal(key, 'adonis-auth')
      assert.equal(value, 1)
    }
    request.header = function () {}

    request.loginVia({ id: 1 })
    await Request._hooks[0](request)
  })

  test('set basic auth header when hook is executed', async (assert) => {
    assert.plan(2)

    const request = new Request()
    request.header = function (key, value) {
      assert.equal(key, 'authorization')
      assert.equal(value, `Basic ${Buffer.from('foo:bar').toString('base64')}`)
    }
    request.session = function () {}

    request.loginVia('foo', 'bar', 'basic')
    await Request._hooks[0](request)
  })

  test('set jwt token when hook is executed', async (assert) => {
    assert.plan(2)

    const request = new Request()
    request.header = function (key, value) {
      assert.equal(key, 'authorization')
      assert.include(value, 'Bearer')
    }
    request.session = function () {}

    request.loginVia({ id: 1 }, 'jwt')
    await Request._hooks[0](request)
  })

  test('skip authentication when loginVia was never called', async (assert) => {
    assert.plan(0)

    const request = new Request()
    request.header = function () {}
    request.session = function () {}
    await Request._hooks[0](request)
  })

  test('throw exception when authenticator is invalid', async (assert) => {
    assert.plan(1)

    const request = new Request()
    request.header = function () {}
    request.session = function () {}
    request.loginVia({ id: 1 }, 'foo')

    try {
      await Request._hooks[0](request)
    } catch ({ message }) {
      assert.equal(message, 'E_MISSING_CONFIG: auth.foo is not defined inside config/auth.js file')
    }
  })
})
