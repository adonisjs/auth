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
const supertest = require('supertest')
const http = require('http')
const setup = require('./setup')
const groupSetup = require('../unit/setup')
const helpers = require('../unit/helpers')

test.group('Middleware | Auth', (group) => {
  groupSetup.databaseHook(group)
  groupSetup.hashHook(group)

  group.before(async () => {
    await setup()
  })

  group.beforeEach(() => {
    this.server = http.createServer()
  })

  test('attempt to login when scheme is session but ignore silently', async (assert) => {
    let fnCalled = false

    this.server.on('request', (req, res) => {
      const Context = ioc.use('Adonis/Src/HttpContext')

      const ctx = new Context()
      ctx.request = helpers.getRequest(req)
      ctx.response = helpers.getResponse(req, res)
      ctx.session = helpers.getSession(req, res)

      ctx.auth.authenticator('session')
      ctx.auth._authenticatorsPool['session'].loginIfCan = function () {
        fnCalled = true
      }

      const authInit = ioc.use('Adonis/Middleware/AuthInit')

      authInit
        .handle(ctx, function () {})
        .then((status) => {
          res.writeHead(200)
          res.write('skipped')
          res.end()
        })
        .catch(({ status, message }) => {
          res.writeHead(status || 500)
          res.write(message)
          res.end()
        })
    })

    await supertest(this.server).get('/').expect(200)
    assert.isTrue(fnCalled)
  })

  test('throw exception when unable to login via default scheme', async (assert) => {
    this.server.on('request', (req, res) => {
      const Context = ioc.use('Adonis/Src/HttpContext')

      const ctx = new Context()
      ctx.request = helpers.getRequest(req)
      ctx.response = helpers.getResponse(req, res)
      ctx.session = helpers.getSession(req, res)

      const authMiddleware = ioc.use('Adonis/Middleware/Auth')

      authMiddleware
        .handle(ctx, function () {})
        .then((status) => {
          res.writeHead(200)
          res.write('skipped')
          res.end()
        })
        .catch(({ status, message }) => {
          res.writeHead(status || 500)
          res.write(message)
          res.end()
        })
    })

    const { text } = await supertest(this.server).get('/').expect(401)
    assert.equal(text, 'E_INVALID_SESSION: Invalid session')
  })

  test('set current property on auth when user is logged in', async (assert) => {
    await ioc.use('App/Models/User').create({ email: 'foo@bar.com', password: 'secret' })

    this.server.on('request', (req, res) => {
      const Context = ioc.use('Adonis/Src/HttpContext')

      const ctx = new Context()
      ctx.request = helpers.getRequest(req)
      ctx.response = helpers.getResponse(req, res)
      ctx.session = helpers.getSession(req, res)

      const authMiddleware = ioc.use('Adonis/Middleware/Auth')

      authMiddleware
        .handle(ctx, function () {})
        .then((status) => {
          res.writeHead(200)
          assert.deepEqual(ctx.auth.current, ctx.auth.authenticatorInstance)
          res.end()
        })
        .catch(({ status, message }) => {
          res.writeHead(status || 500)
          res.write(message)
          res.end()
        })
    })

    await supertest(this.server).get('/').set('Cookie', 'adonis-auth=1').expect(200)
  })

  test('throw exception when all of the schemes fails to login the user', async (assert) => {
    this.server.on('request', (req, res) => {
      const Context = ioc.use('Adonis/Src/HttpContext')

      const ctx = new Context()
      ctx.request = helpers.getRequest(req)
      ctx.response = helpers.getResponse(req, res)
      ctx.session = helpers.getSession(req, res)

      const authMiddleware = ioc.use('Adonis/Middleware/Auth')

      authMiddleware
        .handle(ctx, function () {}, ['basic', 'jwt'])
        .then((status) => {
          res.writeHead(200)
          res.end()
        })
        .catch(({ status, message }) => {
          res.writeHead(status || 500)
          res.write(message)
          res.end()
        })
    })

    const { text } = await supertest(this.server).get('/').expect(401)
    assert.equal(text, 'E_INVALID_JWT_TOKEN: jwt must be provided')
  })

  test('skip upcoming schemes when one authenticates a user', async (assert) => {
    await ioc.use('App/Models/User').create({ email: 'foo@bar.com', password: 'secret' })

    this.server.on('request', (req, res) => {
      const Context = ioc.use('Adonis/Src/HttpContext')

      const ctx = new Context()
      ctx.request = helpers.getRequest(req)
      ctx.response = helpers.getResponse(req, res)
      ctx.session = helpers.getSession(req, res)

      const authMiddleware = ioc.use('Adonis/Middleware/Auth')

      authMiddleware
        .handle(ctx, function () {}, ['basic', 'jwt'])
        .then((status) => {
          res.writeHead(200)
          assert.isDefined(ctx.auth.current)
          assert.equal(ctx.auth.current.scheme, 'basic')
          assert.notDeepEqual(ctx.auth.current, ctx.auth.authenticatorInstance)
          res.end()
        })
        .catch(({ status, message }) => {
          res.writeHead(status || 500)
          res.write(message)
          res.end()
        })
    })

    const userCredentials = Buffer.from('foo@bar.com:secret').toString('base64')
    await supertest(this.server).get('/').set('Authorization', `Basic ${userCredentials}`).expect(200)
  })
})
