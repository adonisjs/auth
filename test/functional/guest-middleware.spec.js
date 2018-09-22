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

test.group('Middleware | Guest', (group) => {
  groupSetup.databaseHook(group)
  groupSetup.hashHook(group)

  group.before(async () => {
    await setup()
  })

  group.beforeEach(() => {
    this.server = http.createServer()
  })

  test('throw exception when trying to reach a guest route and user is logged in', async (assert) => {
    await ioc.use('App/Models/User').create({ email: 'foo@bar.com', password: 'secret' })

    this.server.on('request', (req, res) => {
      const Context = ioc.use('Adonis/Src/HttpContext')

      const ctx = new Context()
      ctx.request = helpers.getRequest(req)
      ctx.response = helpers.getResponse(req, res)
      ctx.session = helpers.getSession(req, res)

      const guestMiddleware = ioc.use('Adonis/Middleware/AllowGuestOnly')

      guestMiddleware
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

    const { text } = await supertest(this.server).get('/').set('Cookie', 'adonis-auth=1').expect(403)
    assert.equal(text, `E_GUEST_ONLY: Only guest user can access the route GET /`)
  })
})
