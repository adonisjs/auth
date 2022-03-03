/*
 * @adonisjs/auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { DateTime } from 'luxon'
import supertest from 'supertest'
import { createServer } from 'http'
import { ApplicationContract } from '@ioc:Adonis/Core/Application'

import { OpaqueToken } from '../../src/Tokens/OpaqueToken'
import { ProviderToken } from '../../src/Tokens/ProviderToken'

import {
  setup,
  reset,
  cleanup,
  getUserModel,
  setupApplication,
  getLucidProvider,
  getApiTokensGuard,
  getTokensDbProvider,
  getLucidProviderConfig,
} from '../../test-helpers'

let app: ApplicationContract

test.group('OAT Guard | Verify Credentials', (group) => {
  group.setup(async () => {
    app = await setupApplication()
    await setup(app)
  })

  group.teardown(async () => {
    await cleanup(app)
  })

  group.each.teardown(async () => {
    await reset(app)
    app.container.use('Adonis/Core/Event')['clearAllListeners']()
  })

  test('raise exception when unable to lookup user', async ({ assert }) => {
    assert.plan(1)

    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    try {
      await apiTokensGuard.verifyCredentials('virk@adonisjs.com', 'password')
    } catch (error) {
      assert.deepEqual(error.message, 'E_INVALID_AUTH_UID: User not found')
    }
  })

  test('raise exception when password is incorrect', async ({ assert }) => {
    assert.plan(1)

    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    try {
      await apiTokensGuard.verifyCredentials('virk@adonisjs.com', 'password')
    } catch (error) {
      assert.deepEqual(error.message, 'E_INVALID_AUTH_PASSWORD: Password mis-match')
    }
  })

  test('return user when able to verify credentials', async ({ assert }) => {
    assert.plan(1)

    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    const user = await apiTokensGuard.verifyCredentials('virk@adonisjs.com', 'secret')
    assert.instanceOf(user, User)
  })
})

test.group('OAT Guard | attempt', (group) => {
  group.setup(async () => {
    app = await setupApplication()
    await setup(app)
  })

  group.teardown(async () => {
    await cleanup(app)
  })

  group.each.teardown(async () => {
    await reset(app)
    app.container.use('Adonis/Core/Event')['clearAllListeners']()
  })

  test('return token with user from the attempt call', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    /**
     * Assert the event is fired with correct set of arguments
     */
    app.container.use('Adonis/Core/Event').once('adonis:api:login', ({ name, user, token }) => {
      assert.equal(name, 'api')
      assert.instanceOf(user, User)
      assert.instanceOf(token, OpaqueToken)
    })

    const token = await apiTokensGuard.attempt('virk@adonisjs.com', 'secret')
    const tokens = await app.container.use('Adonis/Lucid/Database').query().from('api_tokens')

    /**
     * Assert correct token is generated and persisted to the db
     */
    assert.equal(token.type, 'bearer')
    assert.instanceOf(token.user, User)
    assert.isUndefined(token.expiresAt)
    assert.lengthOf(tokens, 1)
    assert.isNull(tokens[0].expires_at)
  })

  test('define custom expiry', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    /**
     * Assert the event is fired with correct set of arguments
     */
    app.container
      .use('Adonis/Core/Event')
      .once('adonis:api:login', ({ name, user: model, token }) => {
        assert.equal(name, 'api')
        assert.instanceOf(model, User)
        assert.instanceOf(token, OpaqueToken)
      })

    const token = await apiTokensGuard.attempt('virk@adonisjs.com', 'secret', {
      expiresIn: '3mins',
    })
    const tokens = await app.container.use('Adonis/Lucid/Database').query().from('api_tokens')

    /**
     * Assert correct token is generated and persisted to the db
     */
    assert.lengthOf(tokens, 1)
    assert.isBelow(token.expiresAt.diff(DateTime.local(), 'minutes').minutes, 4)
    assert.isBelow(
      DateTime.fromSQL(tokens[0].expires_at).diff(DateTime.local(), 'minutes').minutes,
      4
    )
  })

  test('define custom name for the token', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    /**
     * Assert the event is fired with correct set of arguments
     */
    app.container
      .use('Adonis/Core/Event')
      .once('adonis:api:login', ({ name, user: model, token }) => {
        assert.equal(name, 'api')
        assert.instanceOf(model, User)
        assert.instanceOf(token, OpaqueToken)
      })

    const token = await apiTokensGuard.attempt('virk@adonisjs.com', 'secret', {
      name: 'Android token',
    })
    const tokens = await app.container
      .use('Adonis/Lucid/Database')
      .query()
      .from('api_tokens')
      .where('user_id', user.id)

    /**
     * Assert correct token is generated and persisted to the db
     */
    assert.lengthOf(tokens, 1)
    assert.equal(token.name, 'Android token')
    assert.equal(tokens[0].name, 'Android token')
  })

  test('define meta data to be persisted inside the database', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    /**
     * Assert the event is fired with correct set of arguments
     */
    app.container
      .use('Adonis/Core/Event')
      .once('adonis:api:login', ({ name, user: model, token }) => {
        assert.equal(name, 'api')
        assert.instanceOf(model, User)
        assert.instanceOf(token, OpaqueToken)
      })

    const token = await apiTokensGuard.attempt('virk@adonisjs.com', 'secret', {
      device_name: 'Android',
      ip_address: '192.168.1.1',
    })
    const tokens = await app.container
      .use('Adonis/Lucid/Database')
      .query()
      .from('api_tokens')
      .where('user_id', user.id)

    /**
     * Assert correct token is generated and persisted to the db
     */
    assert.lengthOf(tokens, 1)
    assert.equal(tokens[0].device_name, 'Android')
    assert.equal(tokens[0].ip_address, '192.168.1.1')
    assert.deepEqual(token.meta, { device_name: 'Android', ip_address: '192.168.1.1' })
  })
})

test.group('OAT Guard | login', (group) => {
  group.setup(async () => {
    app = await setupApplication()
    await setup(app)
  })

  group.teardown(async () => {
    await cleanup(app)
  })

  group.each.teardown(async () => {
    await reset(app)
    app.container.use('Adonis/Core/Event')['clearAllListeners']()
  })

  test('login using user instance', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    /**
     * Assert the event is fired with correct set of arguments
     */
    app.container
      .use('Adonis/Core/Event')
      .once('adonis:api:login', ({ name, user: model, token }) => {
        assert.equal(name, 'api')
        assert.instanceOf(model, User)
        assert.instanceOf(token, OpaqueToken)
      })

    const token = await apiTokensGuard.login(user, {
      device_name: 'Android',
      ip_address: '192.168.1.1',
    })
    const tokens = await app.container
      .use('Adonis/Lucid/Database')
      .query()
      .from('api_tokens')
      .where('user_id', user.id)

    /**
     * Assert correct token is generated and persisted to the db
     */
    assert.lengthOf(tokens, 1)
    assert.equal(tokens[0].device_name, 'Android')
    assert.equal(tokens[0].ip_address, '192.168.1.1')
    assert.deepEqual(token.meta, { device_name: 'Android', ip_address: '192.168.1.1' })
  })

  test('use custom token type', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database')),
      {
        driver: 'database',
        table: 'api_tokens',
        type: 'access_token',
      }
    )

    /**
     * Assert the event is fired with correct set of arguments
     */
    app.container
      .use('Adonis/Core/Event')
      .once('adonis:api:login', ({ name, user: model, token }) => {
        assert.equal(name, 'api')
        assert.instanceOf(model, User)
        assert.instanceOf(token, OpaqueToken)
        assert.equal(token.type, 'bearer')
      })

    const token = await apiTokensGuard.login(user, {
      device_name: 'Android',
      ip_address: '192.168.1.1',
    })
    const tokens = await app.container
      .use('Adonis/Lucid/Database')
      .query()
      .from('api_tokens')
      .where('user_id', user.id)

    /**
     * Assert correct token is generated and persisted to the db
     */
    assert.lengthOf(tokens, 1)
    assert.equal(tokens[0].device_name, 'Android')
    assert.equal(tokens[0].ip_address, '192.168.1.1')
    assert.equal(tokens[0].type, 'access_token')
    assert.deepEqual(token.meta, { device_name: 'Android', ip_address: '192.168.1.1' })
  })
})

test.group('OAT Guard | loginViaId', (group) => {
  group.setup(async () => {
    app = await setupApplication()
    await setup(app)
  })

  group.teardown(async () => {
    await cleanup(app)
  })

  group.each.teardown(async () => {
    await reset(app)
    app.container.use('Adonis/Core/Event')['clearAllListeners']()
  })

  test('login using user id', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    /**
     * Assert the event is fired with correct set of arguments
     */
    app.container
      .use('Adonis/Core/Event')
      .once('adonis:api:login', ({ name, user: model, token }) => {
        assert.equal(name, 'api')
        assert.instanceOf(model, User)
        assert.instanceOf(token, OpaqueToken)
      })

    const token = await apiTokensGuard.loginViaId(user.id, {
      device_name: 'Android',
      ip_address: '192.168.1.1',
    })
    const tokens = await app.container
      .use('Adonis/Lucid/Database')
      .query()
      .from('api_tokens')
      .where('user_id', user.id)

    /**
     * Assert correct token is generated and persisted to the db
     */
    assert.lengthOf(tokens, 1)
    assert.equal(tokens[0].device_name, 'Android')
    assert.equal(tokens[0].ip_address, '192.168.1.1')
    assert.deepEqual(token.meta, { device_name: 'Android', ip_address: '192.168.1.1' })
  })
})

test.group('OAT Guard | authenticate', (group) => {
  group.setup(async () => {
    app = await setupApplication()
    await setup(app)
  })

  group.teardown(async () => {
    await cleanup(app)
  })

  group.each.teardown(async () => {
    await reset(app)
    app.container.use('Adonis/Core/Event')['clearAllListeners']()
  })

  test('authenticate request by reading the bearer token', async ({ assert }) => {
    assert.plan(6)

    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    /**
     * Assert the event is fired with correct set of arguments
     */
    app.container
      .use('Adonis/Core/Event')
      .once('adonis:api:authenticate', ({ name, user: model, token }) => {
        assert.equal(name, 'api')
        assert.instanceOf(model, User)
        assert.instanceOf(token, ProviderToken)
      })

    const token = await apiTokensGuard.loginViaId(user.id, {
      device_name: 'Android',
      ip_address: '192.168.1.1',
    })

    const server = createServer(async (req, res) => {
      const ctx = app.container.use('Adonis/Core/HttpContext').create('/', {}, req, res)
      const oat1 = getApiTokensGuard(
        app,
        getLucidProvider(app, { model: async () => User }),
        getLucidProviderConfig({ model: async () => User }),
        ctx,
        getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
      )

      try {
        await oat1.authenticate()
        ctx.response.send(oat1.token)
      } catch (error) {
        ctx.response.status(500).send(error)
      }

      ctx.response.finish()
    })

    const { body } = await supertest(server)
      .get('/')
      .set('Authorization', `${token.type} ${token.token}`)
      .expect(200)

    assert.equal(body.name, 'Opaque Access Token')
    assert.equal(body.type, 'opaque_token')
    assert.exists(body.tokenHash)
  })

  test('raise error when Authorization header is missing', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    await apiTokensGuard.loginViaId(user.id, {
      device_name: 'Android',
      ip_address: '192.168.1.1',
    })

    const server = createServer(async (req, res) => {
      const ctx = app.container.use('Adonis/Core/HttpContext').create('/', {}, req, res)
      const oat1 = getApiTokensGuard(
        app,
        getLucidProvider(app, { model: async () => User }),
        getLucidProviderConfig({ model: async () => User }),
        ctx,
        getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
      )

      try {
        await oat1.authenticate()
        ctx.response.send(oat1.token)
      } catch (error) {
        error.handle(error, { ...ctx, auth: { use: () => oat1 } as any })
      }

      ctx.response.finish()
    })

    const { body } = await supertest(server).get('/').set('Accept', 'application/json').expect(401)

    assert.deepEqual(body, {
      errors: [{ message: 'E_INVALID_API_TOKEN: Invalid API token' }],
    })
  })

  test('raise error when token is malformed', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    await apiTokensGuard.loginViaId(user.id, {
      device_name: 'Android',
      ip_address: '192.168.1.1',
    })

    const server = createServer(async (req, res) => {
      const ctx = app.container.use('Adonis/Core/HttpContext').create('/', {}, req, res)
      const oat1 = getApiTokensGuard(
        app,
        getLucidProvider(app, { model: async () => User }),
        getLucidProviderConfig({ model: async () => User }),
        ctx,
        getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
      )

      try {
        await oat1.authenticate()
        ctx.response.send(oat1.token)
      } catch (error) {
        error.handle(error, { ...ctx, auth: { use: () => oat1 } as any })
      }

      ctx.response.finish()
    })

    const { body } = await supertest(server)
      .get('/')
      .set('Accept', 'application/json')
      .set('Authorization', 'Bearer foobar')
      .expect(401)

    assert.deepEqual(body, {
      errors: [{ message: 'E_INVALID_API_TOKEN: Invalid API token' }],
    })
  })

  test('raise error when token is missing in the database', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    const token = await apiTokensGuard.loginViaId(user.id, {
      device_name: 'Android',
      ip_address: '192.168.1.1',
    })

    const server = createServer(async (req, res) => {
      const ctx = app.container.use('Adonis/Core/HttpContext').create('/', {}, req, res)
      const oat1 = getApiTokensGuard(
        app,
        getLucidProvider(app, { model: async () => User }),
        getLucidProviderConfig({ model: async () => User }),
        ctx,
        getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
      )

      try {
        await oat1.authenticate()
        ctx.response.send(oat1.token)
      } catch (error) {
        error.handle(error, { ...ctx, auth: { use: () => oat1 } as any })
      }

      ctx.response.finish()
    })

    await app.container.use('Adonis/Lucid/Database').from('api_tokens').del()
    const { body } = await supertest(server)
      .get('/')
      .set('Accept', 'application/json')
      .set('Authorization', `${token.type} ${token.token}`)
      .expect(401)

    assert.deepEqual(body, {
      errors: [{ message: 'E_INVALID_API_TOKEN: Invalid API token' }],
    })
  })

  test('raise error when token is valid but user is missing', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    const token = await apiTokensGuard.loginViaId(user.id, {
      device_name: 'Android',
      ip_address: '192.168.1.1',
    })

    const server = createServer(async (req, res) => {
      const ctx = app.container.use('Adonis/Core/HttpContext').create('/', {}, req, res)
      const oat1 = getApiTokensGuard(
        app,
        getLucidProvider(app, { model: async () => User }),
        getLucidProviderConfig({ model: async () => User }),
        ctx,
        getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
      )

      try {
        await oat1.authenticate()
        ctx.response.send(oat1.token)
      } catch (error) {
        error.handle(error, { ...ctx, auth: { use: () => oat1 } as any })
      }

      ctx.response.finish()
    })

    await app.container.use('Adonis/Lucid/Database').from('users').del()
    const { body } = await supertest(server)
      .get('/')
      .set('Accept', 'application/json')
      .set('Authorization', `${token.type} ${token.token}`)
      .expect(401)

    assert.deepEqual(body, {
      errors: [{ message: 'E_INVALID_API_TOKEN: Invalid API token' }],
    })
  })

  test('raise error when token is expired', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    const token = await apiTokensGuard.loginViaId(user.id, {
      device_name: 'Android',
      ip_address: '192.168.1.1',
    })

    await app.container
      .use('Adonis/Lucid/Database')
      .from('api_tokens')
      .update({
        expires_at: DateTime.local().minus({ days: 1 }).toJSDate(),
      })

    const server = createServer(async (req, res) => {
      const ctx = app.container.use('Adonis/Core/HttpContext').create('/', {}, req, res)
      const oat1 = getApiTokensGuard(
        app,
        getLucidProvider(app, { model: async () => User }),
        getLucidProviderConfig({ model: async () => User }),
        ctx,
        getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
      )

      try {
        await oat1.authenticate()
        ctx.response.send(oat1.token)
      } catch (error) {
        error.handle(error, { ...ctx, auth: { use: () => oat1 } as any })
      }

      ctx.response.finish()
    })

    const { body } = await supertest(server)
      .get('/')
      .set('Accept', 'application/json')
      .set('Authorization', `${token.type} ${token.token}`)
      .expect(401)

    assert.deepEqual(body, {
      errors: [{ message: 'E_INVALID_API_TOKEN: Invalid API token' }],
    })
  })

  test('work fine when token is not expired', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    const token = await apiTokensGuard.loginViaId(user.id, {
      device_name: 'Android',
      ip_address: '192.168.1.1',
      expiresIn: '30 mins',
    })

    const server = createServer(async (req, res) => {
      const ctx = app.container.use('Adonis/Core/HttpContext').create('/', {}, req, res)
      const oat1 = getApiTokensGuard(
        app,
        getLucidProvider(app, { model: async () => User }),
        getLucidProviderConfig({ model: async () => User }),
        ctx,
        getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
      )

      try {
        await oat1.authenticate()
        ctx.response.send(oat1.token)
      } catch (error) {
        error.handle(error, { ...ctx, auth: { use: () => oat1 } as any })
      }

      ctx.response.finish()
    })

    const { body } = await supertest(server)
      .get('/')
      .set('Accept', 'application/json')
      .set('Authorization', `${token.type} ${token.token}`)
      .expect(200)

    assert.equal(body.name, 'Opaque Access Token')
    assert.equal(body.type, 'opaque_token')
    assert.exists(body.tokenHash)
  })
})

test.group('OAT Guard | logout', (group) => {
  group.setup(async () => {
    app = await setupApplication()
    await setup(app)
  })

  group.teardown(async () => {
    await cleanup(app)
  })

  group.each.teardown(async () => {
    await reset(app)
    app.container.use('Adonis/Core/Event')['clearAllListeners']()
  })

  test('delete user token during logout', async ({ assert }) => {
    assert.plan(6)

    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: await app.container.use('Adonis/Core/Hash').make('secret'),
    })

    const apiTokensGuard = getApiTokensGuard(
      app,
      getLucidProvider(app, { model: async () => User }),
      getLucidProviderConfig({ model: async () => User }),
      app.container.use('Adonis/Core/HttpContext').create('/', {}),
      getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
    )

    /**
     * Assert the event is fired with correct set of arguments
     */
    app.container
      .use('Adonis/Core/Event')
      .once('adonis:api:authenticate', ({ name, user: model, token }) => {
        assert.equal(name, 'api')
        assert.instanceOf(model, User)
        assert.instanceOf(token, ProviderToken)
      })

    const token = await apiTokensGuard.loginViaId(user.id, {
      device_name: 'Android',
      ip_address: '192.168.1.1',
    })

    const server = createServer(async (req, res) => {
      const ctx = app.container.use('Adonis/Core/HttpContext').create('/', {}, req, res)
      const oat1 = getApiTokensGuard(
        app,
        getLucidProvider(app, { model: async () => User }),
        getLucidProviderConfig({ model: async () => User }),
        ctx,
        getTokensDbProvider(app.container.use('Adonis/Lucid/Database'))
      )

      try {
        await oat1.logout()
        ctx.response.send(oat1.toJSON())
      } catch (error) {
        ctx.response.status(500).send(error)
      }

      ctx.response.finish()
    })

    const { body } = await supertest(server)
      .get('/')
      .set('Authorization', `${token.type} ${token.token}`)
      .expect(200)

    const tokens = await app.container.use('Adonis/Lucid/Database').query().from('api_tokens')
    assert.lengthOf(tokens, 0)
    assert.isFalse(body.isLoggedIn)
    assert.isTrue(body.authenticationAttempted)
  })
})
