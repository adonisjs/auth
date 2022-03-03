/*
 * @adonisjs/auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { ApplicationContract } from '@ioc:Adonis/Core/Application'
import { DatabaseUser } from '../../src/UserProviders/Database/User'
import { setupApplication, setup, reset, cleanup, getDatabaseProvider } from '../../test-helpers'

let app: ApplicationContract

test.group('Database Provider | findById', (group) => {
  group.setup(async () => {
    app = await setupApplication()
    await setup(app)
  })

  group.teardown(async () => {
    await cleanup(app)
  })

  group.each.teardown(async () => {
    await reset(app)
  })

  test('find a user using the id', async ({ assert }) => {
    assert.plan(5)

    const db = app.container.use('Adonis/Lucid/Database')
    await db.table('users').insert({ username: 'virk', email: 'virk@adonisjs.com' })

    const dbProvider = getDatabaseProvider(app, {})

    dbProvider.before('findUser', async (query) => assert.exists(query))
    dbProvider.after('findUser', async (user) => {
      assert.equal(user.username, 'virk')
      assert.equal(user.email, 'virk@adonisjs.com')
    })

    const providerUser = await dbProvider.findById('1')
    assert.equal(providerUser.user!.username, 'virk')
    assert.equal(providerUser.user!.email, 'virk@adonisjs.com')
  })

  test('return null when unable to find the user', async ({ assert }) => {
    assert.plan(2)

    const dbProvider = getDatabaseProvider(app, {})
    dbProvider.before('findUser', async (query) => assert.exists(query))
    dbProvider.after('findUser', async () => {
      throw new Error('not expected to be called')
    })

    const providerUser = await dbProvider.findById('1')
    assert.isNull(providerUser.user)
  })

  test('use custom connection', async ({ assert }) => {
    const db = app.container.use('Adonis/Lucid/Database')
    await db.table('users').insert({ username: 'virk', email: 'virk@adonisjs.com' })

    const dbProvider = getDatabaseProvider(app, {})
    dbProvider.setConnection('secondary')

    const providerUser = await dbProvider.findById('1')
    assert.isNull(providerUser.user)
  })

  test('use custom query client', async ({ assert }) => {
    const db = app.container.use('Adonis/Lucid/Database')

    await db.table('users').insert({ username: 'virk', email: 'virk@adonisjs.com' })

    const dbProvider = getDatabaseProvider(app, {})
    dbProvider.setConnection(db.connection('secondary'))

    const providerUser = await dbProvider.findById('1')
    assert.isNull(providerUser.user)
  })

  test('user custom user builder', async ({ assert }) => {
    assert.plan(6)

    const db = app.container.use('Adonis/Lucid/Database')
    await db.table('users').insert({ username: 'virk', email: 'virk@adonisjs.com' })

    class CustomUser extends DatabaseUser {}

    const dbProvider = getDatabaseProvider(app, {
      user: async () => CustomUser,
    })

    dbProvider.before('findUser', async (query) => assert.exists(query))
    dbProvider.after('findUser', async (user) => {
      assert.equal(user.username, 'virk')
      assert.equal(user.email, 'virk@adonisjs.com')
    })

    const providerUser = await dbProvider.findById('1')
    assert.instanceOf(providerUser, CustomUser)
    assert.equal(providerUser.user!.username, 'virk')
    assert.equal(providerUser.user!.email, 'virk@adonisjs.com')
  })
})

test.group('Database Provider | findByUids', (group) => {
  group.setup(async () => {
    app = await setupApplication()
    await setup(app)
  })

  group.teardown(async () => {
    await cleanup(app)
  })

  group.each.teardown(async () => {
    await reset(app)
  })

  test('find a user using one of the uids', async ({ assert }) => {
    assert.plan(10)

    await app.container
      .use('Adonis/Lucid/Database')
      .table('users')
      .insert({ username: 'virk', email: 'virk@adonisjs.com' })

    await app.container
      .use('Adonis/Lucid/Database')
      .table('users')
      .insert({ username: 'nikk', email: 'nikk@adonisjs.com' })

    const dbProvider = getDatabaseProvider(app, {})

    dbProvider.before('findUser', async (query) => assert.exists(query))
    dbProvider.after('findUser', async (user) => {
      assert.property(user, 'username')
      assert.property(user, 'email')
    })

    const providerUser = await dbProvider.findByUid('virk')
    const providerUser1 = await dbProvider.findByUid('nikk@adonisjs.com')

    assert.equal(providerUser.user!.username, 'virk')
    assert.equal(providerUser.user!.email, 'virk@adonisjs.com')
    assert.equal(providerUser1.user!.username, 'nikk')
    assert.equal(providerUser1.user!.email, 'nikk@adonisjs.com')
  })

  test('return null when unable to lookup user using uids', async ({ assert }) => {
    assert.plan(4)

    const dbProvider = getDatabaseProvider(app, {})
    dbProvider.before('findUser', async (query) => assert.exists(query))
    dbProvider.after('findUser', async () => {
      throw new Error('not expected to be called')
    })

    const providerUser = await dbProvider.findByUid('virk')
    const providerUser1 = await dbProvider.findByUid('virk@adonisjs.com')

    assert.isNull(providerUser.user)
    assert.isNull(providerUser1.user)
  })

  test('use custom connection', async ({ assert }) => {
    await app.container
      .use('Adonis/Lucid/Database')
      .table('users')
      .insert({ username: 'virk', email: 'virk@adonisjs.com' })
    await app.container
      .use('Adonis/Lucid/Database')
      .table('users')
      .insert({ username: 'nikk', email: 'nikk@adonisjs.com' })

    const dbProvider = getDatabaseProvider(app, {})
    dbProvider.setConnection('secondary')

    const providerUser = await dbProvider.findByUid('virk')
    const providerUser1 = await dbProvider.findByUid('nikk@adonisjs.com')

    assert.isNull(providerUser.user)
    assert.isNull(providerUser1.user)
  })

  test('use custom query client', async ({ assert }) => {
    const db = app.container.use('Adonis/Lucid/Database')

    await db.table('users').insert({ username: 'virk', email: 'virk@adonisjs.com' })
    await db.table('users').insert({ username: 'nikk', email: 'nikk@adonisjs.com' })

    const dbProvider = getDatabaseProvider(app, {})
    dbProvider.setConnection(db.connection('secondary'))

    const providerUser = await dbProvider.findByUid('virk')
    const providerUser1 = await dbProvider.findByUid('nikk@adonisjs.com')

    assert.isNull(providerUser.user)
    assert.isNull(providerUser1.user)
  })
})

test.group('Database Provider | findByRememberMeToken', (group) => {
  group.setup(async () => {
    app = await setupApplication()
    await setup(app)
  })

  group.teardown(async () => {
    await cleanup(app)
  })

  group.each.teardown(async () => {
    await reset(app)
  })

  test('find a user using a token', async ({ assert }) => {
    assert.plan(5)
    const db = app.container.use('Adonis/Lucid/Database')

    await db
      .table('users')
      .insert({ username: 'virk', email: 'virk@adonisjs.com', remember_me_token: '123' })
    await db
      .table('users')
      .insert({ username: 'nikk', email: 'nikk@adonisjs.com', remember_me_token: '123' })

    const dbProvider = getDatabaseProvider(app, {})
    dbProvider.before('findUser', async (query) => assert.exists(query))
    dbProvider.after('findUser', async (user) => {
      assert.equal(user.username, 'virk')
      assert.equal(user.email, 'virk@adonisjs.com')
    })

    const providerUser = await dbProvider.findByRememberMeToken(1, '123')
    assert.equal(providerUser.user!.username, 'virk')
    assert.equal(providerUser.user!.email, 'virk@adonisjs.com')
  })

  test('return null when user exists but token is missing', async ({ assert }) => {
    const db = app.container.use('Adonis/Lucid/Database')

    await db.table('users').insert({ username: 'virk', email: 'virk@adonisjs.com' })
    await db
      .table('users')
      .insert({ username: 'nikk', email: 'nikk@adonisjs.com', remember_me_token: '123' })

    const dbProvider = getDatabaseProvider(app, {})
    const providerUser = await dbProvider.findByRememberMeToken(1, '123')
    assert.isNull(providerUser.user)
  })

  test('return null when user is missing', async ({ assert }) => {
    const dbProvider = getDatabaseProvider(app, {})
    const providerUser = await dbProvider.findByRememberMeToken(1, '123')
    assert.isNull(providerUser.user)
  })

  test('use custom connection', async ({ assert }) => {
    const db = app.container.use('Adonis/Lucid/Database')

    await db
      .table('users')
      .insert({ username: 'virk', email: 'virk@adonisjs.com', remember_me_token: '123' })
    await db
      .table('users')
      .insert({ username: 'nikk', email: 'nikk@adonisjs.com', remember_me_token: '123' })

    const dbProvider = getDatabaseProvider(app, {})
    dbProvider.setConnection('secondary')
    const providerUser = await dbProvider.findByRememberMeToken(1, '123')
    assert.isNull(providerUser.user)
  })

  test('use custom query client', async ({ assert }) => {
    const db = app.container.use('Adonis/Lucid/Database')

    await db
      .table('users')
      .insert({ username: 'virk', email: 'virk@adonisjs.com', remember_me_token: '123' })
    await db
      .table('users')
      .insert({ username: 'nikk', email: 'nikk@adonisjs.com', remember_me_token: '123' })

    const dbProvider = getDatabaseProvider(app, {})
    dbProvider.setConnection(db.connection('secondary'))
    const providerUser = await dbProvider.findByRememberMeToken(1, '123')
    assert.isNull(providerUser.user)
  })
})
