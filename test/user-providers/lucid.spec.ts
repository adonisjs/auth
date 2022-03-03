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

import { LucidUser } from '../../src/UserProviders/Lucid/User'
import {
  setup,
  reset,
  cleanup,
  getUserModel,
  getLucidProvider,
  setupApplication,
} from '../../test-helpers'

let app: ApplicationContract

test.group('Lucid Provider | findById', (group) => {
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

    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({ username: 'virk', email: 'virk@adonisjs.com' })

    const lucidProvider = getLucidProvider(app, { model: async () => User })
    lucidProvider.before('findUser', async (query) => assert.exists(query))
    lucidProvider.after('findUser', async (model) => assert.instanceOf(model, User))

    const providerUser = await lucidProvider.findById(user.id)

    assert.instanceOf(providerUser.user, User)
    assert.equal(providerUser.user!.username, 'virk')
    assert.equal(providerUser.user!.email, 'virk@adonisjs.com')
  })

  test('return null when unable to lookup using id', async ({ assert }) => {
    assert.plan(2)

    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)

    const lucidProvider = getLucidProvider(app, { model: async () => User })
    lucidProvider.before('findUser', async (query) => assert.exists(query))
    lucidProvider.after('findUser', async () => {
      throw new Error('not expected to be invoked')
    })

    const providerUser = await lucidProvider.findById(1)
    assert.isNull(providerUser.user)
  })

  test('use custom connection', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({ username: 'virk', email: 'virk@adonisjs.com' })

    const lucidProvider = getLucidProvider(app, { model: async () => User })
    lucidProvider.setConnection('secondary')

    const providerUser = await lucidProvider.findById(user.id)
    assert.isNull(providerUser.user)
  })

  test('use custom query client', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({ username: 'virk', email: 'virk@adonisjs.com' })

    const lucidProvider = getLucidProvider(app, { model: async () => User })
    lucidProvider.setConnection(app.container.use('Adonis/Lucid/Database').connection('secondary'))

    const providerUser = await lucidProvider.findById(user.id)
    assert.isNull(providerUser.user)
  })

  test('use custom user builder', async ({ assert }) => {
    assert.plan(6)

    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({ username: 'virk', email: 'virk@adonisjs.com' })
    class CustomUser extends LucidUser<typeof User> {}

    const lucidProvider = getLucidProvider(app, {
      model: async () => User,
      user: async () => CustomUser,
    })

    lucidProvider.before('findUser', async (query) => assert.exists(query))
    lucidProvider.after('findUser', async (model) => assert.instanceOf(model, User))

    const providerUser = await lucidProvider.findById(user.id)

    assert.instanceOf(providerUser, CustomUser)
    assert.instanceOf(providerUser.user, User)
    assert.equal(providerUser.user!.username, 'virk')
    assert.equal(providerUser.user!.email, 'virk@adonisjs.com')
  })
})

test.group('Lucid Provider | findByUids', (group) => {
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
    assert.plan(9)

    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    await User.create({ username: 'virk', email: 'virk@adonisjs.com' })
    await User.create({ username: 'nikk', email: 'nikk@adonisjs.com' })

    const lucidProvider = getLucidProvider(app, { model: async () => User })
    lucidProvider.before('findUser', async (query) => assert.exists(query))
    lucidProvider.after('findUser', async (user) => assert.instanceOf(user, User))

    const providerUser = await lucidProvider.findByUid('virk')
    const providerUser1 = await lucidProvider.findByUid('nikk@adonisjs.com')

    assert.instanceOf(providerUser.user, User)
    assert.equal(providerUser.user!.username, 'virk')
    assert.equal(providerUser.user!.email, 'virk@adonisjs.com')

    assert.equal(providerUser1.user!.username, 'nikk')
    assert.equal(providerUser1.user!.email, 'nikk@adonisjs.com')
  })

  test('return null when unable to lookup user using uid', async ({ assert }) => {
    assert.plan(4)

    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const lucidProvider = getLucidProvider(app, { model: async () => User })

    lucidProvider.before('findUser', async (query) => assert.exists(query))
    lucidProvider.after('findUser', async () => {
      throw new Error('not expected to be invoked')
    })

    const providerUser = await lucidProvider.findByUid('virk')
    const providerUser1 = await lucidProvider.findByUid('virk@adonisjs.com')
    assert.isNull(providerUser.user)
    assert.isNull(providerUser1.user)
  })

  test('use custom connection', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    await User.create({ username: 'nikk', email: 'nikk@adonisjs.com' })

    const lucidProvider = getLucidProvider(app, { model: async () => User })
    lucidProvider.setConnection('secondary')

    const providerUser = await lucidProvider.findByUid('nikk')
    const providerUser1 = await lucidProvider.findByUid('nikk@adonisjs.com')

    assert.isNull(providerUser.user)
    assert.isNull(providerUser1.user)
  })

  test('use custom query client', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    await User.create({ username: 'nikk', email: 'nikk@adonisjs.com' })

    const lucidProvider = getLucidProvider(app, { model: async () => User })
    lucidProvider.setConnection(app.container.use('Adonis/Lucid/Database').connection('secondary'))

    const providerUser = await lucidProvider.findByUid('nikk')
    const providerUser1 = await lucidProvider.findByUid('nikk@adonisjs.com')
    assert.isNull(providerUser.user)
    assert.isNull(providerUser1.user)
  })

  test('find a user using the custom function', async ({ assert }) => {
    assert.plan(4)

    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    User['findForAuth'] = function (_: any, uid: string) {
      return this.query().where('username', uid).first()
    }

    await User.create({ username: 'virk', email: 'virk@adonisjs.com' })
    await User.create({ username: 'nikk', email: 'nikk@adonisjs.com' })

    const lucidProvider = getLucidProvider(app, { model: async () => User })

    /**
     * These won't be executed
     */
    lucidProvider.before('findUser', async (query) => assert.exists(query))
    lucidProvider.after('findUser', async (user) => assert.instanceOf(user, User))

    const providerUser = await lucidProvider.findByUid('virk')
    const providerUser1 = await lucidProvider.findByUid('nikk@adonisjs.com')

    assert.instanceOf(providerUser.user, User)
    assert.equal(providerUser.user!.username, 'virk')
    assert.equal(providerUser.user!.email, 'virk@adonisjs.com')

    assert.isNull(providerUser1.user)
  })
})

test.group('Lucid Provider | findByRememberMeToken', (group) => {
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

    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      rememberMeToken: '123',
    })
    await User.create({ username: 'nikk', email: 'nikk@adonisjs.com' })

    const lucidProvider = getLucidProvider(app, { model: async () => User })
    lucidProvider.before('findUser', async (query) => assert.exists(query))
    lucidProvider.after('findUser', async (model) => assert.instanceOf(model, User))

    const providerUser = await lucidProvider.findByRememberMeToken(user.id, '123')
    assert.instanceOf(providerUser.user, User)
    assert.equal(providerUser.user!.username, 'virk')
    assert.equal(providerUser.user!.email, 'virk@adonisjs.com')
  })

  test("return null when user doesn't exists", async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const lucidProvider = getLucidProvider(app, { model: async () => User })
    const providerUser = await lucidProvider.findByRememberMeToken(1, '123')
    assert.isNull(providerUser.user)
  })

  test('return null when users exists but token is missing', async ({ assert }) => {
    assert.plan(2)

    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)

    const user = await User.create({ username: 'nikk', email: 'nikk@adonisjs.com' })
    await User.create({ username: 'virk', email: 'virk@adonisjs.com', rememberMeToken: '123' })

    const lucidProvider = getLucidProvider(app, { model: async () => User })
    lucidProvider.before('findUser', async (query) => assert.exists(query))
    lucidProvider.after('findUser', async () => {
      throw new Error('not expected to be invoked')
    })

    const providerUser = await lucidProvider.findByRememberMeToken(user.id, '123')
    assert.isNull(providerUser.user)
  })

  test('use custom connection', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      rememberMeToken: '123',
    })

    const lucidProvider = getLucidProvider(app, { model: async () => User })
    lucidProvider.setConnection('secondary')

    const providerUser = await lucidProvider.findByRememberMeToken(user.id, '123')
    assert.isNull(providerUser.user)
  })

  test('use custom query client', async ({ assert }) => {
    const User = getUserModel(app.container.use('Adonis/Lucid/Orm').BaseModel)
    const user = await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      rememberMeToken: '123',
    })

    const lucidProvider = getLucidProvider(app, { model: async () => User })
    lucidProvider.setConnection(app.container.use('Adonis/Lucid/Database').connection('secondary'))

    const providerUser = await lucidProvider.findByRememberMeToken(user.id, '123')
    assert.isNull(providerUser.user)
  })
})
