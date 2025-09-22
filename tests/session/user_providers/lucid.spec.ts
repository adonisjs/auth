/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { Secret } from '@adonisjs/core/helpers'
import { BaseModel, column } from '@adonisjs/lucid/orm'

import { createDatabase, createTables } from '../../helpers.ts'
import { RememberMeToken } from '../../../modules/session_guard/remember_me_token.ts'
import { SessionLucidUserProvider } from '../../../modules/session_guard/user_providers/lucid.ts'
import { DbRememberMeTokensProvider } from '../../../modules/session_guard/token_providers/db.ts'

test.group('Session user provider | Lucid', () => {
  test('throw error when user model is not using tokens provider', async () => {
    const db = await createDatabase()
    await createTables(db)

    class User extends BaseModel {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string
    }

    const userProvider = new SessionLucidUserProvider({
      async model() {
        return {
          default: User,
        }
      },
    })

    await userProvider.verifyRememberToken(new Secret('foo.bar'))
  }).throws(
    'Cannot use "User" model for verifying remember me tokens. Make sure to assign a token provider to the model.'
  )
})

test.group('Session user provider | Lucid | findById', () => {
  test('find user by id', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    class User extends BaseModel {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string
    }

    const userProvider = new SessionLucidUserProvider({
      async model() {
        return {
          default: User,
        }
      },
    })

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const freshUser = await userProvider.findById(user.id)
    assert.instanceOf(freshUser!.getOriginal(), User)
    assert.equal(freshUser!.getId(), user.id)
  })

  test('return null when user does not exist', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    class User extends BaseModel {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string
    }

    const userProvider = new SessionLucidUserProvider({
      async model() {
        return {
          default: User,
        }
      },
    })

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })
    await user.delete()

    const freshUser = await userProvider.findById(user.id)
    assert.isNull(freshUser)
  })
})

test.group('Session user provider | Lucid | createToken', () => {
  test('create token for a user', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    class User extends BaseModel {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string

      static rememberMeTokens = DbRememberMeTokensProvider.forModel(User)
    }

    const userProvider = new SessionLucidUserProvider({
      async model() {
        return {
          default: User,
        }
      },
    })

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await userProvider.createRememberToken(user, '20 mins')
    assert.instanceOf(token, RememberMeToken)
    assert.exists(token.identifier)
    assert.instanceOf(token, RememberMeToken)
    assert.equal(token.tokenableId, user.id)
    assert.instanceOf(token.expiresAt, Date)
    assert.instanceOf(token.createdAt, Date)
    assert.instanceOf(token.updatedAt, Date)
    assert.isDefined(token.hash)
    assert.exists(token.value)
  })
})

test.group('Session user provider | Lucid | deleteToken', () => {
  test('delete existing token', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    class User extends BaseModel {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string

      static rememberMeTokens = DbRememberMeTokensProvider.forModel(User)
    }

    const userProvider = new SessionLucidUserProvider({
      async model() {
        return {
          default: User,
        }
      },
    })

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await userProvider.createRememberToken(user, '20 mins')
    assert.equal(await userProvider.deleteRemeberToken(user, token.identifier), 1)

    const tokens = await User.rememberMeTokens.all(user)
    assert.lengthOf(tokens, 0)
  })
})

test.group('Session user provider | Lucid | recycleToken', () => {
  test('recycle token', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    class User extends BaseModel {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string

      static rememberMeTokens = DbRememberMeTokensProvider.forModel(User)
    }

    const userProvider = new SessionLucidUserProvider({
      async model() {
        return {
          default: User,
        }
      },
    })

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await userProvider.createRememberToken(user, '20 mins')
    const freshToken = await userProvider.recycleRememberToken(user, token.identifier, '20 mins')

    assert.isNull(await User.rememberMeTokens.find(user, token.identifier))
    assert.isNotNull(await User.rememberMeTokens.find(user, freshToken.identifier))
  })
})

test.group('Session user provider | Lucid | verifyToken', () => {
  test('return remember token when it is valid', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    class User extends BaseModel {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string

      static rememberMeTokens = DbRememberMeTokensProvider.forModel(User)
    }

    const userProvider = new SessionLucidUserProvider({
      async model() {
        return {
          default: User,
        }
      },
    })

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await userProvider.createRememberToken(user, '20 mins')
    const freshToken = await userProvider.verifyRememberToken(new Secret(token.value!.release()))
    assert.instanceOf(freshToken, RememberMeToken)
    assert.isUndefined(freshToken!.value)
    assert.equal(freshToken!.hash, token.hash)
    assert.closeTo(freshToken!.createdAt.getTime(), token.createdAt.getTime(), 10)
  })
})

test.group('Session user provider | Lucid | createUserForGuard', () => {
  test('throw error via getId when user does not have an id', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    class User extends BaseModel {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string

      static rememberMeTokens = DbRememberMeTokensProvider.forModel(User)
    }

    const userProvider = new SessionLucidUserProvider({
      async model() {
        return {
          default: User,
        }
      },
    })

    const user = await userProvider.createUserForGuard(new User())
    assert.throws(
      () => user.getId(),
      'Cannot use "User" model for authentication. The value of column "id" is undefined or null'
    )
  })

  test('throw error via getId when user is not an instance of the associated model', async ({
    assert,
  }) => {
    const db = await createDatabase()
    await createTables(db)

    class User extends BaseModel {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string

      static rememberMeTokens = DbRememberMeTokensProvider.forModel(User)
    }

    const userProvider = new SessionLucidUserProvider({
      async model() {
        return {
          default: User,
        }
      },
    })

    await assert.rejects(
      // @ts-expect-error
      () => userProvider.createUserForGuard({}),
      'Invalid user object. It must be an instance of the "User" model'
    )
  })
})
