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

import { createDatabase, createTables } from '../../helpers.js'
import { AccessToken } from '../../../modules/access_tokens_guard/access_token.js'
import { DbAccessTokensProvider } from '../../../modules/access_tokens_guard/token_providers/db.js'
import { AccessTokensLucidUserProvider } from '../../../modules/access_tokens_guard/user_providers/lucid.js'

test.group('Access tokens user provider | Lucid', () => {
  test('throw error when user does not implement a token provider', async ({ assert }) => {
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

    const userProvider = new AccessTokensLucidUserProvider({
      tokens: 'authTokens',
      async model() {
        return {
          default: User,
        }
      },
    } as any)

    await assert.rejects(
      () => userProvider.verifyToken(new Secret('foo')),
      'Cannot use "User" model for verifying access tokens. Make sure to assign a token provider to the model.'
    )
  })
})

test.group('Access tokens user provider | Lucid | verify', () => {
  test('return access token when it is valid', async ({ assert }) => {
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const userProvider = new AccessTokensLucidUserProvider({
      tokens: 'authTokens',
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

    const token = await User.authTokens.create(user)
    const freshToken = await userProvider.verifyToken(new Secret(token.value!.release()))
    assert.instanceOf(freshToken, AccessToken)
    assert.isUndefined(freshToken!.value)
    assert.equal(freshToken!.type, token.type)
    assert.equal(freshToken!.hash, token.hash)
    assert.closeTo(freshToken!.createdAt.getTime(), token.createdAt.getTime(), 10)
    assert.instanceOf(freshToken!.lastUsedAt, Date)
  })
})

test.group('Access tokens user provider | Lucid | createToken', () => {
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const userProvider = new AccessTokensLucidUserProvider({
      tokens: 'authTokens',
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

    const token = await userProvider.createToken(user)
    assert.exists(token.identifier)
    assert.instanceOf(token, AccessToken)
    assert.equal(token.tokenableId, user.id)
    assert.deepEqual(token.abilities, ['*'])
    assert.isNull(token.lastUsedAt)
    assert.isNull(token.expiresAt)
    assert.instanceOf(token.createdAt, Date)
    assert.instanceOf(token.updatedAt, Date)
    assert.isDefined(token.hash)
    assert.equal(token.type, 'auth_token')
    assert.isTrue(token.value!.release().startsWith('oat_'))
  })
})

test.group('Access tokens user provider | Lucid | invalidateToken', () => {
  test('return true if token was invalidated', async ({ assert }) => {
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const userProvider = new AccessTokensLucidUserProvider({
      tokens: 'authTokens',
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

    const token = await User.authTokens.create(user)
    const result = await userProvider.invalidateToken(token.value!)
    assert.isTrue(result)
  })

  test('return false if not a real token', async ({ assert }) => {
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const userProvider = new AccessTokensLucidUserProvider({
      tokens: 'authTokens',
      async model() {
        return {
          default: User,
        }
      },
    })

    const result = await userProvider.invalidateToken(new Secret('not-a-real-token'))
    assert.isFalse(result)
  })

  test('return false if token is not longer valid', async ({ assert }) => {
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const userProvider = new AccessTokensLucidUserProvider({
      tokens: 'authTokens',
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

    const token = await User.authTokens.create(user)
    await userProvider.invalidateToken(token.value!)

    const result = await userProvider.invalidateToken(token.value!)
    assert.isFalse(result)
  })
})

test.group('Access tokens user provider | Lucid | findById', () => {
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const userProvider = new AccessTokensLucidUserProvider({
      tokens: 'authTokens',
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

    const token = await User.authTokens.create(user)
    const freshToken = await userProvider.verifyToken(new Secret(token.value!.release()))
    const freshUser = await userProvider.findById(freshToken!.tokenableId)

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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const userProvider = new AccessTokensLucidUserProvider({
      tokens: 'authTokens',
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
    const token = await User.authTokens.create(user)
    await user.delete()

    const freshToken = await userProvider.verifyToken(new Secret(token.value!.release()))
    const freshUser = await userProvider.findById(freshToken!.tokenableId)
    assert.isNull(freshUser)
  })
})

test.group('Access tokens user provider | Lucid | createUserForGuard', () => {
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const userProvider = new AccessTokensLucidUserProvider({
      tokens: 'authTokens',
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const userProvider = new AccessTokensLucidUserProvider({
      tokens: 'authTokens',
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
