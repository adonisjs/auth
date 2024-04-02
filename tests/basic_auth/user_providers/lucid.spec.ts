/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { compose } from '@adonisjs/core/helpers'
import { BaseModel, column } from '@adonisjs/lucid/orm'

import { withAuthFinder } from '../../../src/mixins/lucid.js'
import { createDatabase, createTables, getHasher } from '../../helpers.js'
import { BasicAuthGuardUser } from '../../../modules/basic_auth_guard/types.js'
import { BasicAuthLucidUserProvider } from '../../../modules/basic_auth_guard/user_providers/lucid.js'

test.group('Basic auth user provider | Lucid | verifyCredentials', () => {
  test('return user when credentials are valid', async ({ assert, expectTypeOf }) => {
    const db = await createDatabase()
    await createTables(db)

    const hash = getHasher()
    class User extends compose(
      BaseModel,
      withAuthFinder(() => hash, {
        uids: ['email', 'username'],
        passwordColumnName: 'password',
      })
    ) {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string
    }

    const userProvider = new BasicAuthLucidUserProvider({
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

    const freshUser = await userProvider.verifyCredentials('virk@adonisjs.com', 'secret')
    assert.instanceOf(freshUser!.getOriginal(), User)
    assert.equal(freshUser!.getId(), user.id)
    expectTypeOf(freshUser).toEqualTypeOf<BasicAuthGuardUser<User> | null>()
  })

  test('return null when user does not exists', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const hash = getHasher()
    class User extends compose(
      BaseModel,
      withAuthFinder(() => hash, {
        uids: ['email', 'username'],
        passwordColumnName: 'password',
      })
    ) {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string
    }

    const userProvider = new BasicAuthLucidUserProvider({
      async model() {
        return {
          default: User,
        }
      },
    })

    const freshUser = await userProvider.verifyCredentials('virk@adonisjs.com', 'secret')
    assert.isNull(freshUser)
  })

  test('return null when password is invalid', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const hash = getHasher()
    class User extends compose(
      BaseModel,
      withAuthFinder(() => hash, {
        uids: ['email', 'username'],
        passwordColumnName: 'password',
      })
    ) {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string
    }

    const userProvider = new BasicAuthLucidUserProvider({
      async model() {
        return {
          default: User,
        }
      },
    })

    await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const freshUser = await userProvider.verifyCredentials('virk@adonisjs.com', 'supersecret')
    assert.isNull(freshUser)
  })
})

test.group('Basic auth user provider | Lucid | createUserForGuard', () => {
  test('throw error via getId when user does not have an id', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const hash = getHasher()
    class User extends compose(
      BaseModel,
      withAuthFinder(() => hash, {
        uids: ['email', 'username'],
        passwordColumnName: 'password',
      })
    ) {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string
    }

    const userProvider = new BasicAuthLucidUserProvider({
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

    const hash = getHasher()
    class User extends compose(
      BaseModel,
      withAuthFinder(() => hash, {
        uids: ['email', 'username'],
        passwordColumnName: 'password',
      })
    ) {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string
    }

    const userProvider = new BasicAuthLucidUserProvider({
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
