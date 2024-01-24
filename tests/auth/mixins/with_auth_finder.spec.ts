/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import convertHrtime from 'convert-hrtime'
import { compose } from '@adonisjs/core/helpers'
import { BaseModel, column } from '@adonisjs/lucid/orm'

import { createDatabase, createTables, getHasher } from '../../helpers.js'
import { withAuthFinder } from '../../../src/mixins/with_auth_finder.js'

test.group('withAuthFinder | findForAuth', () => {
  test('find user for authentication using the mixin', async ({ assert, expectTypeOf }) => {
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

    await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: 'secret',
    })

    const userByEmail = await User.findForAuth(['username', 'email'], 'virk@adonisjs.com')
    const userByUsername = await User.findForAuth(['username', 'email'], 'virk')

    expectTypeOf(userByEmail).toEqualTypeOf<User | null>()
    expectTypeOf(userByUsername).toEqualTypeOf<User | null>()

    assert.instanceOf(userByEmail, User)
    assert.instanceOf(userByUsername, User)
  })

  test('return null when user does not exists', async ({ assert, expectTypeOf }) => {
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

    const userByEmail = await User.findForAuth(['username', 'email'], 'virk@adonisjs.com')
    const userByUsername = await User.findForAuth(['username', 'email'], 'virk')

    expectTypeOf(userByEmail).toEqualTypeOf<User | null>()
    expectTypeOf(userByUsername).toEqualTypeOf<User | null>()

    assert.isNull(userByEmail)
    assert.isNull(userByUsername)
  })
})

test.group('withAuthFinder | verify', () => {
  test('return user instance when credentials are correct', async ({ assert, expectTypeOf }) => {
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

    await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: 'secret',
    })

    const user = await User.verifyCredentials('virk@adonisjs.com', 'secret')
    expectTypeOf(user).toEqualTypeOf<User>()
    assert.instanceOf(user, User)
  })

  test('throw error when user does not exists', async ({ assert }) => {
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

    await assert.rejects(
      () => User.verifyCredentials('virk@adonisjs.com', 'secret'),
      'Invalid user credentials'
    )
  })

  test('throw error when password is incorrect', async ({ assert }) => {
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

    await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: 'secret',
    })

    await assert.rejects(
      () => User.verifyCredentials('virk@adonisjs.com', 'supersecret'),
      'Invalid user credentials'
    )
  })

  test('throw error when user does not have a password', async ({ assert }) => {
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
      declare password: string | null
    }

    await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: null,
    })

    await assert.rejects(
      () => User.verifyCredentials('virk@adonisjs.com', 'supersecret'),
      'Cannot verify password during login. The value of column "password" is undefined or null'
    )
  })

  test('prevent timing attacks', async ({ assert }) => {
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

    await User.create({
      username: 'virk',
      email: 'virk@adonisjs.com',
      password: 'secret',
    })

    let startTime = process.hrtime.bigint()
    try {
      await User.verifyCredentials('baz@bar.com', 'secret')
    } catch {}
    const invalidEmailTime = convertHrtime(process.hrtime.bigint() - startTime)

    startTime = process.hrtime.bigint()
    try {
      await User.verifyCredentials('virk@adonisjs.com', 'supersecret')
    } catch {}
    const invalidPasswordTime = convertHrtime(process.hrtime.bigint() - startTime)

    /**
     * Same timing within the range of 10 milliseconds is acceptable
     */
    assert.isBelow(Math.abs(invalidPasswordTime.seconds - invalidEmailTime.seconds), 1)
    assert.isBelow(Math.abs(invalidPasswordTime.milliseconds - invalidEmailTime.milliseconds), 10)
  })

  test('throw error when uid or password values are missing', async ({ assert }) => {
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

    await assert.rejects(
      () => User.verifyCredentials('virk@adonisjs.com', ''),
      'Invalid user credentials'
    )
  })
})
