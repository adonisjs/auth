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

import { createDatabase, createTables, timeTravel } from '../../helpers.ts'
import { RememberMeToken } from '../../../modules/session_guard/remember_me_token.ts'
import { DbRememberMeTokensProvider } from '../../../modules/session_guard/token_providers/db.ts'

test.group('RememberMe tokens provider | DB | create', () => {
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

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.rememberMeTokens.create(user, '20 mins')
    assert.exists(token.identifier)
    assert.instanceOf(token, RememberMeToken)
    assert.equal(token.tokenableId, user.id)
    assert.instanceOf(token.expiresAt, Date)
    assert.instanceOf(token.createdAt, Date)
    assert.instanceOf(token.updatedAt, Date)
    assert.isDefined(token.hash)
    assert.exists(token.value)

    assert.isFalse(token.isExpired())
    timeTravel(21 * 60)
    assert.isTrue(token.isExpired())
  })

  test('throw error when user id is missing', async ({ assert }) => {
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

    const user = new User()
    await assert.rejects(
      () => User.rememberMeTokens.create(user, '20 mins'),
      'Cannot use "User" model for managing remember me tokens. The value of column "id" is undefined or null'
    )
  })

  test('throw error when user is not an instance of the associated model', async ({ assert }) => {
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

    await assert.rejects(
      // @ts-expect-error
      () => User.rememberMeTokens.create({}, '20 mins'),
      'Invalid user object. It must be an instance of the "User" model'
    )
  })
})

test.group('RememberMe tokens provider | DB | verify', () => {
  test('return remember me token when token value is valid', async ({ assert }) => {
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

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.rememberMeTokens.create(user, '20 mins')
    const freshToken = await User.rememberMeTokens.verify(new Secret(token.value!.release()))

    assert.instanceOf(freshToken, RememberMeToken)
    assert.isUndefined(freshToken!.value)
    assert.equal(freshToken!.hash, token.hash)
    assert.closeTo(freshToken!.createdAt.getTime(), token.createdAt.getTime(), 10)
    assert.closeTo(freshToken!.expiresAt.getTime(), token.expiresAt.getTime(), 10)
  })

  test('return null when token has been expired', async ({ assert }) => {
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

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.rememberMeTokens.create(user, '20 mins')
    timeTravel(21 * 60)

    const freshToken = await User.rememberMeTokens.verify(new Secret(token.value!.release()))
    assert.isNull(freshToken)
  })

  test('return null when token does not exists', async ({ assert }) => {
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

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.rememberMeTokens.create(user, '20 mins')
    await User.rememberMeTokens.delete(user, token.identifier)

    const freshToken = await User.rememberMeTokens.verify(new Secret(token.value!.release()))
    assert.isNull(freshToken)
  })

  test('return null when token value is invalid', async ({ assert }) => {
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

    const freshToken = await User.rememberMeTokens.verify(new Secret('foo.bar'))
    assert.isNull(freshToken)
  })

  test('return null when token secret is invalid', async ({ assert }) => {
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

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.rememberMeTokens.create(user, '20 mins')
    const value = token.value!.release()
    const [identifier] = value.split('.')

    const freshToken = await User.rememberMeTokens.verify(new Secret(`${identifier}.bar`))
    assert.isNull(freshToken)
  })
})

test.group('RememberMe tokens provider | DB | find', () => {
  test('get token by id', async ({ assert }) => {
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

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.rememberMeTokens.create(user, '20 mins')
    const freshToken = await User.rememberMeTokens.find(user, token.identifier)

    assert.exists(freshToken!.identifier)
    assert.instanceOf(freshToken, RememberMeToken)
    assert.equal(freshToken!.tokenableId, user.id)
    assert.instanceOf(freshToken!.expiresAt, Date)
    assert.instanceOf(freshToken!.createdAt, Date)
    assert.instanceOf(freshToken!.updatedAt, Date)
    assert.isDefined(freshToken!.hash)
    assert.isUndefined(freshToken!.value)
  })

  test('return expired tokens as well', async ({ assert }) => {
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

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.rememberMeTokens.create(user, '20 mins')
    timeTravel(21 * 60)
    const freshToken = await User.rememberMeTokens.find(user, token.identifier)

    assert.exists(freshToken!.identifier)
    assert.instanceOf(freshToken, RememberMeToken)
    assert.equal(freshToken!.tokenableId, user.id)
    assert.instanceOf(freshToken!.expiresAt, Date)
    assert.instanceOf(freshToken!.createdAt, Date)
    assert.instanceOf(freshToken!.updatedAt, Date)
    assert.isDefined(freshToken!.hash)
    assert.isUndefined(freshToken!.value)
    assert.isTrue(freshToken!.isExpired())
  })

  test('return null when token is missing', async ({ assert }) => {
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

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const freshToken = await User.rememberMeTokens.find(user, 2)
    assert.isNull(freshToken)
  })
})

test.group('RememberMe tokens provider | DB | all', () => {
  test('get list of all tokens order by id', async ({ assert }) => {
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

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    await User.rememberMeTokens.create(user, '20 mins')
    await User.rememberMeTokens.create(user, '2 years')
    timeTravel(21 * 60)
    const tokens = await User.rememberMeTokens.all(user)

    assert.lengthOf(tokens, 2)

    assert.exists(tokens[0].identifier)
    assert.instanceOf(tokens[0], RememberMeToken)
    assert.equal(tokens[0].tokenableId, user.id)
    assert.instanceOf(tokens[0].expiresAt, Date)
    assert.instanceOf(tokens[0].createdAt, Date)
    assert.instanceOf(tokens[0].updatedAt, Date)
    assert.isDefined(tokens[0].hash)
    assert.isUndefined(tokens[0].value)
    assert.isFalse(tokens[0].isExpired())

    assert.exists(tokens[1].identifier)
    assert.equal(tokens[1].tokenableId, user.id)
    assert.instanceOf(tokens[1].expiresAt, Date)
    assert.instanceOf(tokens[1].createdAt, Date)
    assert.instanceOf(tokens[1].updatedAt, Date)
    assert.isDefined(tokens[1].hash)
    assert.isUndefined(tokens[1].value)
    assert.isTrue(tokens[1].isExpired())
  })
})

test.group('RememberMe tokens provider | DB | recycle', () => {
  test('delete token on recycle', async ({ assert }) => {
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

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.rememberMeTokens.create(user, '20 mins')
    const freshToken = await User.rememberMeTokens.recycle(user, token.identifier, '20 mins')

    assert.isNull(await User.rememberMeTokens.find(user, token.identifier))
    assert.isNotNull(await User.rememberMeTokens.find(user, freshToken.identifier))
  })
})
