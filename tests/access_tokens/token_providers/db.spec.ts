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

import { createDatabase, createTables, timeTravel } from '../../helpers.js'
import { AccessToken } from '../../../modules/access_tokens_guard/access_token.js'
import { DbAccessTokensProvider } from '../../../modules/access_tokens_guard/token_providers/db.js'

test.group('Access tokens provider | DB | create', () => {
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

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.authTokens.create(user)
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

  test('define token expiry', async ({ assert }) => {
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

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.authTokens.create(user, ['*'], { expiresIn: '20 mins' })
    assert.exists(token.identifier)
    assert.instanceOf(token, AccessToken)
    assert.equal(token.tokenableId, user.id)
    assert.deepEqual(token.abilities, ['*'])
    assert.isNull(token.lastUsedAt)
    assert.instanceOf(token.expiresAt, Date)
    assert.instanceOf(token.createdAt, Date)
    assert.instanceOf(token.updatedAt, Date)
    assert.isDefined(token.hash)
    assert.equal(token.type, 'auth_token')
    assert.isTrue(token.value!.release().startsWith('oat_'))

    assert.isFalse(token.isExpired())
    timeTravel(21 * 60)
    assert.isTrue(token.isExpired())
  })

  test('define token name', async ({ assert }) => {
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

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.authTokens.create(user, ['*'], {
      expiresIn: '20 mins',
      name: 'List projects',
    })
    assert.exists(token.identifier)
    assert.instanceOf(token, AccessToken)
    assert.equal(token.tokenableId, user.id)
    assert.deepEqual(token.abilities, ['*'])
    assert.isNull(token.lastUsedAt)
    assert.instanceOf(token.expiresAt, Date)
    assert.instanceOf(token.createdAt, Date)
    assert.instanceOf(token.updatedAt, Date)
    assert.isDefined(token.hash)
    assert.equal(token.name, 'List projects')
    assert.equal(token.type, 'auth_token')
    assert.isTrue(token.value!.release().startsWith('oat_'))

    assert.isFalse(token.isExpired())
    timeTravel(21 * 60)
    assert.isTrue(token.isExpired())
  })

  test('customize token type', async ({ assert }) => {
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

      static authTokens = DbAccessTokensProvider.forModel(User, {
        type: 'oat',
      })
    }

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.authTokens.create(user)
    assert.exists(token.identifier)
    assert.instanceOf(token, AccessToken)
    assert.equal(token.tokenableId, user.id)
    assert.deepEqual(token.abilities, ['*'])
    assert.isNull(token.lastUsedAt)
    assert.isNull(token.expiresAt)
    assert.instanceOf(token.createdAt, Date)
    assert.instanceOf(token.updatedAt, Date)
    assert.isDefined(token.hash)
    assert.equal(token.type, 'oat')
    assert.isTrue(token.value!.release().startsWith('oat_'))
  })

  test('customize token prefix', async ({ assert }) => {
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

      static authTokens = DbAccessTokensProvider.forModel(User, {
        prefix: 'pat_',
      })
    }

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.authTokens.create(user)
    assert.exists(token.identifier)
    assert.instanceOf(token, AccessToken)
    assert.equal(token.tokenableId, user.id)
    assert.deepEqual(token.abilities, ['*'])
    assert.isNull(token.lastUsedAt)
    assert.isNull(token.expiresAt)
    assert.instanceOf(token.createdAt, Date)
    assert.instanceOf(token.updatedAt, Date)
    assert.isDefined(token.hash)
    assert.isTrue(token.value!.release().startsWith('pat_'))
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const user = new User()
    await assert.rejects(
      () => User.authTokens.create(user),
      'Cannot use "User" model for managing access tokens. The value of column "id" is undefined or null'
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    await assert.rejects(
      // @ts-expect-error
      () => User.authTokens.create({}),
      'Invalid user object. It must be an instance of the "User" model'
    )
  })
})

test.group('Access tokens provider | DB | verify', () => {
  test('return access token when token value is valid', async ({ assert }) => {
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

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.authTokens.create(user, ['*'], { name: 'List projects' })
    const freshToken = await User.authTokens.verify(new Secret(token.value!.release()))

    assert.instanceOf(freshToken, AccessToken)
    assert.isUndefined(freshToken!.value)
    assert.equal(freshToken!.type, token.type)
    assert.equal(freshToken!.hash, token.hash)
    assert.equal(freshToken!.name, 'List projects')
    assert.closeTo(freshToken!.createdAt.getTime(), token.createdAt.getTime(), 10)
    assert.instanceOf(freshToken!.lastUsedAt, Date)
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.authTokens.create(user, ['*'], { expiresIn: '20 mins' })
    timeTravel(21 * 60)

    const freshToken = await User.authTokens.verify(new Secret(token.value!.release()))
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.authTokens.create(user)
    await User.authTokens.delete(user, token.identifier)

    const freshToken = await User.authTokens.verify(new Secret(token.value!.release()))
    assert.isNull(freshToken)
  })

  test('return null when token type mis-matches', async ({ assert }) => {
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
      static personalTokens = DbAccessTokensProvider.forModel(User, {
        type: 'personal_tokens',
      })
    }

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.authTokens.create(user)

    const freshToken = await User.personalTokens.verify(new Secret(token.value!.release()))
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const freshToken = await User.authTokens.verify(new Secret('foo.bar'))
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.authTokens.create(user)
    const value = token.value!.release()
    const [identifier] = value.split('.')

    const freshToken = await User.authTokens.verify(new Secret(`${identifier}.bar`))
    assert.isNull(freshToken)
  })
})

test.group('Access tokens provider | DB | find', () => {
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.authTokens.create(user)
    const freshToken = await User.authTokens.find(user, token.identifier)

    assert.exists(freshToken!.identifier)
    assert.instanceOf(freshToken, AccessToken)
    assert.equal(freshToken!.tokenableId, user.id)
    assert.deepEqual(freshToken!.abilities, ['*'])
    assert.isNull(freshToken!.lastUsedAt)
    assert.isNull(freshToken!.expiresAt)
    assert.instanceOf(freshToken!.createdAt, Date)
    assert.instanceOf(freshToken!.updatedAt, Date)
    assert.isDefined(freshToken!.hash)
    assert.equal(freshToken!.type, 'auth_token')
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.authTokens.create(user, ['*'], {
      expiresIn: '20 mins',
      name: 'List projects',
    })
    timeTravel(21 * 60)
    const freshToken = await User.authTokens.find(user, token.identifier)

    assert.exists(freshToken!.identifier)
    assert.instanceOf(freshToken, AccessToken)
    assert.equal(freshToken!.name, 'List projects')
    assert.equal(freshToken!.tokenableId, user.id)
    assert.deepEqual(freshToken!.abilities, ['*'])
    assert.isNull(freshToken!.lastUsedAt)
    assert.instanceOf(freshToken!.expiresAt, Date)
    assert.instanceOf(freshToken!.createdAt, Date)
    assert.instanceOf(freshToken!.updatedAt, Date)
    assert.isDefined(freshToken!.hash)
    assert.equal(freshToken!.type, 'auth_token')
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const freshToken = await User.authTokens.find(user, 2)
    assert.isNull(freshToken)
  })
})

test.group('Access tokens provider | DB | all', () => {
  test('get list of all tokens', async ({ assert }) => {
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

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    await User.authTokens.create(user, ['*'], { expiresIn: '20 mins', name: 'List projects' })
    await User.authTokens.create(user)
    timeTravel(21 * 60)
    const tokens = await User.authTokens.all(user)

    assert.lengthOf(tokens, 2)

    assert.exists(tokens[0].identifier)
    assert.instanceOf(tokens[0], AccessToken)
    assert.equal(tokens[0].tokenableId, user.id)
    assert.deepEqual(tokens[0].abilities, ['*'])
    assert.isNull(tokens[0].lastUsedAt)
    assert.isNull(tokens[0].expiresAt)
    assert.instanceOf(tokens[0].createdAt, Date)
    assert.instanceOf(tokens[0].updatedAt, Date)
    assert.isDefined(tokens[0].hash)
    assert.equal(tokens[0].type, 'auth_token')
    assert.isUndefined(tokens[0].value)
    assert.isFalse(tokens[0].isExpired())

    assert.exists(tokens[1].identifier)
    assert.instanceOf(tokens[1], AccessToken)
    assert.equal(tokens[1].tokenableId, user.id)
    assert.deepEqual(tokens[1].abilities, ['*'])
    assert.isNull(tokens[1].lastUsedAt)
    assert.instanceOf(tokens[1].expiresAt, Date)
    assert.instanceOf(tokens[1].createdAt, Date)
    assert.instanceOf(tokens[1].updatedAt, Date)
    assert.isDefined(tokens[1].hash)
    assert.equal(tokens[1].name, 'List projects')
    assert.equal(tokens[1].type, 'auth_token')
    assert.isUndefined(tokens[1].value)
    assert.isTrue(tokens[1].isExpired())
  })

  test('order tokens by last_used_at timestamp', async ({ assert }) => {
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

    const user = await User.create({
      email: 'virk@adonisjs.com',
      username: 'virk',
      password: 'secret',
    })

    const token = await User.authTokens.create(user, ['*'], { expiresIn: '20 mins' })
    await User.authTokens.create(user)

    /**
     * This will touch the last_used_at timestamp
     */
    assert.instanceOf(await User.authTokens.verify(token.value!), AccessToken)

    const tokens = await User.authTokens.all(user)

    assert.lengthOf(tokens, 2)

    assert.equal(tokens[0].identifier, token.identifier)
    assert.instanceOf(tokens[0], AccessToken)
    assert.equal(tokens[0].tokenableId, user.id)
    assert.deepEqual(tokens[0].abilities, ['*'])
    assert.instanceOf(tokens[0].lastUsedAt, Date)
    assert.instanceOf(tokens[0].expiresAt, Date)
    assert.instanceOf(tokens[0].createdAt, Date)
    assert.instanceOf(tokens[0].updatedAt, Date)
    assert.isDefined(tokens[0].hash)
    assert.equal(tokens[0].type, 'auth_token')
    assert.isUndefined(tokens[0].value)
    assert.isFalse(tokens[0].isExpired())
  })
})
