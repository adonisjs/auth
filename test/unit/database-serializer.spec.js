'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

require('@adonisjs/lucid/lib/iocResolver').setFold(require('@adonisjs/fold'))

const test = require('japa')
const { ioc } = require('@adonisjs/fold')

const { database: DatabaseSerializer } = require('../../src/Serializers')
const setup = require('./setup')

test.group('Serializers - Database', (group) => {
  setup.databaseHook(group)
  setup.hashHook(group)

  test('generate correct query to fetch user by id', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id'
    }

    const db = new DatabaseSerializer()
    db.setConfig(config)

    let authQuery
    db.query((builder) => {
      builder.on('query', (query) => (authQuery = query))
    })

    await db.findById(1)

    assert.equal(authQuery.sql, 'select * from "users" where "id" = ? limit ?')
    assert.deepEqual(authQuery.bindings, [1, 1])
  })

  test('generate correct query to fetch user by uid', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id'
    }

    const db = new DatabaseSerializer()
    db.setConfig(config)

    let authQuery
    db.query((builder) => {
      builder.on('query', (query) => (authQuery = query))
    })

    await db.findByUid('foo@bar.com')

    assert.equal(authQuery.sql, 'select * from "users" where "email" = ? limit ?')
    assert.deepEqual(authQuery.bindings, ['foo@bar.com', 1])
  })

  test('return false when unable to match password', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id'
    }

    const db = new DatabaseSerializer(ioc.use('Hash'))
    db.setConfig(config)
    await ioc.use('Database').table('users').insert({ email: 'foo@bar.com', password: 'secret' })

    const verified = await db.validateCredentails({ id: 1, password: 'secret' }, 'foo')
    assert.isFalse(verified)
  })

  test('return false when there is no password is user payload', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id'
    }

    const db = new DatabaseSerializer(ioc.use('Hash'))
    db.setConfig(config)

    const verified = await db.validateCredentails({ id: 1 }, 'foo')
    assert.isFalse(verified)
  })

  test('return true when password matches', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id'
    }

    const db = new DatabaseSerializer(ioc.use('Hash'))
    db.setConfig(config)
    await ioc.use('Database').table('users').insert({ email: 'foo@bar.com', password: 'secret' })

    const verified = await db.validateCredentails({ id: 1, password: 'secret' }, 'secret')
    assert.isTrue(verified)
  })

  test('return add runtime constraints to query builder', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id'
    }

    const db = new DatabaseSerializer()
    db.setConfig(config)

    let authQuery
    await db.query((builder) => {
      builder.on('query', (query) => (authQuery = query))
      builder.where('is_active', true)
    }).findById(1)

    assert.equal(authQuery.sql, 'select * from "users" where "is_active" = ? and "id" = ? limit ?')
  })

  test('make correct findByToken query', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id',
      tokensTable: 'tokens',
      foreignKey: 'user_id'
    }

    const db = new DatabaseSerializer()
    db.setConfig(config)

    let authQuery
    db.query((builder) => {
      builder.on('query', (query) => (authQuery = query))
    })

    await db.findByToken('20', 'remember_token')
    assert.equal(
      authQuery.sql,
      'select * from "users" where exists (select * from "tokens" where "token" = ? and "type" = ? and "is_revoked" = ? and users.id = tokens.user_id) limit ?'
    )
    assert.deepEqual(authQuery.bindings, ['20', 'remember_token', false, 1])
  })

  test('save token for a given user', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id',
      tokensTable: 'tokens',
      foreignKey: 'user_id'
    }

    const db = new DatabaseSerializer()
    db.setConfig(config)

    let tokensQuery = null
    db.query((builder) => {
      builder.on('query', (query) => (tokensQuery = query))
    })

    await ioc.use('Database').table('users').insert({ email: 'foo@bar.com', password: 'secret' })
    await db.saveToken({ id: 1 }, '20', 'remember_token')
    assert.equal(
      tokensQuery.sql,
      'insert into "tokens" ("is_revoked", "token", "type", "user_id") values (?, ?, ?, ?)'
    )
    assert.deepEqual(tokensQuery.bindings, [false, '20', 'remember_token', 1])
  })

  test('remove single token for a given user', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id',
      tokensTable: 'tokens',
      foreignKey: 'user_id'
    }

    const db = new DatabaseSerializer()
    db.setConfig(config)

    let tokensQuery = null
    db.query((builder) => {
      builder.on('query', (query) => (tokensQuery = query))
    })

    await db.revokeTokens({ id: 1 }, '20')
    assert.equal(
      tokensQuery.sql,
      'update "tokens" set "is_revoked" = ? where "token" in (?) and "user_id" = ?'
    )
    assert.deepEqual(tokensQuery.bindings, [true, '20', 1])
  })

  test('remove all tokens for a given user', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id',
      tokensTable: 'tokens',
      foreignKey: 'user_id'
    }

    const db = new DatabaseSerializer()
    db.setConfig(config)

    let tokensQuery = null
    db.query((builder) => {
      builder.on('query', (query) => (tokensQuery = query))
    })

    await db.revokeTokens({ id: 1 })
    assert.equal(
      tokensQuery.sql,
      'update "tokens" set "is_revoked" = ? where "user_id" = ?'
    )
    assert.deepEqual(tokensQuery.bindings, [true, 1])
  })

  test('remove multiple tokens for a given user', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id',
      tokensTable: 'tokens',
      foreignKey: 'user_id'
    }

    const db = new DatabaseSerializer()
    db.setConfig(config)

    let tokensQuery = null
    db.query((builder) => {
      builder.on('query', (query) => (tokensQuery = query))
    })

    await db.revokeTokens({ id: 1 }, ['20', '30'])
    assert.equal(
      tokensQuery.sql,
      'update "tokens" set "is_revoked" = ? where "token" in (?, ?) and "user_id" = ?'
    )
    assert.deepEqual(tokensQuery.bindings, [true, '20', '30', 1])
  })

  test('remove all but not mentioned tokens', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id',
      tokensTable: 'tokens',
      foreignKey: 'user_id'
    }

    const db = new DatabaseSerializer()
    db.setConfig(config)

    let tokensQuery = null
    db.query((builder) => {
      builder.on('query', (query) => (tokensQuery = query))
    })

    await db.revokeTokens({ id: 1 }, ['20', '30'], true)
    assert.equal(
      tokensQuery.sql,
      'update "tokens" set "is_revoked" = ? where "token" not in (?, ?) and "user_id" = ?'
    )
    assert.deepEqual(tokensQuery.bindings, [true, '20', '30', 1])
  })

  test('query for user tokens', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id',
      tokensTable: 'tokens',
      foreignKey: 'user_id'
    }

    const db = new DatabaseSerializer()
    db.setConfig(config)

    let tokensQuery = null
    db.query((builder) => {
      builder.on('query', (query) => (tokensQuery = query))
    })

    await db.listTokens({ id: 1 }, 'api_tokens')
    assert.equal(tokensQuery.sql, 'select * from "tokens" where "type" = ? and "is_revoked" = ? and "user_id" = ?')
    assert.deepEqual(tokensQuery.bindings, ['api_tokens', false, 1])
  })

  test('delete single token for a given user', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id',
      tokensTable: 'tokens',
      foreignKey: 'user_id'
    }

    const db = new DatabaseSerializer()
    db.setConfig(config)

    let tokensQuery = null
    db.query((builder) => {
      builder.on('query', (query) => (tokensQuery = query))
    })

    await db.deleteTokens({ id: 1 }, '20')
    assert.equal(
      tokensQuery.sql,
      'delete from "tokens" where "token" in (?) and "user_id" = ?'
    )
    assert.deepEqual(tokensQuery.bindings, ['20', 1])
  })

  test('delete all tokens for a given user', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id',
      tokensTable: 'tokens',
      foreignKey: 'user_id'
    }

    const db = new DatabaseSerializer()
    db.setConfig(config)

    let tokensQuery = null
    db.query((builder) => {
      builder.on('query', (query) => (tokensQuery = query))
    })

    await db.deleteTokens({ id: 1 })
    assert.equal(
      tokensQuery.sql,
      'delete from "tokens" where "user_id" = ?'
    )
    assert.deepEqual(tokensQuery.bindings, [1])
  })

  test('delete multiple tokens for a given user', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id',
      tokensTable: 'tokens',
      foreignKey: 'user_id'
    }

    const db = new DatabaseSerializer()
    db.setConfig(config)

    let tokensQuery = null
    db.query((builder) => {
      builder.on('query', (query) => (tokensQuery = query))
    })

    await db.deleteTokens({ id: 1 }, ['20', '30'])
    assert.equal(
      tokensQuery.sql,
      'delete from "tokens" where "token" in (?, ?) and "user_id" = ?'
    )
    assert.deepEqual(tokensQuery.bindings, ['20', '30', 1])
  })

  test('delete all but not mentioned tokens', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id',
      tokensTable: 'tokens',
      foreignKey: 'user_id'
    }

    const db = new DatabaseSerializer()
    db.setConfig(config)

    let tokensQuery = null
    db.query((builder) => {
      builder.on('query', (query) => (tokensQuery = query))
    })

    await db.deleteTokens({ id: 1 }, ['20', '30'], true)
    assert.equal(
      tokensQuery.sql,
      'delete from "tokens" where "token" not in (?, ?) and "user_id" = ?'
    )
    assert.deepEqual(tokensQuery.bindings, ['20', '30', 1])
  })

  test('make fake response', async (assert) => {
    const config = {
      uid: 'email',
      password: 'password',
      table: 'users',
      primaryKey: 'id',
      tokensTable: 'tokens',
      foreignKey: 'user_id'
    }

    const db = new DatabaseSerializer()
    db.setConfig(config)
    assert.deepEqual(db.fakeResult(), [])
  })
})
