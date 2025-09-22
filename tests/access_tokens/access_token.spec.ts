/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { Secret, base64 } from '@adonisjs/core/helpers'

import { freezeTime } from '../helpers.js'
import { AccessToken } from '../../modules/access_tokens_guard/access_token.js'

test.group('AccessToken token | decode', () => {
  test('decode "{input}" as token')
    .with([
      {
        input: null,
        output: null,
      },
      {
        input: '',
        output: null,
      },
      {
        input: '..',
        output: null,
      },
      {
        input: 'foobar',
        output: null,
      },
      {
        input: 'foo.baz',
        output: null,
      },
      {
        input: 'foo_baz.foo',
        output: null,
      },
      {
        input: `api_bar.${base64.urlEncode('baz')}`,
        output: null,
      },
      {
        input: `api_${base64.urlEncode('baz')}.bar`,
        output: null,
      },
      {
        input: `api_${base64.urlEncode('baz')}.${base64.urlEncode('baz')}`,
        output: null,
      },
      {
        input: `auth_token_`,
        output: null,
      },
      {
        input: `auth_token_..`,
        output: null,
      },
      {
        input: `auth_token_foo.bar`,
        output: null,
      },
      {
        input: `auth_token_${base64.urlEncode('bar')}.${base64.urlEncode('baz')}`,
        output: {
          identifier: 'bar',
          secret: 'baz',
        },
      },
    ])
    .run(({ assert }, { input, output }) => {
      const decoded = AccessToken.decode('auth_token_', input as string)
      if (!decoded) {
        assert.deepEqual(decoded, output)
      } else {
        assert.deepEqual(
          { identifier: decoded.identifier, secret: decoded.secret.release() },
          output
        )
      }
    })
})

test.group('AccessToken token | create', () => {
  test('create a transient token', ({ assert }) => {
    freezeTime()
    const date = new Date()
    const expiresAt = new Date()
    expiresAt.setSeconds(date.getSeconds() + 60 * 20)

    const token = AccessToken.createTransientToken(1, 40, '20 mins')
    assert.equal(token.userId, 1)
    assert.exists(token.hash)
    assert.equal(token.expiresAt!.getTime(), expiresAt.getTime())
    assert.instanceOf(token.secret, Secret)
  })

  test('create a long-lived transient token', ({ assert }) => {
    freezeTime()
    const date = new Date()
    const expiresAt = new Date()
    expiresAt.setSeconds(date.getSeconds() + 60 * 20)

    const token = AccessToken.createTransientToken(1, 40)
    assert.equal(token.userId, 1)
    assert.exists(token.hash)
    assert.isUndefined(token.expiresAt)
    assert.instanceOf(token.secret, Secret)
  })

  test('create token from persisted information', ({ assert }) => {
    const createdAt = new Date()
    const updatedAt = new Date()
    const lastUsedAt = new Date()
    const expiresAt = new Date()
    expiresAt.setSeconds(createdAt.getSeconds() + 60 * 20)

    const token = new AccessToken({
      identifier: '12',
      name: 'foo',
      tokenableId: 1,
      type: 'auth_token',
      hash: '1234',
      createdAt,
      updatedAt,
      expiresAt,
      lastUsedAt,
    })

    assert.equal(token.identifier, '12')
    assert.equal(token.hash, '1234')
    assert.equal(token.tokenableId, 1)
    assert.equal(token.name, 'foo')
    assert.equal(token.createdAt.getTime(), createdAt.getTime())
    assert.equal(token.updatedAt.getTime(), updatedAt.getTime())
    assert.equal(token.expiresAt!.getTime(), expiresAt.getTime())
    assert.equal(token.lastUsedAt!.getTime(), lastUsedAt.getTime())
    assert.equal(token.type, 'auth_token')
    assert.deepEqual(token.abilities, ['*'])

    assert.isUndefined(token.value)
    assert.isFalse(token.isExpired())
  })

  test('create token with a secret', ({ assert }) => {
    const createdAt = new Date()
    const updatedAt = new Date()
    const expiresAt = new Date()
    expiresAt.setSeconds(createdAt.getSeconds() + 60 * 20)

    const transientToken = AccessToken.createTransientToken(1, 40, '20 mins')
    assert.throws(
      () =>
        new AccessToken({
          identifier: '12',
          tokenableId: 1,
          type: 'auth_token',
          name: null,
          hash: transientToken.hash,
          createdAt,
          updatedAt,
          expiresAt,
          lastUsedAt: null,
          secret: transientToken.secret,
        }),
      'Cannot compute token value without the prefix'
    )

    const token = new AccessToken({
      identifier: '12',
      tokenableId: 1,
      type: 'auth_token',
      name: null,
      hash: transientToken.hash,
      createdAt,
      updatedAt,
      expiresAt,
      lastUsedAt: null,
      prefix: 'oat_',
      secret: transientToken.secret,
    })

    const decoded = AccessToken.decode('oat_', token.value!.release())

    assert.equal(token.identifier, '12')
    assert.equal(token.tokenableId, 1)
    assert.equal(token.hash, transientToken.hash)
    assert.instanceOf(token.value, Secret)
    assert.isTrue(token.verify(transientToken.secret))
    assert.isTrue(token.verify(decoded!.secret))
    assert.equal(token.createdAt.getTime(), createdAt.getTime())
    assert.equal(token.updatedAt.getTime(), updatedAt.getTime())
    assert.equal(token.expiresAt!.getTime(), expiresAt.getTime())
    assert.isFalse(token.isExpired())
  })

  test('verify token hash', ({ assert }) => {
    const transientToken = AccessToken.createTransientToken(1, 40, '20 mins')

    const token = new AccessToken({
      identifier: '12',
      tokenableId: 1,
      type: 'auth_token',
      name: null,
      hash: transientToken.hash,
      createdAt: new Date(),
      updatedAt: new Date(),
      expiresAt: null,
      lastUsedAt: null,
      prefix: 'oat_',
      secret: transientToken.secret,
    })

    assert.isTrue(token.verify(transientToken.secret))
  })

  test('check if a token allows or denies an ability', ({ assert }) => {
    const transientToken = AccessToken.createTransientToken(1, 40, '20 mins')

    const token = new AccessToken({
      createdAt: new Date(),
      updatedAt: new Date(),
      expiresAt: transientToken.expiresAt || null,
      lastUsedAt: null,
      name: null,
      hash: transientToken.hash,
      identifier: '12',
      type: 'auth_token',
      tokenableId: transientToken.userId,
      abilities: ['*'],
    })
    const tokenWithPermissions = new AccessToken({
      createdAt: new Date(),
      updatedAt: new Date(),
      expiresAt: transientToken.expiresAt || null,
      lastUsedAt: null,
      name: null,
      hash: transientToken.hash,
      identifier: '12',
      type: 'auth_token',
      tokenableId: transientToken.userId,
      abilities: ['gist:read'],
    })

    assert.isTrue(token.allows('gist:read'))
    assert.isTrue(token.allows('gist:delete'))
    assert.isFalse(token.denies('gist:read'))
    assert.isFalse(token.denies('gist:delete'))
    assert.doesNotThrow(() => token.authorize('gist:read'))
    assert.doesNotThrow(() => token.authorize('gist:delete'))

    assert.isTrue(tokenWithPermissions.allows('gist:read'))
    assert.isFalse(tokenWithPermissions.allows('gist:delete'))
    assert.isFalse(tokenWithPermissions.denies('gist:read'))
    assert.isTrue(tokenWithPermissions.denies('gist:delete'))
    assert.doesNotThrow(() => tokenWithPermissions.authorize('gist:read'))
    assert.throws(() => tokenWithPermissions.authorize('gist:delete'), 'Unauthorized access')
  })

  test('convert token to JSON', ({ assert }) => {
    const createdAt = new Date()
    const updatedAt = new Date()
    const expiresAt = new Date()
    expiresAt.setSeconds(createdAt.getSeconds() + 60 * 20)

    const transientToken = AccessToken.createTransientToken(1, 40, '20 mins')
    const token = new AccessToken({
      identifier: '12',
      tokenableId: 1,
      type: 'auth_token',
      name: 'my token',
      hash: transientToken.hash,
      createdAt,
      updatedAt,
      expiresAt,
      lastUsedAt: null,
      prefix: 'oat_',
      secret: transientToken.secret,
    })
    const persistedToken = new AccessToken({
      identifier: '12',
      tokenableId: 1,
      type: 'auth_token',
      name: 'my token',
      hash: transientToken.hash,
      createdAt,
      updatedAt,
      expiresAt,
      lastUsedAt: null,
    })

    assert.deepEqual(token.toJSON(), {
      type: 'bearer',
      name: 'my token',
      token: token.value!.release(),
      abilities: ['*'],
      lastUsedAt: null,
      expiresAt: token.expiresAt,
    })
    assert.deepEqual(persistedToken.toJSON(), {
      type: 'bearer',
      name: 'my token',
      token: undefined,
      abilities: ['*'],
      lastUsedAt: null,
      expiresAt: token.expiresAt,
    })
  })
})
