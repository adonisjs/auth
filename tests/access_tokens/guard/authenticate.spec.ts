/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { HttpContextFactory } from '@adonisjs/core/factories/http'

import { E_UNAUTHORIZED_ACCESS } from '../../../src/errors.js'
import { createEmitter, pEvent, timeTravel } from '../../helpers.js'
import { AccessTokensGuard } from '../../../modules/access_tokens_guard/guard.js'
import type { AccessTokensGuardEvents } from '../../../modules/access_tokens_guard/types.js'
import {
  type AccessTokensFakeUser,
  AccessTokensFakeUserProvider,
} from '../../../factories/access_tokens/main.js'
import { AccessToken } from '../../../modules/access_tokens_guard/access_token.js'

test.group('Access tokens guard | authenticate', () => {
  test('return user when access token is valid', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<AccessTokensGuardEvents<AccessTokensFakeUser>>()
    const userProvider = new AccessTokensFakeUserProvider()

    const guard = new AccessTokensGuard('api', ctx, emitter, userProvider)
    const user = await userProvider.findById(1)
    const token = await userProvider.createToken(user!.getOriginal())

    ctx.request.request.headers.authorization = `Bearer ${token.value!.release()}`
    const [attempted, succeeded, authenticatedUser] = await Promise.all([
      pEvent(emitter, 'access_tokens_auth:authentication_attempted'),
      pEvent(emitter, 'access_tokens_auth:authentication_succeeded'),
      guard.authenticate(),
    ])

    expectTypeOf(authenticatedUser).toEqualTypeOf<
      AccessTokensFakeUser & { currentAccessToken: AccessToken }
    >()
    expectTypeOf(guard.user).toEqualTypeOf<
      (AccessTokensFakeUser & { currentAccessToken: AccessToken }) | undefined
    >()
    assert.equal(attempted!.guardName, 'api')
    assert.equal(succeeded!.guardName, 'api')
    assert.equal(succeeded!.token.identifier, token.identifier)
    assert.property(guard.user, 'currentAccessToken')
    assert.instanceOf(guard.user!.currentAccessToken, AccessToken)

    assert.deepEqual(guard.user, authenticatedUser)
    assert.deepEqual(guard.getUserOrFail(), authenticatedUser)
    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when authorization header is missing', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokensFakeUserProvider()

    const guard = new AccessTokensGuard('api', ctx, emitter, userProvider)

    const [attempted, failed, authenticationResult] = await Promise.allSettled([
      pEvent(emitter, 'access_tokens_auth:authentication_attempted'),
      pEvent(emitter, 'access_tokens_auth:authentication_failed'),
      guard.authenticate(),
    ])

    assert.equal(attempted!.status, 'fulfilled')
    assert.equal(failed!.status, 'fulfilled')
    if (failed!.status === 'fulfilled') {
      assert.equal(failed!.value.error.message, 'Unauthorized access')
    }

    assert.equal(authenticationResult!.status, 'rejected')
    if (authenticationResult!.status === 'rejected') {
      assert.instanceOf(authenticationResult!.reason, E_UNAUTHORIZED_ACCESS)
    }

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when authorization header does not have a bearer token', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokensFakeUserProvider()
    ctx.request.request.headers.authorization = 'foo bar'

    const guard = new AccessTokensGuard('api', ctx, emitter, userProvider)
    const [attempted, failed, authenticationResult] = await Promise.allSettled([
      pEvent(emitter, 'access_tokens_auth:authentication_attempted'),
      pEvent(emitter, 'access_tokens_auth:authentication_failed'),
      guard.authenticate(),
    ])

    assert.equal(attempted!.status, 'fulfilled')
    assert.equal(failed!.status, 'fulfilled')
    if (failed!.status === 'fulfilled') {
      assert.equal(failed!.value.error.message, 'Unauthorized access')
    }

    assert.equal(authenticationResult!.status, 'rejected')
    if (authenticationResult!.status === 'rejected') {
      assert.instanceOf(authenticationResult!.reason, E_UNAUTHORIZED_ACCESS)
    }

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when authorization header has an empty bearer token', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokensFakeUserProvider()
    ctx.request.request.headers.authorization = 'Bearer '

    const guard = new AccessTokensGuard('api', ctx, emitter, userProvider)
    const [attempted, failed, authenticationResult] = await Promise.allSettled([
      pEvent(emitter, 'access_tokens_auth:authentication_attempted'),
      pEvent(emitter, 'access_tokens_auth:authentication_failed'),
      guard.authenticate(),
    ])

    assert.equal(attempted!.status, 'fulfilled')
    assert.equal(failed!.status, 'fulfilled')
    if (failed!.status === 'fulfilled') {
      assert.equal(failed!.value.error.message, 'Unauthorized access')
    }

    assert.equal(authenticationResult!.status, 'rejected')
    if (authenticationResult!.status === 'rejected') {
      assert.instanceOf(authenticationResult!.reason, E_UNAUTHORIZED_ACCESS)
    }

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when bearer token is invalid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokensFakeUserProvider()
    ctx.request.request.headers.authorization = 'Bearer helloworld'

    const guard = new AccessTokensGuard('api', ctx, emitter, userProvider)
    const [attempted, failed, authenticationResult] = await Promise.allSettled([
      pEvent(emitter, 'access_tokens_auth:authentication_attempted'),
      pEvent(emitter, 'access_tokens_auth:authentication_failed'),
      guard.authenticate(),
    ])

    assert.equal(attempted!.status, 'fulfilled')
    assert.equal(failed!.status, 'fulfilled')
    if (failed!.status === 'fulfilled') {
      assert.equal(failed!.value.error.message, 'Unauthorized access')
    }

    assert.equal(authenticationResult!.status, 'rejected')
    if (authenticationResult!.status === 'rejected') {
      assert.instanceOf(authenticationResult!.reason, E_UNAUTHORIZED_ACCESS)
    }

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when bearer token does not exist', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokensFakeUserProvider()
    const user = await userProvider.findById(1)
    const token = await userProvider.createToken(user!.getOriginal())
    userProvider.deleteToken(token.identifier)

    ctx.request.request.headers.authorization = `Bearer ${token.value!.release()}`
    const guard = new AccessTokensGuard('api', ctx, emitter, userProvider)
    const [attempted, failed, authenticationResult] = await Promise.allSettled([
      pEvent(emitter, 'access_tokens_auth:authentication_attempted'),
      pEvent(emitter, 'access_tokens_auth:authentication_failed'),
      guard.authenticate(),
    ])

    assert.equal(attempted!.status, 'fulfilled')
    assert.equal(failed!.status, 'fulfilled')
    if (failed!.status === 'fulfilled') {
      assert.equal(failed!.value.error.message, 'Unauthorized access')
    }

    assert.equal(authenticationResult!.status, 'rejected')
    if (authenticationResult!.status === 'rejected') {
      assert.instanceOf(authenticationResult!.reason, E_UNAUTHORIZED_ACCESS)
    }

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when token user is missing', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokensFakeUserProvider()
    const user = await userProvider.findById(1)
    const originalUser = { ...user!.getOriginal() }

    /**
     * Mutating id to point to a non-existing user
     */
    originalUser.id = 10

    const token = await userProvider.createToken(originalUser)

    ctx.request.request.headers.authorization = `Bearer ${token.value!.release()}`
    const guard = new AccessTokensGuard('api', ctx, emitter, userProvider)
    const [attempted, failed, authenticationResult] = await Promise.allSettled([
      pEvent(emitter, 'access_tokens_auth:authentication_attempted'),
      pEvent(emitter, 'access_tokens_auth:authentication_failed'),
      guard.authenticate(),
    ])

    assert.equal(attempted!.status, 'fulfilled')
    assert.equal(failed!.status, 'fulfilled')
    if (failed!.status === 'fulfilled') {
      assert.equal(failed!.value.error.message, 'Unauthorized access')
    }

    assert.equal(authenticationResult!.status, 'rejected')
    if (authenticationResult!.status === 'rejected') {
      assert.instanceOf(authenticationResult!.reason, E_UNAUTHORIZED_ACCESS)
    }

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when bearer token has been expired', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokensFakeUserProvider()
    const user = await userProvider.findById(1)
    const token = await userProvider.createToken(user!.getOriginal(), ['*'], {
      expiresIn: '20 mins',
    })
    timeTravel(21 * 60)

    ctx.request.request.headers.authorization = `Bearer ${token.value!.release()}`
    const guard = new AccessTokensGuard('api', ctx, emitter, userProvider)
    const [attempted, failed, authenticationResult] = await Promise.allSettled([
      pEvent(emitter, 'access_tokens_auth:authentication_attempted'),
      pEvent(emitter, 'access_tokens_auth:authentication_failed'),
      guard.authenticate(),
    ])

    assert.equal(attempted!.status, 'fulfilled')
    assert.equal(failed!.status, 'fulfilled')
    if (failed!.status === 'fulfilled') {
      assert.equal(failed!.value.error.message, 'Unauthorized access')
    }

    assert.equal(authenticationResult!.status, 'rejected')
    if (authenticationResult!.status === 'rejected') {
      assert.instanceOf(authenticationResult!.reason, E_UNAUTHORIZED_ACCESS)
    }

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('multiple calls to authenticate method should be a noop', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokensFakeUserProvider()

    const guard = new AccessTokensGuard('api', ctx, emitter, userProvider)
    const user = await userProvider.findById(1)
    const token = await userProvider.createToken(user!.getOriginal(), ['*'], {
      expiresIn: '20 mins',
    })
    await assert.rejects(() => guard.authenticate(), 'Unauthorized access')

    ctx.request.request.headers.authorization = `Bearer ${token.value!.release()}`

    /**
     * Even though the token exists now, the authenticate
     * method will use previous state
     */
    await assert.rejects(() => guard.authenticate(), 'Unauthorized access')

    assert.isUndefined(guard.user)
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })
})

test.group('Access token guard | check', () => {
  test('return true when access token is valid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokensFakeUserProvider()

    const guard = new AccessTokensGuard('api', ctx, emitter, userProvider)
    const user = await userProvider.findById(1)
    const token = await userProvider.createToken(user!.getOriginal())

    ctx.request.request.headers.authorization = `Bearer ${token.value!.release()}`
    const isLoggedIn = await guard.check()

    assert.isTrue(isLoggedIn)
    assert.deepEqual(guard.user, {
      id: 1,
      email: 'virk@adonisjs.com',
      password: 'secret',
      currentAccessToken: await userProvider.verifyToken(token.value!),
    })
    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('return false when access token is invalid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokensFakeUserProvider()

    const guard = new AccessTokensGuard('api', ctx, emitter, userProvider)
    const user = await userProvider.findById(1)
    const token = await userProvider.createToken(user!.getOriginal())
    userProvider.deleteToken(token.identifier)

    ctx.request.request.headers.authorization = `Bearer ${token.value!.release()}`
    const isLoggedIn = await guard.check()

    assert.isFalse(isLoggedIn)
    assert.isUndefined(guard.user)
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })
})

test.group('Access tokens guard | authenticateAsClient', () => {
  test('create bearer token for the given user', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<AccessTokensGuardEvents<AccessTokensFakeUser>>()
    const userProvider = new AccessTokensFakeUserProvider()

    const guard = new AccessTokensGuard('api', ctx, emitter, userProvider)
    const user = await userProvider.findById(1)
    const response = await guard.authenticateAsClient(user!.getOriginal())

    assert.property(response.headers, 'authorization')
    assert.match(response.headers!.authorization, /Bearer oat_[a-zA-Z0-9]+\.[a-zA-Z0-9]+/)
  })
})

test.group('Access tokens guard | createToken', () => {
  test('create bearer token for the given user', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<AccessTokensGuardEvents<AccessTokensFakeUser>>()
    const userProvider = new AccessTokensFakeUserProvider()

    const guard = new AccessTokensGuard('api', ctx, emitter, userProvider)
    const user = await userProvider.findById(1)
    const token = await guard.createToken(user!.getOriginal(), ['list.users'], {
      expiresIn: 3600,
      name: 'sign_in',
    })
    assert.instanceOf(token, AccessToken)
    assert.equal(token.tokenableId, user?.getId())
    assert.deepEqual(token.abilities, ['list.users'])
    assert.equal(token.name, 'sign_in')
    assert.closeTo(token.expiresAt!.getTime(), new Date().getTime() + 3600 * 1000, 100)
    assert.match(token.value!.release(), /oat_[a-zA-Z0-9]+\.[a-zA-Z0-9]+/)
  })
})
