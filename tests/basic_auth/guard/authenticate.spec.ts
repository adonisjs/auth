/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { base64 } from '@adonisjs/core/helpers'
import { HttpContextFactory } from '@adonisjs/core/factories/http'

import { createEmitter, pEvent } from '../../helpers.ts'
import { E_UNAUTHORIZED_ACCESS } from '../../../src/errors.ts'
import { BasicAuthGuard } from '../../../modules/basic_auth_guard/guard.ts'
import { type BasicAuthGuardEvents } from '../../../modules/basic_auth_guard/types.ts'
import {
  type BasicAuthFakeUser,
  BasicAuthFakeUserProvider,
} from '../../../factories/basic_auth/main.ts'

test.group('Basic auth guard | authenticate', () => {
  test('return user when credentials are valid', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<BasicAuthGuardEvents<BasicAuthFakeUser>>()
    const userProvider = new BasicAuthFakeUserProvider()

    const guard = new BasicAuthGuard('basic', ctx, emitter, userProvider)

    ctx.request.request.headers.authorization = `Basic ${base64.encode('virk@adonisjs.com:secret')}`
    const [attempted, succeeded, authenticatedUser] = await Promise.all([
      pEvent(emitter, 'basic_auth:authentication_attempted'),
      pEvent(emitter, 'basic_auth:authentication_succeeded'),
      guard.authenticate(),
    ])

    expectTypeOf(authenticatedUser).toEqualTypeOf<BasicAuthFakeUser>()
    expectTypeOf(guard.user).toEqualTypeOf<BasicAuthFakeUser | undefined>()
    assert.equal(attempted!.guardName, 'basic')
    assert.equal(succeeded!.guardName, 'basic')

    assert.deepEqual(guard.user, authenticatedUser)
    assert.deepEqual(guard.getUserOrFail(), authenticatedUser)
    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when authorization header is missing', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<BasicAuthGuardEvents<BasicAuthFakeUser>>()
    const userProvider = new BasicAuthFakeUserProvider()

    const guard = new BasicAuthGuard('basic', ctx, emitter, userProvider)
    const [attempted, failed, authenticationResult] = await Promise.allSettled([
      pEvent(emitter, 'basic_auth:authentication_attempted'),
      pEvent(emitter, 'basic_auth:authentication_failed'),
      guard.authenticate(),
    ])

    assert.equal(attempted!.status, 'fulfilled')
    assert.equal(failed!.status, 'fulfilled')
    if (failed!.status === 'fulfilled') {
      assert.equal(failed!.value!.error.message, 'Invalid basic auth credentials')
    }

    assert.equal(authenticationResult!.status, 'rejected')
    if (authenticationResult!.status === 'rejected') {
      assert.instanceOf(authenticationResult!.reason, E_UNAUTHORIZED_ACCESS)
    }

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Invalid basic auth credentials')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when authorization header is invalid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<BasicAuthGuardEvents<BasicAuthFakeUser>>()
    const userProvider = new BasicAuthFakeUserProvider()

    ctx.request.request.headers.authorization = 'foo bar'
    const guard = new BasicAuthGuard('basic', ctx, emitter, userProvider)
    const [attempted, failed, authenticationResult] = await Promise.allSettled([
      pEvent(emitter, 'basic_auth:authentication_attempted'),
      pEvent(emitter, 'basic_auth:authentication_failed'),
      guard.authenticate(),
    ])

    assert.equal(attempted!.status, 'fulfilled')
    assert.equal(failed!.status, 'fulfilled')
    if (failed!.status === 'fulfilled') {
      assert.equal(failed!.value!.error.message, 'Invalid basic auth credentials')
    }

    assert.equal(authenticationResult!.status, 'rejected')
    if (authenticationResult!.status === 'rejected') {
      assert.instanceOf(authenticationResult!.reason, E_UNAUTHORIZED_ACCESS)
    }

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Invalid basic auth credentials')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when authorization credentials are empty', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<BasicAuthGuardEvents<BasicAuthFakeUser>>()
    const userProvider = new BasicAuthFakeUserProvider()

    ctx.request.request.headers.authorization = `Basic ${base64.encode('')}`
    const guard = new BasicAuthGuard('basic', ctx, emitter, userProvider)
    const [attempted, failed, authenticationResult] = await Promise.allSettled([
      pEvent(emitter, 'basic_auth:authentication_attempted'),
      pEvent(emitter, 'basic_auth:authentication_failed'),
      guard.authenticate(),
    ])

    assert.equal(attempted!.status, 'fulfilled')
    assert.equal(failed!.status, 'fulfilled')
    if (failed!.status === 'fulfilled') {
      assert.equal(failed!.value!.error.message, 'Invalid basic auth credentials')
    }

    assert.equal(authenticationResult!.status, 'rejected')
    if (authenticationResult!.status === 'rejected') {
      assert.instanceOf(authenticationResult!.reason, E_UNAUTHORIZED_ACCESS)
    }

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Invalid basic auth credentials')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('multiple calls to authenticate method should be a noop', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<BasicAuthGuardEvents<BasicAuthFakeUser>>()
    const userProvider = new BasicAuthFakeUserProvider()

    const guard = new BasicAuthGuard('basic', ctx, emitter, userProvider)
    await assert.rejects(() => guard.authenticate(), 'Invalid basic auth credentials')

    ctx.request.request.headers.authorization = `Basic ${base64.encode('virk@adonisjs.com:secret')}`

    /**
     * Even though the credentials exists now, the authenticate
     * method will use previous state
     */
    await assert.rejects(() => guard.authenticate(), 'Invalid basic auth credentials')

    assert.isUndefined(guard.user)
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })
})

test.group('Basic auth guard | check', () => {
  test('return true when credentials are valid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<BasicAuthGuardEvents<BasicAuthFakeUser>>()
    const userProvider = new BasicAuthFakeUserProvider()

    const guard = new BasicAuthGuard('basic', ctx, emitter, userProvider)

    ctx.request.request.headers.authorization = `Basic ${base64.encode('virk@adonisjs.com:secret')}`
    const isLoggedIn = await guard.check()

    assert.isTrue(isLoggedIn)
    assert.deepEqual(guard.user, {
      id: 1,
      email: 'virk@adonisjs.com',
      password: 'secret',
    })
    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('return false when credentials are valid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<BasicAuthGuardEvents<BasicAuthFakeUser>>()
    const userProvider = new BasicAuthFakeUserProvider()

    const guard = new BasicAuthGuard('basic', ctx, emitter, userProvider)

    ctx.request.request.headers.authorization = `Basic ${base64.encode('virk@adonisjs.com:foo')}`
    const isLoggedIn = await guard.check()

    assert.isFalse(isLoggedIn)
    assert.isUndefined(guard.user)
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })
})

test.group('Basic auth guard | authenticateAsClient', () => {
  test('create authorization header from user credentials', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<BasicAuthGuardEvents<BasicAuthFakeUser>>()
    const userProvider = new BasicAuthFakeUserProvider()

    const guard = new BasicAuthGuard('basic', ctx, emitter, userProvider)
    const response = await guard.authenticateAsClient('virk@adonisjs.com', 'secret')

    assert.property(response.headers, 'authorization')
    assert.equal(
      response.headers!.authorization,
      `Basic ${base64.encode('virk@adonisjs.com:secret')}`
    )
  })
})
