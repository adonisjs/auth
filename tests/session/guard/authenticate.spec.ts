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
import { SessionMiddlewareFactory } from '@adonisjs/session/factories'

import { SessionGuard } from '../../../modules/session_guard/guard.js'
import { type SessionGuardEvents } from '../../../modules/session_guard/types.js'
import { RememberMeToken } from '../../../modules/session_guard/remember_me_token.js'
import { createEmitter, defineCookies, pEvent, parseCookies, timeTravel } from '../../helpers.js'
import {
  type SessionFakeUser,
  SessionFakeUserProvider,
  SessionFakeUserWithTokensProvider,
} from '../../../factories/session/main.js'

test.group('Session guard | authenticate via session', () => {
  test('return user when request has a valid session', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<SessionGuardEvents<SessionFakeUser>>()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard(
      'web',
      ctx,
      {
        useRememberMeTokens: false,
      },
      emitter,
      userProvider
    )

    /**
     * Setup ctx with session
     */
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    await sessionMiddleware.handle(ctx, async () => {})

    const user = await userProvider.findById(1)
    ctx.session.put('auth_web', user!.getId())

    const [attempted, succeeded, authenticatedUser] = await Promise.all([
      pEvent(emitter, 'session_auth:authentication_attempted'),
      pEvent(emitter, 'session_auth:authentication_succeeded'),
      guard.authenticate(),
    ])

    expectTypeOf(authenticatedUser).toEqualTypeOf<SessionFakeUser>()
    expectTypeOf(guard.user).toEqualTypeOf<SessionFakeUser | undefined>()
    expectTypeOf(succeeded!.user).toEqualTypeOf<SessionFakeUser>()

    assert.equal(attempted!.guardName, 'web')
    assert.equal(succeeded!.guardName, 'web')
    assert.equal(succeeded!.sessionId, ctx.session.sessionId)
    assert.deepEqual(succeeded!.user, authenticatedUser)

    assert.deepEqual(guard.user, authenticatedUser)
    assert.deepEqual(guard.getUserOrFail(), authenticatedUser)
    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.viaRemember)
    assert.isFalse(guard.attemptedViaRemember)
  })

  test('throw error when session does not exist', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<SessionGuardEvents<SessionFakeUser>>()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard(
      'web',
      ctx,
      {
        useRememberMeTokens: false,
      },
      emitter,
      userProvider
    )

    /**
     * Setup ctx with session
     */
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    await sessionMiddleware.handle(ctx, async () => {})

    const [attempted, failed] = await Promise.all([
      pEvent(emitter, 'session_auth:authentication_attempted'),
      pEvent(emitter, 'session_auth:authentication_failed'),
      (async () => {
        try {
          await guard.authenticate()
        } catch {}
      })(),
    ])

    expectTypeOf(guard.user).toEqualTypeOf<SessionFakeUser | undefined>()

    assert.equal(attempted!.guardName, 'web')
    assert.equal(failed!.guardName, 'web')
    assert.equal(failed!.sessionId, ctx.session.sessionId)
    assert.equal(failed!.error.message, 'Invalid or expired user session')

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Invalid or expired user session')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.viaRemember)
    assert.isFalse(guard.attemptedViaRemember)
  })

  test('throw error when session user does not exists', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<SessionGuardEvents<SessionFakeUser>>()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard(
      'web',
      ctx,
      {
        useRememberMeTokens: false,
      },
      emitter,
      userProvider
    )

    /**
     * Setup ctx with session
     */
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    await sessionMiddleware.handle(ctx, async () => {})

    ctx.session.put('auth_web', 20)

    const [attempted, failed] = await Promise.all([
      pEvent(emitter, 'session_auth:authentication_attempted'),
      pEvent(emitter, 'session_auth:authentication_failed'),
      (async () => {
        try {
          await guard.authenticate()
        } catch {}
      })(),
    ])

    expectTypeOf(guard.user).toEqualTypeOf<SessionFakeUser | undefined>()

    assert.equal(attempted!.guardName, 'web')
    assert.equal(failed!.guardName, 'web')
    assert.equal(failed!.sessionId, ctx.session.sessionId)
    assert.equal(failed!.error.message, 'Invalid or expired user session')

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Invalid or expired user session')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.viaRemember)
    assert.isFalse(guard.attemptedViaRemember)
  })

  test('mutiple calls to authenticate should be a noop', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<SessionGuardEvents<SessionFakeUser>>()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard(
      'web',
      ctx,
      {
        useRememberMeTokens: false,
      },
      emitter,
      userProvider
    )

    /**
     * Setup ctx with session
     */
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    await sessionMiddleware.handle(ctx, async () => {})

    await assert.rejects(() => guard.authenticate(), 'Invalid or expired user session')

    /**
     * Even though the session will exist from here on, the
     * authenticate method will still fail, because it
     * caches results from first call.
     */
    const user = await userProvider.findById(1)
    ctx.session.put('auth_web', user!.getId())

    await assert.rejects(() => guard.authenticate(), 'Invalid or expired user session')
  })
})

test.group('Session guard | authenticate via remember token', () => {
  test('return user when valid remember token exists', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<SessionGuardEvents<SessionFakeUser>>()
    const userProvider = new SessionFakeUserWithTokensProvider()

    const guard = new SessionGuard(
      'web',
      ctx,
      {
        useRememberMeTokens: true,
      },
      emitter,
      userProvider
    )

    const user = await userProvider.findById(1)
    const token = await userProvider.createRememberToken(user!.getOriginal(), '20 mins')

    ctx.request.request.headers.cookie = defineCookies([
      {
        key: 'remember_web',
        value: token.value!.release(),
        type: 'encrypted',
      },
    ])

    /**
     * Setup ctx with session
     */
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    await sessionMiddleware.handle(ctx, async () => {})

    const [attempted, succeeded, authenticatedUser] = await Promise.all([
      pEvent(emitter, 'session_auth:authentication_attempted'),
      pEvent(emitter, 'session_auth:authentication_succeeded'),
      guard.authenticate(),
    ])

    expectTypeOf(authenticatedUser).toEqualTypeOf<SessionFakeUser>()
    expectTypeOf(guard.user).toEqualTypeOf<SessionFakeUser | undefined>()
    expectTypeOf(succeeded!.user).toEqualTypeOf<SessionFakeUser>()

    assert.equal(attempted!.guardName, 'web')
    assert.equal(succeeded!.guardName, 'web')
    assert.deepEqual(succeeded!.user, authenticatedUser)

    assert.deepEqual(guard.user, authenticatedUser)
    assert.deepEqual(guard.getUserOrFail(), authenticatedUser)
    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
    assert.isTrue(guard.viaRemember)
    assert.isTrue(guard.attemptedViaRemember)
  })

  test('do not attempt to use remember token when session id exists but for non-existing user', async ({
    assert,
    expectTypeOf,
  }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<SessionGuardEvents<SessionFakeUser>>()
    const userProvider = new SessionFakeUserWithTokensProvider()

    const guard = new SessionGuard(
      'web',
      ctx,
      {
        useRememberMeTokens: true,
      },
      emitter,
      userProvider
    )

    const user = await userProvider.findById(1)
    const token = await userProvider.createRememberToken(user!.getOriginal(), '20 mins')

    ctx.request.request.headers.cookie = defineCookies([
      {
        key: 'remember_web',
        value: token.value!.release(),
        type: 'encrypted',
      },
    ])

    /**
     * Setup ctx with session
     */
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    await sessionMiddleware.handle(ctx, async () => {})
    ctx.session.put('auth_web', 20)

    const [attempted, failed] = await Promise.all([
      pEvent(emitter, 'session_auth:authentication_attempted'),
      pEvent(emitter, 'session_auth:authentication_failed'),
      (async () => {
        try {
          await guard.authenticate()
        } catch {}
      })(),
    ])

    expectTypeOf(guard.user).toEqualTypeOf<SessionFakeUser | undefined>()

    assert.equal(attempted!.guardName, 'web')
    assert.equal(failed!.guardName, 'web')
    assert.equal(failed!.sessionId, ctx.session.sessionId)
    assert.equal(failed!.error.message, 'Invalid or expired user session')

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Invalid or expired user session')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.viaRemember)
    assert.isFalse(guard.attemptedViaRemember)
  })

  test('do not attempt to use remember token when remember tokens have been disabled', async ({
    assert,
    expectTypeOf,
  }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<SessionGuardEvents<SessionFakeUser>>()
    const userProvider = new SessionFakeUserWithTokensProvider()

    const guard = new SessionGuard(
      'web',
      ctx,
      {
        useRememberMeTokens: false,
      },
      emitter,
      userProvider
    )

    const user = await userProvider.findById(1)
    const token = await userProvider.createRememberToken(user!.getOriginal(), '20 mins')

    ctx.request.request.headers.cookie = defineCookies([
      {
        key: 'remember_web',
        value: token.value!.release(),
        type: 'encrypted',
      },
    ])

    /**
     * Setup ctx with session
     */
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    await sessionMiddleware.handle(ctx, async () => {})

    const [attempted, failed] = await Promise.all([
      pEvent(emitter, 'session_auth:authentication_attempted'),
      pEvent(emitter, 'session_auth:authentication_failed'),
      (async () => {
        try {
          await guard.authenticate()
        } catch {}
      })(),
    ])

    expectTypeOf(guard.user).toEqualTypeOf<SessionFakeUser | undefined>()

    assert.equal(attempted!.guardName, 'web')
    assert.equal(failed!.guardName, 'web')
    assert.equal(failed!.sessionId, ctx.session.sessionId)
    assert.equal(failed!.error.message, 'Invalid or expired user session')

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Invalid or expired user session')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.viaRemember)
    assert.isFalse(guard.attemptedViaRemember)
  })

  test('return error when token has been expired', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<SessionGuardEvents<SessionFakeUser>>()
    const userProvider = new SessionFakeUserWithTokensProvider()

    const guard = new SessionGuard(
      'web',
      ctx,
      {
        useRememberMeTokens: true,
      },
      emitter,
      userProvider
    )

    const user = await userProvider.findById(1)
    const token = await userProvider.createRememberToken(user!.getOriginal(), '20 mins')

    ctx.request.request.headers.cookie = defineCookies([
      {
        key: 'remember_web',
        value: token.value!.release(),
        type: 'encrypted',
      },
    ])

    /**
     * Setup ctx with session
     */
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    await sessionMiddleware.handle(ctx, async () => {})

    /**
     * The token will expire in 20 minutes
     */
    timeTravel(21 * 60)

    const [attempted, failed] = await Promise.all([
      pEvent(emitter, 'session_auth:authentication_attempted'),
      pEvent(emitter, 'session_auth:authentication_failed'),
      (async () => {
        try {
          await guard.authenticate()
        } catch {}
      })(),
    ])

    expectTypeOf(guard.user).toEqualTypeOf<SessionFakeUser | undefined>()

    assert.equal(attempted!.guardName, 'web')
    assert.equal(failed!.guardName, 'web')
    assert.equal(failed!.sessionId, ctx.session.sessionId)
    assert.equal(failed!.error.message, 'Invalid or expired user session')

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Invalid or expired user session')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.viaRemember)
    assert.isTrue(guard.attemptedViaRemember)
  })

  test('return error when token does not exist', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<SessionGuardEvents<SessionFakeUser>>()
    const userProvider = new SessionFakeUserWithTokensProvider()

    const guard = new SessionGuard(
      'web',
      ctx,
      {
        useRememberMeTokens: true,
      },
      emitter,
      userProvider
    )

    const user = await userProvider.findById(1)
    const token = await userProvider.createRememberToken(user!.getOriginal(), '20 mins')

    ctx.request.request.headers.cookie = defineCookies([
      {
        key: 'remember_web',
        value: token.value!.release(),
        type: 'encrypted',
      },
    ])

    /**
     * Setup ctx with session
     */
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    await sessionMiddleware.handle(ctx, async () => {})

    /**
     * Deleting token
     */
    await userProvider.deleteRemeberToken(user!.getOriginal(), token.identifier)

    const [attempted, failed] = await Promise.all([
      pEvent(emitter, 'session_auth:authentication_attempted'),
      pEvent(emitter, 'session_auth:authentication_failed'),
      (async () => {
        try {
          await guard.authenticate()
        } catch {}
      })(),
    ])

    expectTypeOf(guard.user).toEqualTypeOf<SessionFakeUser | undefined>()

    assert.equal(attempted!.guardName, 'web')
    assert.equal(failed!.guardName, 'web')
    assert.equal(failed!.sessionId, ctx.session.sessionId)
    assert.equal(failed!.error.message, 'Invalid or expired user session')

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Invalid or expired user session')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.viaRemember)
    assert.isTrue(guard.attemptedViaRemember)
  })

  test('return error when user for the token does not exist', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<SessionGuardEvents<SessionFakeUser>>()
    const userProvider = new SessionFakeUserWithTokensProvider()

    const guard = new SessionGuard(
      'web',
      ctx,
      {
        useRememberMeTokens: true,
      },
      emitter,
      userProvider
    )

    const token = await userProvider.createRememberToken(
      { id: 20, email: 'foo@bar.com', password: 'secret' },
      '20 mins'
    )

    ctx.request.request.headers.cookie = defineCookies([
      {
        key: 'remember_web',
        value: token.value!.release(),
        type: 'encrypted',
      },
    ])

    /**
     * Setup ctx with session
     */
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    await sessionMiddleware.handle(ctx, async () => {})

    const [attempted, failed] = await Promise.all([
      pEvent(emitter, 'session_auth:authentication_attempted'),
      pEvent(emitter, 'session_auth:authentication_failed'),
      (async () => {
        try {
          await guard.authenticate()
        } catch {}
      })(),
    ])

    expectTypeOf(guard.user).toEqualTypeOf<SessionFakeUser | undefined>()

    assert.equal(attempted!.guardName, 'web')
    assert.equal(failed!.guardName, 'web')
    assert.equal(failed!.sessionId, ctx.session.sessionId)
    assert.equal(failed!.error.message, 'Invalid or expired user session')

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Invalid or expired user session')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.viaRemember)
    assert.isTrue(guard.attemptedViaRemember)
  })

  test('recycle token after use', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<SessionGuardEvents<SessionFakeUser>>()
    const userProvider = new SessionFakeUserWithTokensProvider()

    const guard = new SessionGuard(
      'web',
      ctx,
      {
        useRememberMeTokens: true,
      },
      emitter,
      userProvider
    )

    const user = await userProvider.findById(1)
    const token = await userProvider.createRememberToken(user!.getOriginal(), '20 mins')

    ctx.request.request.headers.cookie = defineCookies([
      {
        key: 'remember_web',
        value: token.value!.release(),
        type: 'encrypted',
      },
    ])

    /**
     * Setup ctx with session
     */
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    await sessionMiddleware.handle(ctx, async () => {})

    const [attempted, succeeded, authenticatedUser] = await Promise.all([
      pEvent(emitter, 'session_auth:authentication_attempted'),
      pEvent(emitter, 'session_auth:authentication_succeeded'),
      guard.authenticate(),
    ])

    expectTypeOf(authenticatedUser).toEqualTypeOf<SessionFakeUser>()
    expectTypeOf(guard.user).toEqualTypeOf<SessionFakeUser | undefined>()
    expectTypeOf(succeeded!.user).toEqualTypeOf<SessionFakeUser>()

    assert.equal(attempted!.guardName, 'web')
    assert.equal(succeeded!.guardName, 'web')
    assert.deepEqual(succeeded!.user, authenticatedUser)

    assert.deepEqual(guard.user, authenticatedUser)
    assert.deepEqual(guard.getUserOrFail(), authenticatedUser)
    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
    assert.isTrue(guard.viaRemember)
    assert.isTrue(guard.attemptedViaRemember)

    assert.lengthOf(userProvider.tokens, 1)
    assert.notEqual(userProvider.tokens[0].id, token.identifier)
    assert.notEqual(userProvider.tokens[0].hash, token.hash)
    assert.notEqual(userProvider.tokens[0].created_at.getTime(), token.createdAt.getTime())
    assert.notEqual(userProvider.tokens[0].updated_at.getTime(), token.updatedAt.getTime())
    assert.notEqual(userProvider.tokens[0].expires_at.getTime(), token.expiresAt.getTime())
    assert.equal(userProvider.tokens[0].tokenable_id, token.tokenableId)

    const responseCookies = parseCookies(ctx.response.getHeader('set-cookie') as string)
    assert.equal(
      RememberMeToken.decode(responseCookies.remember_web.value)?.identifier,
      userProvider.tokens[0].id
    )
  })
})

test.group('Session guard | check', () => {
  test('return true when valid session exists', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<SessionGuardEvents<SessionFakeUser>>()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard(
      'web',
      ctx,
      {
        useRememberMeTokens: false,
      },
      emitter,
      userProvider
    )

    /**
     * Setup ctx with session
     */
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    await sessionMiddleware.handle(ctx, async () => {})

    const user = await userProvider.findById(1)
    ctx.session.put('auth_web', user!.getId())

    const isAuthenticated = await guard.check()

    expectTypeOf(isAuthenticated).toEqualTypeOf<boolean>()
    expectTypeOf(guard.user).toEqualTypeOf<SessionFakeUser | undefined>()

    assert.isTrue(isAuthenticated)
    assert.deepEqual(guard.getUserOrFail(), user!.getOriginal())
    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.viaRemember)
    assert.isFalse(guard.attemptedViaRemember)
  })

  test('return false when valid session does not exists', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<SessionGuardEvents<SessionFakeUser>>()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard(
      'web',
      ctx,
      {
        useRememberMeTokens: false,
      },
      emitter,
      userProvider
    )

    /**
     * Setup ctx with session
     */
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    await sessionMiddleware.handle(ctx, async () => {})

    const isAuthenticated = await guard.check()

    expectTypeOf(isAuthenticated).toEqualTypeOf<boolean>()
    expectTypeOf(guard.user).toEqualTypeOf<SessionFakeUser | undefined>()

    assert.isFalse(isAuthenticated)
    assert.throws(() => guard.getUserOrFail(), 'Invalid or expired user session')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.viaRemember)
    assert.isFalse(guard.attemptedViaRemember)
  })

  test('rethrow errors other than E_AUTHORIZED_ACCESS', async () => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<SessionGuardEvents<SessionFakeUser>>()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard(
      'web',
      ctx,
      {
        useRememberMeTokens: false,
      },
      emitter,
      userProvider
    )

    await guard.check()
  }).throws('Cannot authenticate user. Install and configure "@adonisjs/session" package')
})

test.group('Session guard | authenticateAsClient', () => {
  test('return session info for a given user', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter<SessionGuardEvents<SessionFakeUser>>()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard(
      'web',
      ctx,
      {
        useRememberMeTokens: false,
      },
      emitter,
      userProvider
    )

    const user = await userProvider.findById(1)
    const response = await guard.authenticateAsClient(user!.getOriginal())

    assert.deepEqual(response, {
      session: {
        auth_web: user!.getId(),
      },
    })
  })
})
