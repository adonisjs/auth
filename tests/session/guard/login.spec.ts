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

import { createEmitter, pEvent, parseCookies } from '../../helpers.js'
import { SessionGuard } from '../../../modules/session_guard/guard.js'
import type { SessionGuardEvents } from '../../../modules/session_guard/types.js'
import { RememberMeToken } from '../../../modules/session_guard/remember_me_token.js'
import {
  type SessionFakeUser,
  SessionFakeUserProvider,
  SessionFakeUserWithTokensProvider,
} from '../../../factories/session/main.js'

test.group('Session guard | login', () => {
  test('create session for the user', async ({ assert, expectTypeOf }) => {
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
    const [attempted, succeeded] = await Promise.all([
      pEvent(emitter, 'session_auth:login_attempted'),
      pEvent(emitter, 'session_auth:login_succeeded'),
      guard.login(user!.getOriginal()),
    ])

    expectTypeOf(guard.user).toEqualTypeOf<SessionFakeUser | undefined>()
    expectTypeOf(succeeded!.user).toEqualTypeOf<SessionFakeUser>()

    assert.equal(attempted!.guardName, 'web')
    assert.equal(succeeded!.guardName, 'web')
    assert.equal(succeeded!.sessionId, ctx.session.sessionId)

    assert.deepEqual(guard.user, user!.getOriginal())
    assert.deepEqual(guard.getUserOrFail(), user!.getOriginal())
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.isAuthenticated)
    assert.isFalse(guard.authenticationAttempted)
    assert.isFalse(guard.viaRemember)
    assert.isFalse(guard.attemptedViaRemember)

    assert.deepEqual(ctx.session.all(), {
      auth_web: user!.getId(),
    })
  })

  test('throw error when trying to create remember me token without enabling it', async ({
    assert,
  }) => {
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
    const [attempted] = await Promise.all([
      pEvent(emitter, 'session_auth:login_attempted'),
      (async () => {
        await assert.rejects(
          () => guard.login(user!.getOriginal(), true),
          'Cannot use "rememberMe" feature. It has been disabled'
        )
      })(),
    ])

    assert.exists(attempted)
    assert.isUndefined(guard.user)
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.isAuthenticated)
    assert.isFalse(guard.authenticationAttempted)
    assert.isFalse(guard.viaRemember)
    assert.isFalse(guard.attemptedViaRemember)

    assert.deepEqual(ctx.session.all(), {})
  })

  test('create remember me cookie and token', async ({ assert, expectTypeOf }) => {
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

    /**
     * Setup ctx with session
     */
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    await sessionMiddleware.handle(ctx, async () => {})

    const user = await userProvider.findById(1)
    const [attempted, succeeded] = await Promise.all([
      pEvent(emitter, 'session_auth:login_attempted'),
      pEvent(emitter, 'session_auth:login_succeeded'),
      guard.login(user!.getOriginal(), true),
    ])

    expectTypeOf(guard.user).toEqualTypeOf<SessionFakeUser | undefined>()
    expectTypeOf(succeeded!.user).toEqualTypeOf<SessionFakeUser>()

    assert.equal(attempted!.guardName, 'web')
    assert.equal(succeeded!.guardName, 'web')
    assert.equal(succeeded!.sessionId, ctx.session.sessionId)

    assert.deepEqual(guard.user, user!.getOriginal())
    assert.deepEqual(guard.getUserOrFail(), user!.getOriginal())
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.isAuthenticated)
    assert.isFalse(guard.authenticationAttempted)
    assert.isFalse(guard.viaRemember)
    assert.isFalse(guard.attemptedViaRemember)

    assert.deepEqual(ctx.session.all(), {
      auth_web: user!.getId(),
    })

    const responseCookies = parseCookies(ctx.response.getHeader('set-cookie') as string)
    assert.lengthOf(userProvider.tokens, 1)
    assert.equal(
      RememberMeToken.decode(responseCookies.remember_web.value)?.identifier,
      userProvider.tokens[0].id
    )
  })
})
