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
import { SessionGuardEvents } from '../../../modules/session_guard/types.js'
import { RememberMeToken } from '../../../modules/session_guard/remember_me_token.js'
import { createEmitter, defineCookies, pEvent, parseCookies, timeTravel } from '../../helpers.js'
import {
  SessionFakeUser,
  SessionFakeUserProvider,
  SessionFakeUserWithTokensProvider,
} from '../../../factories/session/main.js'

test.group('Session guard | logout', () => {
  test('delete user session and remember me cookie', async ({ assert }) => {
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

    await guard.authenticate()
    await guard.logout()

    assert.isUndefined(guard.user)
    assert.deepEqual(ctx.session.all(), {})

    const responseCookies = parseCookies(ctx.response.getHeader('set-cookie') as string)
    assert.deepEqual(responseCookies.remember_web.expires, new Date(0))
    assert.deepEqual(responseCookies.remember_web.maxAge, -1)
  })

  test('delete remember me token using user provider', async ({ assert }) => {
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
    ctx.session.put('auth_web', user!.getId())

    await guard.authenticate()
    await guard.logout()

    assert.isUndefined(guard.user)
    assert.deepEqual(ctx.session.all(), {})

    const responseCookies = parseCookies(ctx.response.getHeader('set-cookie') as string)
    assert.deepEqual(responseCookies.remember_web.expires, new Date(0))
    assert.deepEqual(responseCookies.remember_web.maxAge, -1)

    assert.lengthOf(userProvider.tokens, 0)
  })

  test('do not delete token with storage when no user was authenticated in first place', async ({
    assert,
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
    ctx.session.put('auth_web', user!.getId())

    await guard.logout()

    assert.isUndefined(guard.user)
    assert.deepEqual(ctx.session.all(), {})

    const responseCookies = parseCookies(ctx.response.getHeader('set-cookie') as string)
    assert.deepEqual(responseCookies.remember_web.expires, new Date(0))
    assert.deepEqual(responseCookies.remember_web.maxAge, -1)

    assert.lengthOf(userProvider.tokens, 1)
  })
})
