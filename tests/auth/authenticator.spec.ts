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

import { Authenticator } from '../../src/authenticator.ts'
import { E_UNAUTHORIZED_ACCESS } from '../../src/errors.ts'
import { FakeGuard, type FakeUser } from '../../factories/auth/main.ts'

test.group('Authenticator', () => {
  test('create authenticator with guards', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()

    const authenticator = new Authenticator(ctx, {
      default: 'web',
      guards: {
        web: () => new FakeGuard(),
      },
    })

    assert.instanceOf(authenticator, Authenticator)
    expectTypeOf(authenticator.use).parameters.toMatchTypeOf<['web'?]>()
  })

  test('access guard using its name', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()

    const authenticator = new Authenticator(ctx, {
      default: 'web',
      guards: {
        web: () => new FakeGuard(),
      },
    })

    const webGuard = authenticator.use('web')
    assert.instanceOf(webGuard, FakeGuard)
    assert.equal(authenticator.defaultGuard, 'web')
    assert.equal(webGuard.driverName, 'fake')
    assert.strictEqual(authenticator.use('web'), authenticator.use('web'))
    expectTypeOf(webGuard.user).toMatchTypeOf<FakeUser | undefined>()
  })

  test('authenticate using the default guard', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()

    const authenticator = new Authenticator(ctx, {
      default: 'web',
      guards: {
        web: () => new FakeGuard(),
      },
    })

    await authenticator.authenticate()

    assert.equal(authenticator.user!.id, 1)
    expectTypeOf(authenticator.user).toMatchTypeOf<FakeUser | undefined>()
    expectTypeOf(authenticator.getUserOrFail()).toMatchTypeOf<FakeUser>()
    assert.equal(authenticator.authenticatedViaGuard, 'web')
    assert.isTrue(authenticator.isAuthenticated)
    assert.isTrue(authenticator.authenticationAttempted)
  })

  test('check authentication using the default guard', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()

    const authenticator = new Authenticator(ctx, {
      default: 'web',
      guards: {
        web: () => new FakeGuard(),
      },
    })

    await authenticator.check()

    assert.equal(authenticator.user!.id, 1)
    expectTypeOf(authenticator.user).toMatchTypeOf<FakeUser | undefined>()
    expectTypeOf(authenticator.getUserOrFail()).toMatchTypeOf<FakeUser>()
    assert.equal(authenticator.authenticatedViaGuard, 'web')
    assert.isTrue(authenticator.isAuthenticated)
    assert.isTrue(authenticator.authenticationAttempted)
  })

  test('authenticate using the guard instance', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const authenticator = new Authenticator(ctx, {
      default: 'web',
      guards: {
        web: () => new FakeGuard(),
      },
    })

    const user = await authenticator.use().authenticate()

    assert.equal(user.id, 1)
    assert.isUndefined(authenticator.user)
    assert.isUndefined(authenticator.authenticatedViaGuard)
    assert.isFalse(authenticator.isAuthenticated)
    assert.isFalse(authenticator.authenticationAttempted)
  })

  test('access properties without authenticating user', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const authenticator = new Authenticator(ctx, {
      default: 'web',
      guards: {
        web: () => new FakeGuard(),
      },
    })

    assert.isUndefined(authenticator.user)
    assert.isUndefined(authenticator.authenticatedViaGuard)
    assert.isFalse(authenticator.isAuthenticated)
    assert.isFalse(authenticator.authenticationAttempted)
    assert.throws(
      () => authenticator.getUserOrFail(),
      'Cannot access authenticated user. Please call "auth.authenticate" method first.'
    )
  })

  test('throw error when unable to authenticate', async ({ assert }) => {
    assert.plan(5)

    const ctx = new HttpContextFactory().create()
    const authenticator = new Authenticator(ctx, {
      default: 'web',
      guards: {
        web: () => new FakeGuard(),
      },
    })

    authenticator.use('web').authenticate = async function () {
      this.authenticationAttempted = true
      return this.getUserOrFail()
    }

    try {
      await authenticator.authenticateUsing()
    } catch (error: any) {
      assert.instanceOf(error, E_UNAUTHORIZED_ACCESS)
      assert.equal(error.message, 'Unauthorized access')
      assert.equal(error.guardDriverName, 'fake')
    }

    assert.isFalse(authenticator.isAuthenticated)
    assert.isTrue(authenticator.authenticationAttempted)
  })

  test('do not throw error when unable to authenticate via check method', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const authenticator = new Authenticator(ctx, {
      default: 'web',
      guards: {
        web: () => new FakeGuard(),
      },
    })

    authenticator.use('web').authenticate = async function () {
      this.authenticationAttempted = true
      return this.getUserOrFail()
    }

    const isAuthenticated = await authenticator.check()
    assert.isFalse(isAuthenticated)
    assert.isFalse(authenticator.isAuthenticated)
    assert.isTrue(authenticator.authenticationAttempted)
  })

  test('check authentication using multiple guards', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const authenticator = new Authenticator(ctx, {
      default: 'web1',
      guards: {
        web1: () => new FakeGuard(),
        web2: () => new FakeGuard(),
      },
    })

    authenticator.use('web1').authenticate = async function () {
      this.authenticationAttempted = true
      return this.getUserOrFail()
    }

    const isAuthenticated = await authenticator.checkUsing(['web1', 'web2'])

    assert.isTrue(isAuthenticated)
    assert.isTrue(authenticator.isAuthenticated)
    assert.isTrue(authenticator.authenticationAttempted)
    assert.equal(authenticator.authenticatedViaGuard, 'web2')
  })
})
