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

import { AuthManager } from '../../src/auth_manager.ts'
import { FakeGuard } from '../../factories/auth/main.ts'
import { Authenticator } from '../../src/authenticator.ts'
import { AuthenticatorClient } from '../../src/authenticator_client.ts'

test.group('Auth manager', () => {
  test('create authenticator from auth manager', async ({ assert, expectTypeOf }) => {
    const ctx = new HttpContextFactory().create()

    const authManager = new AuthManager({
      default: 'web',
      guards: {
        web: () => new FakeGuard(),
      },
    })

    assert.equal(authManager.defaultGuard, 'web')
    assert.instanceOf(authManager.createAuthenticator(ctx), Authenticator)
    expectTypeOf(authManager.createAuthenticator(ctx).use).parameters.toMatchTypeOf<['web'?]>()
  })

  test('create authenticator client from auth manager', async ({ assert, expectTypeOf }) => {
    const authManager = new AuthManager({
      default: 'web',
      guards: {
        web: () => new FakeGuard(),
      },
    })

    assert.equal(authManager.defaultGuard, 'web')
    assert.instanceOf(authManager.createAuthenticatorClient(), AuthenticatorClient)
    expectTypeOf(authManager.createAuthenticatorClient().use).parameters.toMatchTypeOf<['web'?]>()
  })
})
