/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { FakeGuard, FakeUser } from '../../factories/auth/main.js'
import { AuthenticatorClient } from '../../src/authenticator_client.js'

test.group('Authenticator client', () => {
  test('create authenticator client with guards', async ({ assert, expectTypeOf }) => {
    const client = new AuthenticatorClient({
      default: 'web',
      guards: {
        web: () => new FakeGuard(),
      },
    })

    assert.instanceOf(client, AuthenticatorClient)
    expectTypeOf(client.use).parameters.toMatchTypeOf<['web'?]>()
  })

  test('access guard using its name', async ({ assert, expectTypeOf }) => {
    const client = new AuthenticatorClient({
      default: 'web',
      guards: {
        web: () => new FakeGuard(),
      },
    })

    const webGuard = client.use('web')
    assert.instanceOf(webGuard, FakeGuard)
    assert.equal(client.defaultGuard, 'web')
    assert.equal(webGuard.driverName, 'fake')
    assert.strictEqual(client.use('web'), client.use('web'))
    assert.strictEqual(client.use(), client.use('web'))
    expectTypeOf(webGuard.user).toMatchTypeOf<FakeUser | undefined>()
  })

  test('call authenticateAsClient via client', async ({ assert }) => {
    const client = new AuthenticatorClient({
      default: 'web',
      guards: {
        web: () => new FakeGuard(),
      },
    })

    await assert.rejects(() => client.use('web').authenticateAsClient({ id: 1 }), 'Not supported')
  })
})
