/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import nock from 'nock'
import sinon from 'sinon'
import { test } from '@japa/runner'
import { runner } from '@japa/runner/factories'
import { browserClient } from '@japa/browser-client'
import { AppFactory } from '@adonisjs/core/factories/app'
import type { ApplicationService } from '@adonisjs/core/types'

import { Guards } from './global_types.js'
import { AuthManager } from '../../../src/auth_manager.js'
import { FakeGuard, FakeUser } from '../../../factories/auth/main.js'
import { authBrowserClient } from '../../../src/plugins/japa/browser_client.js'

test.group('Browser client | loginAs', (group) => {
  group.each.timeout(0)

  test('login user using the guard authenticateAsClient method', async ({
    assert,
    expectTypeOf,
  }) => {
    const fakeGuard = new FakeGuard()
    const guards: Guards = {
      web: () => fakeGuard,
    }

    const authManager = new AuthManager({
      default: 'web',
      guards: guards,
    })

    const app = new AppFactory().create(new URL('./', import.meta.url)) as ApplicationService
    await app.init()

    app.container.singleton('auth.manager', () => authManager)
    const spy = sinon.spy(fakeGuard, 'authenticateAsClient')

    nock('http://localhost:3333').get('/').reply(200)

    await runner()
      .configure({
        plugins: [browserClient({}), authBrowserClient(app)],
        files: ['*'],
      })
      .runTest('sample test', async ({ browserContext }) => {
        await browserContext.loginAs({ id: 1 })
        expectTypeOf(browserContext.loginAs).parameters.toEqualTypeOf<
          [
            user: FakeUser,
            abilities?: string[] | undefined,
            expiresIn?: string | number | undefined,
          ]
        >()
      })

    assert.isTrue(spy.calledOnceWithExactly({ id: 1 }))
  })

  test('pass additional params to loginAs method', async ({ assert, expectTypeOf }) => {
    const fakeGuard = new FakeGuard()
    const guards = {
      web: () => fakeGuard,
    }

    const authManager = new AuthManager({
      default: 'web',
      guards: guards,
    })

    const app = new AppFactory().create(new URL('./', import.meta.url)) as ApplicationService
    await app.init()

    app.container.singleton('auth.manager', () => authManager)
    const spy = sinon.spy(fakeGuard, 'authenticateAsClient')

    nock('http://localhost:3333').get('/').reply(200)

    await runner()
      .configure({
        plugins: [browserClient({}), authBrowserClient(app)],
        files: ['*'],
      })
      .runTest('sample test', async ({ browserContext }) => {
        await browserContext.withGuard('web').loginAs({ id: 1 }, ['*'], '20 mins')
        expectTypeOf(browserContext.withGuard('web').loginAs).parameters.toEqualTypeOf<
          [
            user: FakeUser,
            abilities?: string[] | undefined,
            expiresIn?: string | number | undefined,
          ]
        >()
      })

    assert.isTrue(spy.calledOnceWithExactly({ id: 1 }, ['*'], '20 mins'))
  })
})
