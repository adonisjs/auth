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
import { apiClient } from '@japa/api-client'
import { runner } from '@japa/runner/factories'
import { AppFactory } from '@adonisjs/core/factories/app'
import type { ApplicationService } from '@adonisjs/core/types'

import { type Guards } from './global_types.js'
import { AuthManager } from '../../../src/auth_manager.js'
import { FakeGuard, type FakeUser } from '../../../factories/auth/main.js'
import { authApiClient } from '../../../src/plugins/japa/api_client.js'

test.group('Api client | loginAs', () => {
  test('login user using the guard authenticate as client method', async ({
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
        plugins: [apiClient({ baseURL: 'http://localhost:3333' }), authApiClient(app)],
        files: ['*'],
      })
      .runTest('sample test', async ({ client }) => {
        const request = client.get('/')
        await request.loginAs({ id: 1 })
        expectTypeOf(request.loginAs).parameters.toEqualTypeOf<
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
        plugins: [apiClient({ baseURL: 'http://localhost:3333' }), authApiClient(app)],
        files: ['*'],
      })
      .runTest('sample test', async ({ client }) => {
        const request = client.get('/')
        await request.withGuard('web').loginAs({ id: 1 }, ['*'], '20 mins')
        expectTypeOf(request.withGuard('web').loginAs).parameters.toEqualTypeOf<
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
