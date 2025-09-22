/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { AppFactory } from '@adonisjs/core/factories/app'
import type { ApplicationService } from '@adonisjs/core/types'

import { AuthManager } from '../../src/auth_manager.ts'
import { FakeGuard } from '../../factories/auth/main.ts'
import { defineConfig } from '../../src/define_config.ts'
import { HttpContextFactory } from '@adonisjs/core/factories/http'

const BASE_URL = new URL('./', import.meta.url)
const app = new AppFactory().create(BASE_URL, () => {}) as ApplicationService
await app.init()

test.group('Define config', () => {
  test('define and resolve config for the auth manager', async ({ assert }) => {
    const authConfigProvider = defineConfig({
      default: 'web',
      guards: {
        web: () => new FakeGuard(),
      },
    })
    const ctx = new HttpContextFactory().create()

    const authConfig = await authConfigProvider.resolver(app)
    const authManager = new AuthManager(authConfig)
    assert.instanceOf(authManager, AuthManager)
    assert.instanceOf(authManager.createAuthenticator(ctx).use('web'), FakeGuard)
  })

  test('resolve guard registered as provider', async ({ assert }) => {
    const authConfigProvider = defineConfig({
      default: 'web',
      guards: {
        web: {
          async resolver(name) {
            assert.equal(name, 'web')
            return () => new FakeGuard()
          },
        },
      },
    })

    const ctx = new HttpContextFactory().create()
    const authConfig = await authConfigProvider.resolver(app)
    const authManager = new AuthManager(authConfig)
    assert.instanceOf(authManager, AuthManager)
    assert.instanceOf(authManager.createAuthenticator(ctx).use('web'), FakeGuard)
  })
})
