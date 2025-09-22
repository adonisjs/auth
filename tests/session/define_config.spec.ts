/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { configProvider } from '@adonisjs/core'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { AppFactory } from '@adonisjs/core/factories/app'
import type { ApplicationService } from '@adonisjs/core/types'
import { HttpContextFactory } from '@adonisjs/core/factories/http'

import { createEmitter } from '../helpers.ts'
import { SessionGuard, SessionLucidUserProvider } from '../../modules/session_guard/main.ts'
import { sessionGuard, sessionUserProvider } from '../../modules/session_guard/define_config.ts'

test.group('defineConfig', () => {
  test('configure lucid user provider', ({ assert, expectTypeOf }) => {
    class User extends BaseModel {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string
    }

    const userProvider = sessionUserProvider({
      async model() {
        return {
          default: User,
        }
      },
    })
    assert.instanceOf(userProvider, SessionLucidUserProvider)
    expectTypeOf(userProvider).toEqualTypeOf<SessionLucidUserProvider<typeof User>>()
  })

  test('configure session guard', async ({ assert, expectTypeOf }) => {
    class User extends BaseModel {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string
    }

    const ctx = new HttpContextFactory().create()
    const app = new AppFactory().create(new URL('./', import.meta.url)) as ApplicationService
    await app.init()
    app.container.bind('emitter', () => createEmitter())

    const guard = await sessionGuard({
      useRememberMeTokens: false,
      provider: sessionUserProvider({
        async model() {
          return {
            default: User,
          }
        },
      }),
    }).resolver('api', app)

    assert.instanceOf(guard(ctx), SessionGuard)
    expectTypeOf(guard).returns.toEqualTypeOf<
      SessionGuard<false, SessionLucidUserProvider<typeof User>>
    >()
  })

  test('configure session guard and enable remember me tokens', async ({
    assert,
    expectTypeOf,
  }) => {
    class User extends BaseModel {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string
    }

    const ctx = new HttpContextFactory().create()
    const app = new AppFactory().create(new URL('./', import.meta.url)) as ApplicationService
    await app.init()
    app.container.bind('emitter', () => createEmitter())

    const guard = await sessionGuard({
      useRememberMeTokens: true,
      provider: sessionUserProvider({
        async model() {
          return {
            default: User,
          }
        },
      }),
    }).resolver('api', app)

    assert.instanceOf(guard(ctx), SessionGuard)
    expectTypeOf(guard).returns.toEqualTypeOf<
      SessionGuard<true, SessionLucidUserProvider<typeof User>>
    >()
  })

  test('register user provider from a config provider', async ({ assert, expectTypeOf }) => {
    class User extends BaseModel {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string
    }

    const ctx = new HttpContextFactory().create()
    const app = new AppFactory().create(new URL('./', import.meta.url)) as ApplicationService
    await app.init()
    app.container.bind('emitter', () => createEmitter())

    const userProvider = configProvider.create(async () => {
      return sessionUserProvider({
        async model() {
          return {
            default: User,
          }
        },
      })
    })

    const guard = await sessionGuard({
      useRememberMeTokens: false,
      provider: userProvider,
    }).resolver('api', app)

    assert.instanceOf(guard(ctx), SessionGuard)
    expectTypeOf(guard).returns.toEqualTypeOf<
      SessionGuard<false, SessionLucidUserProvider<typeof User>>
    >()
  })
})
