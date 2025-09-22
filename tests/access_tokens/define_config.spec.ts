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
import {
  tokensGuard,
  AccessTokensGuard,
  tokensUserProvider,
  DbAccessTokensProvider,
  AccessTokensLucidUserProvider,
} from '../../modules/access_tokens_guard/main.ts'

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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const userProvider = tokensUserProvider({
      tokens: 'authTokens',
      async model() {
        return {
          default: User,
        }
      },
    })
    assert.instanceOf(userProvider, AccessTokensLucidUserProvider)
    expectTypeOf(userProvider).toEqualTypeOf<
      AccessTokensLucidUserProvider<'authTokens', typeof User>
    >()
  })

  test('configure access tokens guard', async ({ assert, expectTypeOf }) => {
    class User extends BaseModel {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const ctx = new HttpContextFactory().create()
    const app = new AppFactory().create(new URL('./', import.meta.url)) as ApplicationService
    await app.init()
    app.container.bind('emitter', () => createEmitter())

    const guard = await tokensGuard({
      provider: tokensUserProvider({
        tokens: 'authTokens',
        async model() {
          return {
            default: User,
          }
        },
      }),
    }).resolver('api', app)

    assert.instanceOf(guard(ctx), AccessTokensGuard)
    expectTypeOf(guard).returns.toEqualTypeOf<
      AccessTokensGuard<AccessTokensLucidUserProvider<'authTokens', typeof User>>
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

      static authTokens = DbAccessTokensProvider.forModel(User)
    }

    const ctx = new HttpContextFactory().create()
    const app = new AppFactory().create(new URL('./', import.meta.url)) as ApplicationService
    await app.init()
    app.container.bind('emitter', () => createEmitter())

    const userProvider = configProvider.create(async () => {
      return tokensUserProvider({
        tokens: 'authTokens',
        async model() {
          return {
            default: User,
          }
        },
      })
    })
    const guard = await tokensGuard({ provider: userProvider }).resolver('api', app)

    assert.instanceOf(guard(ctx), AccessTokensGuard)
    expectTypeOf(guard).returns.toEqualTypeOf<
      AccessTokensGuard<AccessTokensLucidUserProvider<'authTokens', typeof User>>
    >()
  })
})
