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
import { compose } from '@adonisjs/core/helpers'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { AppFactory } from '@adonisjs/core/factories/app'
import type { ApplicationService } from '@adonisjs/core/types'
import { HttpContextFactory } from '@adonisjs/core/factories/http'

import { withAuthFinder } from '../../src/mixins/with_auth_finder.js'
import { createEmitter, getHasher } from '../helpers.js'
import {
  basicAuthGuard,
  basicAuthUserProvider,
} from '../../modules/basic_auth_guard/define_config.js'
import { BasicAuthGuard, BasicAuthLucidUserProvider } from '../../modules/basic_auth_guard/main.js'

test.group('defineConfig', () => {
  test('configure lucid user provider', ({ assert, expectTypeOf }) => {
    const hash = getHasher()

    class User extends compose(
      BaseModel,
      withAuthFinder(() => hash, {
        uids: ['email'],
        passwordColumnName: 'password',
      })
    ) {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string
    }

    const userProvider = basicAuthUserProvider({
      async model() {
        return {
          default: User,
        }
      },
    })
    assert.instanceOf(userProvider, BasicAuthLucidUserProvider)
    expectTypeOf(userProvider).toEqualTypeOf<BasicAuthLucidUserProvider<typeof User>>()
  })

  test('configure basic auth guard', async ({ assert, expectTypeOf }) => {
    const hash = getHasher()

    class User extends compose(
      BaseModel,
      withAuthFinder(() => hash, {
        uids: ['email'],
        passwordColumnName: 'password',
      })
    ) {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string
    }

    const userProvider = basicAuthUserProvider({
      async model() {
        return {
          default: User,
        }
      },
    })

    const ctx = new HttpContextFactory().create()
    const app = new AppFactory().create(new URL('./', import.meta.url)) as ApplicationService
    await app.init()
    app.container.bind('emitter', () => createEmitter())

    const guard = await basicAuthGuard({
      provider: userProvider,
    }).resolver('api', app)

    assert.instanceOf(guard(ctx), BasicAuthGuard)
    expectTypeOf(guard).returns.toEqualTypeOf<
      BasicAuthGuard<BasicAuthLucidUserProvider<typeof User>>
    >()
  })

  test('register user provider from a config provider', async ({ assert, expectTypeOf }) => {
    const hash = getHasher()

    class User extends compose(
      BaseModel,
      withAuthFinder(() => hash, {
        uids: ['email'],
        passwordColumnName: 'password',
      })
    ) {
      @column({ isPrimary: true })
      declare id: number

      @column()
      declare username: string

      @column()
      declare email: string

      @column()
      declare password: string
    }

    const userProvider = configProvider.create(async () => {
      return basicAuthUserProvider({
        async model() {
          return {
            default: User,
          }
        },
      })
    })

    const ctx = new HttpContextFactory().create()
    const app = new AppFactory().create(new URL('./', import.meta.url)) as ApplicationService
    await app.init()
    app.container.bind('emitter', () => createEmitter())

    const guard = await basicAuthGuard({
      provider: userProvider,
    }).resolver('api', app)

    assert.instanceOf(guard(ctx), BasicAuthGuard)
    expectTypeOf(guard).returns.toEqualTypeOf<
      BasicAuthGuard<BasicAuthLucidUserProvider<typeof User>>
    >()
  })
})
