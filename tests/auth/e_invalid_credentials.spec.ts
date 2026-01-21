/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { I18nManagerFactory } from '@adonisjs/i18n/factories'
import { HttpContextFactory } from '@adonisjs/core/factories/http'
import { SessionMiddlewareFactory } from '@adonisjs/session/factories'

import { E_INVALID_CREDENTIALS } from '../../src/errors.ts'

test.group('Errors | E_INVALID_CREDENTIALS', () => {
  test('report error via flash messages and redirect', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = new E_INVALID_CREDENTIALS('Invalid credentials')

    const ctx = new HttpContextFactory().create()
    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.deepEqual(ctx.session.responseFlashMessages.all(), {
      error: 'Invalid credentials',
      errorsBag: { E_INVALID_CREDENTIALS: 'Invalid credentials' },
      input: {},
    })
    assert.equal(ctx.response.getHeader('location'), '/')
  })

  test('respond with text message when session middleware is not configured', async ({
    assert,
  }) => {
    const error = new E_INVALID_CREDENTIALS('Invalid credentials')

    const ctx = new HttpContextFactory().create()
    await error.handle(error, ctx)

    assert.isUndefined(ctx.response.getHeader('location'))
    assert.deepEqual(ctx.response.getBody(), 'Invalid credentials')
  })

  test('respond with json', async ({ assert }) => {
    const error = new E_INVALID_CREDENTIALS('Invalid credentials')

    const ctx = new HttpContextFactory().create()

    /**
     * Force JSON response
     */
    ctx.request.request.headers.accept = 'application/json'
    await error.handle(error, ctx)

    assert.isUndefined(ctx.response.getHeader('location'))
    assert.deepEqual(ctx.response.getBody(), {
      errors: [
        {
          message: 'Invalid credentials',
        },
      ],
    })
  })

  test('respond with JSONAPI response', async ({ assert }) => {
    const error = new E_INVALID_CREDENTIALS('Invalid credentials')

    const ctx = new HttpContextFactory().create()

    /**
     * Force JSONAPI response
     */
    ctx.request.request.headers.accept = 'application/vnd.api+json'
    await error.handle(error, ctx)

    assert.isUndefined(ctx.response.getHeader('location'))
    assert.deepEqual(ctx.response.getBody(), {
      errors: [
        {
          title: 'Invalid credentials',
          code: 'E_INVALID_CREDENTIALS',
        },
      ],
    })
  })

  test('translate error message using i18n', async ({ assert }) => {
    const error = new E_INVALID_CREDENTIALS('Invalid credentials')
    const i18nManager = new I18nManagerFactory()
      .merge({
        config: {
          loaders: [
            () => {
              return {
                async load() {
                  return {
                    en: {
                      'errors.E_INVALID_CREDENTIALS': 'Incorrect email or password',
                    },
                  }
                },
              }
            },
          ],
        },
      })
      .create()

    const ctx = new HttpContextFactory().create()
    await i18nManager.loadTranslations()
    ctx.i18n = i18nManager.locale('en')

    /**
     * Force JSON response
     */
    ctx.request.request.headers.accept = 'application/json'
    await error.handle(error, ctx)

    assert.isUndefined(ctx.response.getHeader('location'))
    assert.deepEqual(ctx.response.getBody(), {
      errors: [
        {
          message: 'Incorrect email or password',
        },
      ],
    })
  })
})
