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
import { EncryptionFactory } from '@adonisjs/core/factories/encryption'
import { SessionMiddlewareFactory } from '@adonisjs/session/factories'
import { HttpContextFactory, RequestFactory, ResponseFactory } from '@adonisjs/core/factories/http'

const encryption = new EncryptionFactory().create()

import { E_UNAUTHORIZED_ACCESS } from '../../src/errors.ts'

test.group('Errors | E_UNAUTHORIZED_ACCESS | session', () => {
  test('report error via flash messages and redirect', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'session',
    })

    const ctx = new HttpContextFactory().create()
    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.deepEqual(ctx.session.responseFlashMessages.all(), {
      error: 'Unauthorized access',
      errorsBag: { E_UNAUTHORIZED_ACCESS: 'Unauthorized access' },
      input: {},
    })
    assert.equal(ctx.response.getHeader('location'), '/')
  })

  test('redirect to a custom location', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'session',
      redirectTo: '/login',
    })

    const ctx = new HttpContextFactory().create()
    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.deepEqual(ctx.session.responseFlashMessages.all(), {
      error: 'Unauthorized access',
      errorsBag: { E_UNAUTHORIZED_ACCESS: 'Unauthorized access' },
      input: {},
    })
    assert.equal(ctx.response.getHeader('location'), '/login')
  })

  test('store intended URL in session for GET navigational requests', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'session',
      redirectTo: '/login',
    })

    const request = new RequestFactory()
      .merge({ encryption, url: '/billing?plan=pro', method: 'GET' })
      .create()
    const response = new ResponseFactory().merge({ encryption }).create()
    response.request.url = request.url(true)
    const ctx = new HttpContextFactory().merge({ request, response }).create()
    ctx.route = { pattern: '/billing', handler: {} } as any

    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.equal(ctx.session.get('redirect.intendedUrl'), '/billing?plan=pro')
    assert.equal(ctx.response.getHeader('location'), '/login?plan=pro')
  })

  test('store intended URL for Inertia requests', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'session',
      redirectTo: '/login',
    })

    const request = new RequestFactory()
      .merge({ encryption, url: '/billing', method: 'GET' })
      .create()
    request.request.headers['x-inertia'] = 'true'
    const response = new ResponseFactory().merge({ encryption }).create()
    response.request.url = request.url(true)
    const ctx = new HttpContextFactory().merge({ request, response }).create()
    ctx.route = { pattern: '/billing', handler: {} } as any

    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.equal(ctx.session.get('redirect.intendedUrl'), '/billing')
  })

  test('do not store intended URL for AJAX requests', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'session',
      redirectTo: '/login',
    })

    const request = new RequestFactory()
      .merge({ encryption, url: '/billing', method: 'GET' })
      .create()
    request.request.headers['x-requested-with'] = 'XMLHttpRequest'
    const response = new ResponseFactory().merge({ encryption }).create()
    const ctx = new HttpContextFactory().merge({ request, response }).create()
    ctx.route = { pattern: '/billing', handler: {} } as any

    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.isNull(ctx.session.get('redirect.intendedUrl', null))
  })

  test('do not store intended URL for non-GET requests', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'session',
      redirectTo: '/login',
    })

    const request = new RequestFactory()
      .merge({ encryption, url: '/billing', method: 'POST' })
      .create()
    const response = new ResponseFactory().merge({ encryption }).create()
    const ctx = new HttpContextFactory().merge({ request, response }).create()
    ctx.route = { pattern: '/billing', handler: {} } as any

    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.isNull(ctx.session.get('redirect.intendedUrl', null))
  })

  test('do not store intended URL when no route is matched', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'session',
      redirectTo: '/login',
    })

    const request = new RequestFactory()
      .merge({ encryption, url: '/not-found', method: 'GET' })
      .create()
    const response = new ResponseFactory().merge({ encryption }).create()
    const ctx = new HttpContextFactory().merge({ request, response }).create()

    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.isNull(ctx.session.get('redirect.intendedUrl', null))
  })

  test('respond with json', async ({ assert }) => {
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'session',
    })

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
          message: 'Unauthorized access',
        },
      ],
    })
  })

  test('respond with JSONAPI response', async ({ assert }) => {
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'session',
    })

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
          title: 'Unauthorized access',
          code: 'E_UNAUTHORIZED_ACCESS',
        },
      ],
    })
  })

  test('translate error message using i18n', async ({ assert }) => {
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'session',
    })
    const i18nManager = new I18nManagerFactory()
      .merge({
        config: {
          loaders: [
            () => {
              return {
                async load() {
                  return {
                    en: {
                      'errors.E_UNAUTHORIZED_ACCESS': 'Access denied',
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
          message: 'Access denied',
        },
      ],
    })
  })
})

test.group('Errors | E_UNAUTHORIZED_ACCESS | access_tokens', () => {
  test('convert error to a string based response', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'access_tokens',
    })

    const ctx = new HttpContextFactory().create()
    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.isUndefined(ctx.response.getHeader('location'))
    assert.deepEqual(ctx.response.getBody(), 'Unauthorized access')
  })

  test('respond with json', async ({ assert }) => {
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'access_tokens',
    })

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
          message: 'Unauthorized access',
        },
      ],
    })
  })

  test('respond with JSONAPI response', async ({ assert }) => {
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'access_tokens',
    })

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
          title: 'Unauthorized access',
          code: 'E_UNAUTHORIZED_ACCESS',
        },
      ],
    })
  })

  test('translate error message using i18n', async ({ assert }) => {
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'access_tokens',
    })
    const i18nManager = new I18nManagerFactory()
      .merge({
        config: {
          loaders: [
            () => {
              return {
                async load() {
                  return {
                    en: {
                      'errors.E_UNAUTHORIZED_ACCESS': 'Access denied',
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
          message: 'Access denied',
        },
      ],
    })
  })
})

test.group('Errors | E_UNAUTHORIZED_ACCESS | basic auth', () => {
  test('handle basic auth exception with a prompt', async ({ assert }) => {
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'basic_auth',
    })

    const ctx = new HttpContextFactory().create()
    await error.handle(error, ctx)

    assert.equal(
      ctx.response.getHeader('WWW-Authenticate'),
      `Basic realm="Authenticate", charset="UTF-8"`
    )
  })
})

test.group('Errors | E_UNAUTHORIZED_ACCESS | unknown guard', () => {
  test('send plain text response', async ({ assert }) => {
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: 'foo',
    })

    const ctx = new HttpContextFactory().create()
    await error.handle(error, ctx)

    assert.equal(ctx.response.getStatus(), 401)
    assert.equal(ctx.response.getBody(), 'Unauthorized access')
  })
})
