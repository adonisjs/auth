/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { I18n } from '@adonisjs/i18n'
import { Exception } from '@adonisjs/core/exceptions'
import type { HttpContext } from '@adonisjs/core/http'

/**
 * The "E_UNAUTHORIZED_ACCESS" exception is raised when unable to
 * authenticate an incoming HTTP request.
 *
 * The "error.guardDriverName" can be used to know the driver which
 * raised the error.
 */
export const E_UNAUTHORIZED_ACCESS = class extends Exception {
  static status: number = 401
  static code: string = 'E_UNAUTHORIZED_ACCESS'

  /**
   * Endpoint to redirect to. Only used by "session" driver
   * renderer
   */
  redirectTo?: string

  /**
   * Translation identifier. Can be customized
   */
  identifier: string = 'errors.E_UNAUTHORIZED_ACCESS'

  /**
   * The guard name reference that raised the exception. It allows
   * us to customize the logic of handling the exception.
   */
  guardDriverName: string

  /**
   * A collection of renderers to render the exception to a
   * response.
   *
   * The collection is a key-value pair, where the key is
   * the guard driver name and value is a factory function
   * to respond to the request.
   */
  renderers: Record<
    string,
    (message: string, error: this, ctx: HttpContext) => Promise<void> | void
  > = {
    /**
     * Response when session driver is used
     */
    session: (message, error, ctx) => {
      switch (ctx.request.accepts(['html', 'application/vnd.api+json', 'json'])) {
        case 'html':
        case null:
          ctx.session.flashExcept(['_csrf'])
          ctx.session.flash('error', message)
          /**
           * The "flashErrors" call must be removed in the future
           */
          ctx.session.flashErrors({ [error.code!]: message })
          ctx.response.redirect(error.redirectTo || '/', true)
          break
        case 'json':
          ctx.response.status(error.status).send({
            errors: [
              {
                message,
              },
            ],
          })
          break
        case 'application/vnd.api+json':
          ctx.response.status(error.status).send({
            errors: [
              {
                code: error.code,
                title: message,
              },
            ],
          })
          break
      }
    },

    /**
     * Response when basic auth driver is used
     */
    basic_auth: (message, _, ctx) => {
      ctx.response
        .status(this.status)
        .header('WWW-Authenticate', `Basic realm="Authenticate", charset="UTF-8"`)
        .send(message)
    },

    /**
     * Response when access tokens driver is used
     */
    access_tokens: (message, error, ctx) => {
      switch (ctx.request.accepts(['html', 'application/vnd.api+json', 'json'])) {
        case 'html':
        case null:
          ctx.response.status(error.status).send(message)
          break
        case 'json':
          ctx.response.status(error.status).send({
            errors: [
              {
                message,
              },
            ],
          })
          break
        case 'application/vnd.api+json':
          ctx.response.status(error.status).send({
            errors: [
              {
                code: error.code,
                title: message,
              },
            ],
          })
          break
      }
    },
  }

  /**
   * Returns the message to be sent in the HTTP response.
   * Feel free to override this method and return a custom
   * response.
   *
   * @param error - The error instance
   * @param ctx - The HTTP context
   *
   * @example
   * const message = error.getResponseMessage(error, ctx)
   * console.log('Error message:', message)
   */
  getResponseMessage(error: this, ctx: HttpContext) {
    if ('i18n' in ctx) {
      return (ctx.i18n as I18n).t(error.identifier, {}, error.message)
    }
    return error.message
  }

  /**
   * Creates a new E_UNAUTHORIZED_ACCESS exception
   *
   * @param message - The error message
   * @param options - Options including redirectTo and guardDriverName
   *
   * @example
   * throw new E_UNAUTHORIZED_ACCESS('Access denied', {
   *   guardDriverName: 'session',
   *   redirectTo: '/login'
   * })
   */
  constructor(
    message: string,
    options: {
      redirectTo?: string
      guardDriverName: string
    }
  ) {
    super(message, {})
    this.guardDriverName = options.guardDriverName
    this.redirectTo = options.redirectTo
  }

  /**
   * Converts exception to an HTTP response
   *
   * @param error - The error instance
   * @param ctx - The HTTP context
   *
   * @example
   * // This method is called automatically by AdonisJS
   * await error.handle(error, ctx)
   */
  async handle(error: this, ctx: HttpContext) {
    const renderer = this.renderers[this.guardDriverName]
    const message = error.getResponseMessage(error, ctx)

    if (!renderer) {
      return ctx.response.status(error.status).send(message)
    }

    return renderer(message, error, ctx)
  }
}

/**
 * Exception is raised when user credentials are invalid
 *
 * @example
 * throw new E_INVALID_CREDENTIALS('Invalid email or password')
 */
export const E_INVALID_CREDENTIALS = class extends Exception {
  static status: number = 400
  static code: string = 'E_INVALID_CREDENTIALS'

  /**
   * Translation identifier. Can be customized
   */
  identifier: string = 'errors.E_INVALID_CREDENTIALS'

  /**
   * Returns the message to be sent in the HTTP response.
   * Feel free to override this method and return a custom
   * response.
   *
   * @param error - The error instance
   * @param ctx - The HTTP context
   *
   * @example
   * const message = error.getResponseMessage(error, ctx)
   * console.log('Error message:', message)
   */
  getResponseMessage(error: this, ctx: HttpContext) {
    if ('i18n' in ctx) {
      return (ctx.i18n as I18n).t(error.identifier, {}, error.message)
    }
    return error.message
  }

  /**
   * Converts exception to an HTTP response
   *
   * @param error - The error instance
   * @param ctx - The HTTP context
   *
   * @example
   * // This method is called automatically by AdonisJS
   * await error.handle(error, ctx)
   */
  async handle(error: this, ctx: HttpContext) {
    const message = this.getResponseMessage(error, ctx)

    switch (ctx.request.accepts(['html', 'application/vnd.api+json', 'json'])) {
      case 'html':
      case null:
        if (ctx.session) {
          ctx.session.flashExcept(['_csrf', '_method', 'password', 'password_confirmation'])
          ctx.session.flash('error', message)
          /**
           * The "flashErrors" call must be removed in the future
           */
          ctx.session.flashErrors({ [error.code!]: message })
          ctx.response.redirect('back', true)
        } else {
          ctx.response.status(error.status).send(message)
        }
        break
      case 'json':
        ctx.response.status(error.status).send({
          errors: [
            {
              message,
            },
          ],
        })
        break
      case 'application/vnd.api+json':
        ctx.response.status(error.status).send({
          errors: [
            {
              code: error.code,
              title: message,
            },
          ],
        })
        break
    }
  }
}
