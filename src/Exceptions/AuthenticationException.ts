/*
 * @adonisjs/auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Exception } from '@poppinss/utils'
import { GuardsList } from '@ioc:Adonis/Addons/Auth'
import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'

/**
 * Exception raised when unable to authenticate user session
 */
export class AuthenticationException extends Exception {
  public guard: string
  public redirectTo: string = '/login'
  public responseText = this.message

  /**
   * Raise exception with message and redirect url
   */
  constructor(message: string, code: string, guard?: string, redirectTo?: string) {
    super(message, 401, code)
    if (redirectTo) {
      this.redirectTo = redirectTo
    }

    if (guard) {
      this.guard = guard
    }
  }

  /**
   * Prompts user to enter credentials
   */
  protected respondWithBasicAuthPrompt(ctx: HttpContextContract, realm?: string) {
    realm = realm || 'Authenticate'

    ctx.response
      .status(this.status)
      .header('WWW-Authenticate', `Basic realm="${realm}", charset="UTF-8"`)
      .send(this.responseText)
  }

  /**
   * Send response as an array of errors
   */
  protected respondWithJson(ctx: HttpContextContract) {
    ctx.response.status(this.status).send({
      errors: [
        {
          message: this.responseText,
        },
      ],
    })
  }

  /**
   * Flash error message and redirect the user back
   */
  protected respondWithRedirect(ctx: HttpContextContract) {
    if (!ctx.session) {
      return ctx.response.status(this.status).send(this.responseText)
    }

    ctx.session.flashExcept(['_csrf'])
    ctx.session.flash('auth', { error: this.responseText })
    ctx.response.redirect(this.redirectTo, true)
  }

  /**
   * Send response as an array of errors formatted as per JSONAPI spec
   */
  protected respondWithJsonAPI(ctx: HttpContextContract) {
    ctx.response.status(this.status).send({
      errors: [
        {
          code: this.code,
          title: this.responseText,
          source: null,
        },
      ],
    })
  }

  /**
   * Missing session or unable to lookup user from session
   */
  public static invalidSession(guard: string) {
    return new this('Invalid session', 'E_INVALID_AUTH_SESSION', guard)
  }

  /**
   * Missing/Invalid token or unable to lookup user from the token
   */
  public static invalidToken(guard: string) {
    return new this('Invalid API token', 'E_INVALID_API_TOKEN', guard)
  }

  /**
   * Missing or invalid basic auth credentials
   */
  public static invalidBasicCredentials(guard: string) {
    return new this('Invalid basic auth credentials', 'E_INVALID_BASIC_CREDENTIALS', guard)
  }

  /**
   * Self handle exception and attempt to make the best response based
   * upon the type of request
   */
  public async handle(_: AuthenticationException, ctx: HttpContextContract) {
    /**
     * We need access to the guard config and driver to make appropriate response
     */
    const config = this.guard ? ctx.auth.use(this.guard as keyof GuardsList).config : null

    /**
     * Use translation when using i18n
     */
    if ('i18n' in ctx) {
      this.responseText = ctx.i18n.formatMessage(`auth.${this.code}`, {}, this.message)
    }

    /**
     * Show username, password prompt when using basic auth driver
     */
    if (config && config.driver === 'basic') {
      this.respondWithBasicAuthPrompt(ctx, config.realm)
      return
    }

    /**
     * Respond with json for ajax requests
     */
    if (ctx.request.ajax()) {
      this.respondWithJson(ctx)
      return
    }

    /**
     * Uses content negotiation to make the response
     */
    switch (ctx.request.accepts(['html', 'application/vnd.api+json', 'json'])) {
      case 'html':
      case null:
        this.respondWithRedirect(ctx)
        break
      case 'json':
        this.respondWithJson(ctx)
        break
      case 'application/vnd.api+json':
        this.respondWithJsonAPI(ctx)
        break
    }
  }
}
