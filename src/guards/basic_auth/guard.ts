/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import auth from 'basic-auth'
import type { HttpContext } from '@adonisjs/core/http'
import { Exception, RuntimeException } from '@poppinss/utils'
import type { EmitterLike } from '@adonisjs/core/types/events'

import debug from '../../auth/debug.js'
import type { BasicAuthGuardEvents } from './types.js'
import type { GuardContract } from '../../auth/types.js'
import type { UserProviderContract } from '../../core/types.js'
import { AuthenticationException } from '../../auth/errors.js'
import { PROVIDER_REAL_USER, GUARD_KNOWN_EVENTS } from '../../auth/symbols.js'

/**
 * Implementation of basic auth as an authentication guard
 */
export class BasicAuthGuard<UserProvider extends UserProviderContract<unknown>>
  implements GuardContract<UserProvider[typeof PROVIDER_REAL_USER]>
{
  declare [GUARD_KNOWN_EVENTS]: BasicAuthGuardEvents<UserProvider[typeof PROVIDER_REAL_USER]>

  /**
   * A unique name for the guard. It is used while
   * emitting events
   */
  #name: string

  /**
   * Reference to the current HTTP context
   */
  #ctx: HttpContext

  /**
   * Provider to lookup user details
   */
  #userProvider: UserProvider

  /**
   * Emitter to emit events
   */
  #emitter: EmitterLike<BasicAuthGuardEvents<UserProvider[typeof PROVIDER_REAL_USER]>>

  /**
   * Driver name of the guard
   */
  driverName: 'basic_auth' = 'basic_auth'

  /**
   * Whether or not the authentication has been attempted
   * during the current request
   */
  authenticationAttempted = false

  /**
   * A boolean to know if the current request has
   * been authenticated
   */
  isAuthenticated = false

  /**
   * Reference to an instance of the authenticated or logged-in
   * user. The value only exists after calling one of the
   * following methods.
   *
   * - authenticate
   *
   * You can use the "getUserOrFail" method to throw an exception if
   * the request is not authenticated.
   */
  user?: UserProvider[typeof PROVIDER_REAL_USER]

  constructor(
    name: string,
    ctx: HttpContext,
    emitter: EmitterLike<BasicAuthGuardEvents<UserProvider[typeof PROVIDER_REAL_USER]>>,
    userProvider: UserProvider
  ) {
    this.#ctx = ctx
    this.#name = name
    this.#emitter = emitter
    this.#userProvider = userProvider
  }

  /**
   * Notifies about authentication failure and throws the exception
   */
  #authenticationFailed(error: Exception): never {
    this.#emitter.emit('basic_auth:authentication_failed', {
      ctx: this.#ctx,
      guardName: this.#name,
      error,
    })
    throw error
  }

  /**
   * Returns an instance of the authenticated user. Or throws
   * an exception if the request is not authenticated.
   */
  getUserOrFail(): UserProvider[typeof PROVIDER_REAL_USER] {
    if (!this.user) {
      throw AuthenticationException.E_INVALID_BASIC_AUTH_CREDENTIALS()
    }
    return this.user
  }

  /**
   * Verifies user credentials and returns an instance of
   * the user or throws "E_INVALID_BASIC_AUTH_CREDENTIALS" exception.
   */
  async verifyCredentials(
    uid: string,
    password: string
  ): Promise<UserProvider[typeof PROVIDER_REAL_USER]> {
    debug('basic_auth_guard: attempting to verify credentials for uid "%s"', uid)

    /**
     * Attempt to verify credentials and raise error if they are invalid
     */
    const providerUser = await this.#userProvider.verifyCredentials(uid, password)
    if (!providerUser) {
      this.#authenticationFailed(AuthenticationException.E_INVALID_BASIC_AUTH_CREDENTIALS())
    }

    return providerUser.getOriginal()
  }

  /**
   * Authenticates the current HTTP request for basic
   * auth credentials
   */
  async authenticate(): Promise<UserProvider[typeof PROVIDER_REAL_USER]> {
    /**
     * Avoid re-authenticating when already authenticated
     */
    if (this.authenticationAttempted) {
      return this.getUserOrFail()
    }

    /**
     * Beginning authentication attempt
     */
    this.authenticationAttempted = true
    this.#emitter.emit('basic_auth:authentication_attempted', {
      ctx: this.#ctx,
      guardName: this.#name,
    })

    /**
     * Fetch credentials from the header
     */
    const credentials = auth(this.#ctx.request.request)
    if (!credentials) {
      this.#authenticationFailed(AuthenticationException.E_INVALID_BASIC_AUTH_CREDENTIALS())
    }

    debug('basic_auth_guard: authenticating user using credentials')

    /**
     * Verifying user credentials
     */
    this.user = await this.verifyCredentials(credentials.name, credentials.pass)
    this.isAuthenticated = true

    debug('basic_auth_guard: marking user as authenticated')

    this.#emitter.emit('basic_auth:authentication_succeeded', {
      ctx: this.#ctx,
      guardName: this.#name,
      user: this.user,
    })

    /**
     * Return user
     */
    return this.getUserOrFail()
  }

  /**
   * Silently attempt to authenticate the user.
   *
   * The method returns a boolean indicating if the authentication
   * succeeded or failed.
   */
  async check(): Promise<boolean> {
    try {
      await this.authenticate()
      return true
    } catch (error) {
      if (error instanceof AuthenticationException) {
        return false
      }

      throw error
    }
  }

  /**
   * Not support
   */
  async authenticateAsClient(_: UserProvider[typeof PROVIDER_REAL_USER]): Promise<never> {
    throw new RuntimeException('Cannot authenticate as a client when using basic auth')
  }
}