/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import auth from 'basic-auth'
import { base64 } from '@adonisjs/core/helpers'
import type { HttpContext } from '@adonisjs/core/http'
import type { EmitterLike } from '@adonisjs/core/types/events'

import { E_UNAUTHORIZED_ACCESS } from '../../src/errors.ts'
import type { AuthClientResponse, GuardContract } from '../../src/types.ts'
import { GUARD_KNOWN_EVENTS, type PROVIDER_REAL_USER } from '../../src/symbols.ts'
import type { BasicAuthGuardEvents, BasicAuthUserProviderContract } from './types.ts'

/**
 * BasicAuth guard implements the HTTP Authentication protocol
 */
export class BasicAuthGuard<UserProvider extends BasicAuthUserProviderContract<unknown>>
  implements GuardContract<UserProvider[typeof PROVIDER_REAL_USER]>
{
  /**
   * Events emitted by the guard
   */
  declare [GUARD_KNOWN_EVENTS]: BasicAuthGuardEvents<UserProvider[typeof PROVIDER_REAL_USER]>

  /**
   * A unique name for the guard.
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
   * during the current request.
   */
  authenticationAttempted = false

  /**
   * A boolean to know if the current request has
   * been authenticated
   */
  isAuthenticated = false

  /**
   * Reference to an instance of the authenticated user.
   * The value only exists after calling one of the
   * following methods.
   *
   * - authenticate
   * - check
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
    this.#name = name
    this.#ctx = ctx
    this.#emitter = emitter
    this.#userProvider = userProvider
  }

  /**
   * Emits authentication failure, updates the local state,
   * and returns an exception to end the authentication
   * cycle.
   */
  #authenticationFailed() {
    this.isAuthenticated = false
    this.user = undefined

    const error = new E_UNAUTHORIZED_ACCESS('Invalid basic auth credentials', {
      guardDriverName: this.driverName,
    })

    this.#emitter.emit('basic_auth:authentication_failed', {
      ctx: this.#ctx,
      guardName: this.#name,
      error,
    })

    return error
  }

  /**
   * Emits the authentication succeeded event and updates
   * the local state to reflect successful authentication
   */
  #authenticationSucceeded(user: UserProvider[typeof PROVIDER_REAL_USER]) {
    this.isAuthenticated = true
    this.user = user

    this.#emitter.emit('basic_auth:authentication_succeeded', {
      ctx: this.#ctx,
      guardName: this.#name,
      user,
    })
  }

  /**
   * Returns an instance of the authenticated user. Or throws
   * an exception if the request is not authenticated.
   */
  getUserOrFail(): UserProvider[typeof PROVIDER_REAL_USER] {
    if (!this.user) {
      throw new E_UNAUTHORIZED_ACCESS('Invalid basic auth credentials', {
        guardDriverName: this.driverName,
      })
    }

    return this.user
  }

  /**
   * Authenticates the incoming HTTP request by looking for BasicAuth
   * credentials inside the request authorization header.
   *
   * Returns the authenticated user or throws an exception.
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
     * Fetch credentials from the header or fail
     */
    const credentials = auth(this.#ctx.request.request)
    if (!credentials) {
      throw this.#authenticationFailed()
    }

    /**
     * Verify user credentials or fail
     */
    const user = await this.#userProvider.verifyCredentials(credentials.name, credentials.pass)
    if (!user) {
      throw this.#authenticationFailed()
    }

    /**
     * Mark user as authenticated
     */
    this.#authenticationSucceeded(user.getOriginal())
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
      if (error instanceof E_UNAUTHORIZED_ACCESS) {
        return false
      }

      throw error
    }
  }

  /**
   * Does not support authenticating as client. Instead use "basicAuth"
   * helper on Japa APIClient
   */
  async authenticateAsClient(uid: string, password: string): Promise<AuthClientResponse> {
    return {
      headers: {
        authorization: `Basic ${base64.encode(`${uid}:${password}`)}`,
      },
    }
  }
}
