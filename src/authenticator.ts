/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { HttpContext } from '@adonisjs/core/http'
import { RuntimeException } from '@adonisjs/core/exceptions'

import debug from './debug.js'
import type { GuardFactory } from './types.js'
import { E_UNAUTHORIZED_ACCESS } from './errors.js'

/**
 * Authenticator is used to authenticate incoming HTTP requests
 * using one or more known guards.
 */
export class Authenticator<KnownGuards extends Record<string, GuardFactory>> {
  /**
   * Registered guards
   */
  #config: {
    default: keyof KnownGuards
    guards: KnownGuards
  }

  /**
   * Cache of guards created during the HTTP request
   */
  #guardsCache: Partial<Record<keyof KnownGuards, unknown>> = {}

  /**
   * Last guard that was used to perform the authentication via
   * the "authenticateUsing" method.
   *
   * @note
   * Reset on every call made to "authenticate", "check" and
   * "authenticateUsing" method.
   */
  #authenticationAttemptedViaGuard?: keyof KnownGuards

  /**
   * Name of the guard using which the request has
   * been authenticated successfully.
   *
   * @note
   * Reset on every call made to "authenticate", "check" and
   * "authenticateUsing" method.
   */
  #authenticatedViaGuard?: keyof KnownGuards

  /**
   * Reference to HTTP context
   */
  #ctx: HttpContext

  /**
   * Name of the default guard
   */
  get defaultGuard(): keyof KnownGuards {
    return this.#config.default
  }

  /**
   * Reference to the guard using which the current
   * request has been authenticated.
   */
  get authenticatedViaGuard(): keyof KnownGuards | undefined {
    return this.#authenticatedViaGuard
  }

  /**
   * A boolean to know if the current request has been authenticated. The
   * property returns false when "authenticate" or "authenticateUsing"
   * methods are not used.
   */
  get isAuthenticated(): boolean {
    if (!this.#authenticationAttemptedViaGuard) {
      return false
    }

    return this.use(this.#authenticationAttemptedViaGuard).isAuthenticated
  }

  /**
   * Reference to the currently authenticated user. The property returns
   * undefined when "authenticate" or "authenticateUsing" methods are
   * not used.
   */
  get user(): {
    [K in keyof KnownGuards]: ReturnType<KnownGuards[K]>['user']
  }[keyof KnownGuards] {
    if (!this.#authenticationAttemptedViaGuard) {
      return undefined
    }

    return this.use(this.#authenticationAttemptedViaGuard).user
  }

  /**
   * Whether or not the authentication has been attempted during
   * the current request. The property returns false when the
   * "authenticate" or "authenticateUsing" methods are not
   * used.
   */
  get authenticationAttempted(): boolean {
    if (!this.#authenticationAttemptedViaGuard) {
      return false
    }

    return this.use(this.#authenticationAttemptedViaGuard).authenticationAttempted
  }

  constructor(ctx: HttpContext, config: { default: keyof KnownGuards; guards: KnownGuards }) {
    this.#ctx = ctx
    this.#config = config
    debug('creating authenticator. config %O', this.#config)
  }

  /**
   * Returns an instance of the logged-in user or throws an
   * exception
   */
  getUserOrFail(): {
    [K in keyof KnownGuards]: ReturnType<ReturnType<KnownGuards[K]>['getUserOrFail']>
  }[keyof KnownGuards] {
    if (!this.#authenticatedViaGuard) {
      throw new RuntimeException(
        'Cannot access authenticated user. Please call "auth.authenticate" method first.'
      )
    }

    return this.use(this.#authenticatedViaGuard).getUserOrFail() as {
      [K in keyof KnownGuards]: ReturnType<ReturnType<KnownGuards[K]>['getUserOrFail']>
    }[keyof KnownGuards]
  }

  /**
   * Returns an instance of a known guard. Guards instances are
   * cached during the lifecycle of an HTTP request.
   */
  use<Guard extends keyof KnownGuards>(guard?: Guard): ReturnType<KnownGuards[Guard]> {
    const guardToUse = guard || this.#config.default

    /**
     * Use cached copy if exists
     */
    const cachedGuard = this.#guardsCache[guardToUse]
    if (cachedGuard) {
      debug('authenticator: using guard from cache. name: "%s"', guardToUse)
      return cachedGuard as ReturnType<KnownGuards[Guard]>
    }

    const guardFactory = this.#config.guards[guardToUse]

    /**
     * Construct guard and cache it
     */
    debug('authenticator: creating guard. name: "%s"', guardToUse)
    const guardInstance = guardFactory(this.#ctx)
    this.#guardsCache[guardToUse] = guardInstance

    return guardInstance as ReturnType<KnownGuards[Guard]>
  }

  /**
   * Authenticate current request using the default guard. Calling this
   * method multiple times triggers multiple authentication with the
   * guard.
   */
  authenticate() {
    return this.authenticateUsing()
  }

  /**
   * Silently attempt to authenticate the request using the default
   * guard. Calling this method multiple times triggers multiple
   * authentication with the guard.
   */
  async check() {
    this.#authenticationAttemptedViaGuard = this.defaultGuard
    const isAuthenticated = await this.use().check()
    if (isAuthenticated) {
      this.#authenticatedViaGuard = this.defaultGuard
    }

    return isAuthenticated
  }

  /**
   * Authenticate the request using all of the mentioned guards
   * or the default guard.
   *
   * The authentication process will stop after any of the mentioned
   * guards is able to authenticate the request successfully.
   *
   * Otherwise, "E_UNAUTHORIZED_ACCESS" will be raised.
   */
  async authenticateUsing(
    guards?: (keyof KnownGuards)[],
    options?: { loginRoute?: string }
  ): Promise<boolean> {
    const guardsToUse = guards || [this.defaultGuard]
    let lastUsedDriver: string | undefined

    for (let guardName of guardsToUse) {
      debug('attempting to authenticate using guard "%s"', guardName)

      this.#authenticationAttemptedViaGuard = guardName
      const guard = this.use(guardName)
      lastUsedDriver = guard.driverName

      if (await guard.check()) {
        this.#authenticatedViaGuard = guardName
        return true
      }
    }

    throw new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: lastUsedDriver!,
      redirectTo: options?.loginRoute,
    })
  }
}
