/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import debug from './debug.js'
import type { GuardFactory } from './types.js'
import { HttpContextFactory } from '@adonisjs/core/factories/http'

/**
 * Authenticator client is used to create guard instances for
 * testing. It passes a fake HTTPContext to the guards, so
 * make sure to not call server side APIs that might be
 * relying on a real HTTPContext instance
 */
export class AuthenticatorClient<KnownGuards extends Record<string, GuardFactory>> {
  /**
   * Registered guards
   */
  #config: {
    default: keyof KnownGuards
    guards: KnownGuards
  }

  /**
   * Cache of guards
   */
  #guardsCache: Partial<Record<keyof KnownGuards, unknown>> = {}

  /**
   * Name of the default guard
   */
  get defaultGuard(): keyof KnownGuards {
    return this.#config.default
  }

  constructor(config: { default: keyof KnownGuards; guards: KnownGuards }) {
    this.#config = config
    debug('creating authenticator client. config %O', this.#config)
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
      debug('using guard from cache. name: "%s"', guardToUse)
      return cachedGuard as ReturnType<KnownGuards[Guard]>
    }

    const guardFactory = this.#config.guards[guardToUse]

    /**
     * Construct guard and cache it
     */
    debug('creating guard. name: "%s"', guardToUse)
    const guardInstance = guardFactory(new HttpContextFactory().create())
    this.#guardsCache[guardToUse] = guardInstance

    return guardInstance as ReturnType<KnownGuards[Guard]>
  }
}
