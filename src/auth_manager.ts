/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { HttpContext } from '@adonisjs/core/http'

import type { GuardFactory } from './types.ts'
import { Authenticator } from './authenticator.ts'
import { AuthenticatorClient } from './authenticator_client.ts'

/**
 * Auth manager exposes the API to register and manage authentication
 * guards from the config
 */
export class AuthManager<KnownGuards extends Record<string, GuardFactory>> {
  /**
   * Name of the default guard
   */
  get defaultGuard() {
    return this.config.default
  }

  constructor(public config: { default: keyof KnownGuards; guards: KnownGuards }) {
    this.config = config
  }

  /**
   * Create an authenticator for a given HTTP request. The authenticator
   * is used to authenticated in incoming HTTP request
   */
  createAuthenticator(ctx: HttpContext) {
    return new Authenticator<KnownGuards>(ctx, this.config)
  }

  /**
   * Creates an instance of the authenticator client. The client is
   * used to setup authentication state during testing.
   */
  createAuthenticatorClient() {
    return new AuthenticatorClient<KnownGuards>(this.config)
  }
}
