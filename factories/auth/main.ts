/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { GUARD_KNOWN_EVENTS } from '../../src/symbols.ts'
import { E_UNAUTHORIZED_ACCESS } from '../../src/errors.ts'
import { type AuthClientResponse, type GuardContract } from '../../src/types.ts'

/**
 * @note
 * Should not be exported to the outside world
 */
export type FakeUser = {
  id: number
}

/**
 * Fake guard is an implementation of the auth guard contract
 * that uses in-memory values used for testing the auth
 * layer.
 *
 * @note
 * Should not be exported to the outside world
 */
export class FakeGuard implements GuardContract<FakeUser> {
  isAuthenticated: boolean = false
  authenticationAttempted: boolean = false
  driverName: string = 'fake'
  user?: FakeUser;

  declare [GUARD_KNOWN_EVENTS]: undefined

  getUserOrFail(): FakeUser {
    if (!this.user) {
      throw new E_UNAUTHORIZED_ACCESS('Unauthorized access', { guardDriverName: this.driverName })
    }
    return this.user
  }

  async authenticate(): Promise<FakeUser> {
    if (this.authenticationAttempted) {
      return this.getUserOrFail()
    }

    this.authenticationAttempted = true
    this.isAuthenticated = true
    this.user = {
      id: 1,
    }

    return this.user
  }

  async check(): Promise<boolean> {
    try {
      await this.authenticate()
      return true
    } catch {
      return false
    }
  }

  async authenticateAsClient(
    _user: FakeUser,
    _abilities?: string[],
    _expiresIn?: string | number
  ): Promise<AuthClientResponse> {
    return {}
  }
}
