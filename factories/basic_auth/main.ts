/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { PROVIDER_REAL_USER } from '../../src/symbols.js'
import {
  type BasicAuthGuardUser,
  type BasicAuthUserProviderContract,
} from '../../modules/basic_auth_guard/types.js'

/**
 * Representation of a fake user used to test
 * the basic auth guard.
 *
 * @note
 * Should not be exported to the outside world
 */
export type BasicAuthFakeUser = {
  id: number
  email: string
  password: string
}

/**
 * Collection of dummy users
 */
const users: BasicAuthFakeUser[] = [
  {
    id: 1,
    email: 'virk@adonisjs.com',
    password: 'secret',
  },
  {
    id: 2,
    email: 'romain@adonisjs.com',
    password: 'secret',
  },
]

/**
 * Implementation of a user provider to be used by basic auth guard for
 * authentication. Used for testing.
 *
 * @note
 * Should not be exported to the outside world
 */
export class BasicAuthFakeUserProvider implements BasicAuthUserProviderContract<BasicAuthFakeUser> {
  declare [PROVIDER_REAL_USER]: BasicAuthFakeUser

  /**
   * Creates the adapter user for the guard
   */
  async createUserForGuard(user: BasicAuthFakeUser) {
    return {
      getId() {
        return user.id
      },
      getOriginal() {
        return user
      },
    }
  }

  /**
   * Verifies user credentials
   */
  async verifyCredentials(
    uid: string,
    password: string
  ): Promise<BasicAuthGuardUser<BasicAuthFakeUser> | null> {
    const user = users.find(({ email }) => email === uid)
    if (!user) {
      return null
    }

    if (user.password === password) {
      return this.createUserForGuard(user)
    }

    return null
  }
}
