/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { type Secret } from '@adonisjs/core/helpers'
import { setTimeout } from 'node:timers/promises'
import stringHelpers from '@adonisjs/core/helpers/string'

import { PROVIDER_REAL_USER } from '../../src/symbols.js'
import {
  type RememberMeTokenDbColumns,
  type SessionUserProviderContract,
  type SessionWithTokensUserProviderContract,
} from '../../modules/session_guard/types.js'
import { RememberMeToken } from '../../modules/session_guard/remember_me_token.js'

/**
 * Representation of a fake user used to test
 * the session guard.
 *
 * @note
 * Should not be exported to the outside world
 */
export type SessionFakeUser = {
  id: number
  email: string
  password: string
}

/**
 * Collection of dummy users
 */
const users: SessionFakeUser[] = [
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
 * Implementation of a user provider to be used by session guard for
 * authentication. Used for testing.
 *
 * @note
 * Should not be exported to the outside world
 */
export class SessionFakeUserProvider implements SessionUserProviderContract<SessionFakeUser> {
  declare [PROVIDER_REAL_USER]: SessionFakeUser

  /**
   * Creates the adapter user for the guard
   */
  async createUserForGuard(user: SessionFakeUser) {
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
   * Finds a user id
   */
  async findById(id: number) {
    const user = users.find(({ id: userId }) => userId === id)
    if (!user) {
      return null
    }

    return this.createUserForGuard(user)
  }
}

/**
 * Implementation with tokens methods as well
 *
 * @note
 * Should not be exported to the outside world
 */
export class SessionFakeUserWithTokensProvider
  extends SessionFakeUserProvider
  implements SessionWithTokensUserProviderContract<SessionFakeUser>
{
  tokens: RememberMeTokenDbColumns[] = []

  /**
   * Creates a remember me token for a given user
   */
  async createRememberToken(
    user: SessionFakeUser,
    expiresIn: string | number
  ): Promise<RememberMeToken> {
    const transientToken = RememberMeToken.createTransientToken(user.id, 40, expiresIn)
    const id = stringHelpers.random(15)
    const createdAt = new Date()
    const updatedAt = new Date()

    this.tokens.push({
      id,
      tokenable_id: user.id,
      hash: transientToken.hash,
      created_at: createdAt,
      updated_at: updatedAt,
      expires_at: transientToken.expiresAt,
    })

    return new RememberMeToken({
      identifier: id,
      tokenableId: user.id,
      hash: transientToken.hash,
      secret: transientToken.secret,
      createdAt,
      updatedAt,
      expiresAt: transientToken.expiresAt,
    })
  }

  /**
   * Deletes token by the token id
   */
  async deleteRemeberToken(
    _: SessionFakeUser,
    tokenIdentifier: string | number | BigInt
  ): Promise<number> {
    this.tokens = this.tokens.filter((token) => token.id !== tokenIdentifier)
    return 1
  }

  /**
   * Verifies a given token
   */
  async verifyRememberToken(tokenValue: Secret<string>): Promise<RememberMeToken | null> {
    const decodedToken = RememberMeToken.decode(tokenValue.release())
    if (!decodedToken) {
      return null
    }

    const token = this.tokens.find(({ id }) => id === decodedToken.identifier)
    if (!token) {
      return null
    }

    const rememberMeToken = new RememberMeToken({
      identifier: token.id,
      tokenableId: token.tokenable_id,
      hash: token.hash,
      createdAt: token.created_at,
      updatedAt: token.updated_at,
      expiresAt: token.expires_at,
    })

    if (!rememberMeToken.verify(decodedToken.secret) || rememberMeToken.isExpired()) {
      return null
    }

    return rememberMeToken
  }

  /**
   * Recycles token by deleting the old one and creating a new one
   */
  async recycleRememberToken(
    user: SessionFakeUser,
    tokenIdentifier: string | number | BigInt,
    expiresIn: string | number
  ): Promise<RememberMeToken> {
    await this.deleteRemeberToken(user, tokenIdentifier)
    await setTimeout(100)
    return this.createRememberToken(user, expiresIn)
  }
}
