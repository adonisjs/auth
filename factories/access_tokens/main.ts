/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { type Secret } from '@adonisjs/core/helpers'
import stringHelpers from '@adonisjs/core/helpers/string'
import { PROVIDER_REAL_USER } from '../../src/symbols.ts'
import { AccessToken } from '../../modules/access_tokens_guard/access_token.ts'
import { type AccessTokensUserProviderContract } from '../../modules/access_tokens_guard/types.ts'

/**
 * Representation of a fake user used to test
 * the access token guard.
 *
 * @note
 * Should not be exported to the outside world
 */
export type AccessTokensFakeUser = {
  id: number
  email: string
  password: string
}

/**
 * Collection of dummy users
 */
const users: AccessTokensFakeUser[] = [
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
 * Implementation of a user provider to be used by access tokens
 * guard for authentication. Used for testing.
 *
 * @note
 * Should not be exported to the outside world
 */
export class AccessTokensFakeUserProvider
  implements AccessTokensUserProviderContract<AccessTokensFakeUser>
{
  declare [PROVIDER_REAL_USER]: AccessTokensFakeUser
  #tokens: {
    id: string
    tokenableId: number
    type: string
    abilities: string
    name: string | null
    hash: string
    createdAt: Date
    updatedAt: Date
    lastUsedAt: Date | null
    expiresAt: Date | null
  }[] = []

  deleteToken(identifier: string | number | BigInt) {
    this.#tokens = this.#tokens.filter((token) => token.id !== identifier)
  }

  async createToken(
    user: AccessTokensFakeUser,
    abilities?: string[],
    options?: {
      name?: string
      expiresIn?: string | number
    }
  ): Promise<AccessToken> {
    const transientToken = AccessToken.createTransientToken(user.id, 40, options?.expiresIn)
    const id = stringHelpers.random(15)
    const createdAt = new Date()
    const updatedAt = new Date()

    this.#tokens.push({
      id,
      createdAt,
      updatedAt,
      name: options?.name || null,
      hash: transientToken.hash,
      lastUsedAt: null,
      tokenableId: user.id,
      type: 'auth_tokens',
      expiresAt: transientToken.expiresAt || null,
      abilities: JSON.stringify(abilities || ['*']),
    })

    return new AccessToken({
      identifier: id,
      abilities: abilities || ['*'],
      tokenableId: user.id,
      secret: transientToken.secret,
      prefix: 'oat_',
      type: 'auth_tokens',
      name: options?.name || null,
      hash: transientToken.hash,
      createdAt: createdAt,
      updatedAt: updatedAt,
      expiresAt: transientToken.expiresAt || null,
      lastUsedAt: null,
    })
  }

  async createUserForGuard(user: AccessTokensFakeUser) {
    return {
      getId() {
        return user.id
      },
      getOriginal() {
        return user
      },
    }
  }

  async findById(id: number) {
    const user = users.find(({ id: userId }) => userId === id)
    if (!user) {
      return null
    }

    return this.createUserForGuard(user)
  }

  async invalidateToken(tokenValue: Secret<string>) {
    const decodedToken = AccessToken.decode('oat_', tokenValue.release())
    if (!decodedToken) {
      return false
    }

    const index = this.#tokens.findIndex(({ id }) => id === decodedToken.identifier)

    if (index === -1) {
      return false
    }
    this.#tokens.splice(index, 1)
    return true
  }

  async verifyToken(tokenValue: Secret<string>): Promise<AccessToken | null> {
    const decodedToken = AccessToken.decode('oat_', tokenValue.release())
    if (!decodedToken) {
      return null
    }

    const token = this.#tokens.find(({ id }) => id === decodedToken.identifier)
    if (!token) {
      return null
    }

    const accessToken = new AccessToken({
      identifier: token.id,
      abilities: JSON.parse(token.abilities),
      tokenableId: token.tokenableId,
      type: token.type,
      name: token.name,
      hash: token.hash,
      createdAt: token.createdAt,
      updatedAt: token.updatedAt,
      expiresAt: token.expiresAt,
      lastUsedAt: token.lastUsedAt,
    })

    if (!accessToken.verify(decodedToken.secret) || accessToken.isExpired()) {
      return null
    }

    return accessToken
  }
}
