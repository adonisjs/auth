/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { createHash } from 'node:crypto'
import string from '@adonisjs/core/helpers/string'
import { RuntimeException } from '@adonisjs/core/exceptions'
import { Secret, base64, safeEqual } from '@adonisjs/core/helpers'

import { CRC32 } from './crc32.ts'
import { E_UNAUTHORIZED_ACCESS } from '../../src/errors.ts'

/**
 * Access token represents a token created for a user to authenticate
 * using the auth module.
 *
 * It encapsulates the logic of creating an opaque token, generating
 * its hash and verifying its hash.
 *
 * @example
 * const token = new AccessToken({
 *   identifier: 1,
 *   tokenableId: 123,
 *   type: 'api',
 *   hash: 'sha256hash',
 *   createdAt: new Date(),
 *   updatedAt: new Date(),
 *   lastUsedAt: null,
 *   expiresAt: null,
 *   name: 'API Token',
 *   abilities: ['read', 'write']
 * })
 */
export class AccessToken {
  /**
   * Decodes a publicly shared token and return the series
   * and the token value from it.
   *
   * Returns null when unable to decode the token because of
   * invalid format or encoding.
   *
   * @param prefix - The token prefix to validate against
   * @param value - The token value to decode
   *
   * @example
   * const decoded = AccessToken.decode('oat_', 'oat_abc123.def456')
   * if (decoded) {
   *   console.log('Token ID:', decoded.identifier)
   *   console.log('Secret:', decoded.secret.release())
   * }
   */
  static decode(
    prefix: string,
    value: string
  ): null | { identifier: string; secret: Secret<string> } {
    /**
     * Ensure value is a string and starts with the prefix.
     */
    if (typeof value !== 'string' || !value.startsWith(`${prefix}`)) {
      return null
    }

    /**
     * Remove prefix from the rest of the token.
     */
    const token = value.replace(new RegExp(`^${prefix}`), '')
    if (!token) {
      return null
    }

    const [identifier, ...tokenValue] = token.split('.')
    if (!identifier || tokenValue.length === 0) {
      return null
    }

    const decodedIdentifier = base64.urlDecode(identifier)
    const decodedSecret = base64.urlDecode(tokenValue.join('.'))
    if (!decodedIdentifier || !decodedSecret) {
      return null
    }

    return {
      identifier: decodedIdentifier,
      secret: new Secret(decodedSecret),
    }
  }

  /**
   * Creates a transient token that can be shared with the persistence
   * layer.
   *
   * @param userId - The ID of the user for whom the token is created
   * @param size - The size of the random secret to generate
   * @param expiresIn - Optional expiration time (seconds or duration string)
   *
   * @example
   * const transientToken = AccessToken.createTransientToken(123, 32, '7d')
   * // Store transientToken in database
   */
  static createTransientToken(
    userId: string | number | BigInt,
    size: number,
    expiresIn?: string | number
  ) {
    let expiresAt: Date | undefined
    if (expiresIn) {
      expiresAt = new Date()
      expiresAt.setSeconds(expiresAt.getSeconds() + string.seconds.parse(expiresIn))
    }

    return {
      userId,
      expiresAt,
      ...this.seed(size),
    }
  }

  /**
   * Creates a secret opaque token and its hash. The secret is
   * suffixed with a crc32 checksum for secret scanning tools
   * to easily identify the token.
   *
   * @param size - The size of the random string to generate
   *
   * @example
   * const { secret, hash } = AccessToken.seed(32)
   * console.log('Secret:', secret.release())
   * console.log('Hash:', hash)
   */
  static seed(size: number) {
    const seed = string.random(size)
    const secret = new Secret(`${seed}${new CRC32().calculate(seed)}`)
    const hash = createHash('sha256').update(secret.release()).digest('hex')
    return { secret, hash }
  }

  /**
   * Identifer is a unique sequence to identify the
   * token within database. It should be the
   * primary/unique key
   */
  identifier: string | number | BigInt

  /**
   * Reference to the user id for whom the token
   * is generated.
   */
  tokenableId: string | number | BigInt

  /**
   * The value is a public representation of a token. It is created
   * by combining the "identifier"."secret"
   */
  value?: Secret<string>

  /**
   * Recognizable name for the token
   */
  name: string | null

  /**
   * A unique type to identify a bucket of tokens inside the
   * storage layer.
   */
  type: string

  /**
   * Hash is computed from the seed to later verify the validity
   * of seed
   */
  hash: string

  /**
   * Date/time when the token instance was created
   */
  createdAt: Date

  /**
   * Date/time when the token was updated
   */
  updatedAt: Date

  /**
   * Timestamp at which the token was used for authentication
   */
  lastUsedAt: Date | null

  /**
   * Timestamp at which the token will expire
   */
  expiresAt: Date | null

  /**
   * An array of abilities the token can perform. The abilities
   * is an array of abritary string values
   */
  abilities: string[]

  /**
   * Creates a new AccessToken instance
   *
   * @param attributes - Token attributes including identifier, user ID, type, hash, etc.
   *
   * @example
   * const token = new AccessToken({
   *   identifier: 1,
   *   tokenableId: 123,
   *   type: 'api',
   *   hash: 'sha256hash',
   *   createdAt: new Date(),
   *   updatedAt: new Date(),
   *   lastUsedAt: null,
   *   expiresAt: new Date(Date.now() + 86400000),
   *   name: 'Mobile App Token',
   *   abilities: ['read:posts', 'write:posts']
   * })
   */
  constructor(attributes: {
    identifier: string | number | BigInt
    tokenableId: string | number | BigInt
    type: string
    hash: string
    createdAt: Date
    updatedAt: Date
    lastUsedAt: Date | null
    expiresAt: Date | null
    name: string | null
    prefix?: string
    secret?: Secret<string>
    abilities?: string[]
  }) {
    this.identifier = attributes.identifier
    this.tokenableId = attributes.tokenableId
    this.name = attributes.name
    this.hash = attributes.hash
    this.type = attributes.type
    this.createdAt = attributes.createdAt
    this.updatedAt = attributes.updatedAt
    this.expiresAt = attributes.expiresAt
    this.lastUsedAt = attributes.lastUsedAt
    this.abilities = attributes.abilities || ['*']

    /**
     * Compute value when secret is provided
     */
    if (attributes.secret) {
      if (!attributes.prefix) {
        throw new RuntimeException('Cannot compute token value without the prefix')
      }
      this.value = new Secret(
        `${attributes.prefix}${base64.urlEncode(String(this.identifier))}.${base64.urlEncode(
          attributes.secret.release()
        )}`
      )
    }
  }

  /**
   * Check if the token allows the given ability.
   *
   * @param ability - The ability to check
   *
   * @example
   * if (token.allows('read:posts')) {
   *   console.log('User can read posts')
   * }
   */
  allows(ability: string) {
    return this.abilities.includes(ability) || this.abilities.includes('*')
  }

  /**
   * Check if the token denies the ability.
   *
   * @param ability - The ability to check
   *
   * @example
   * if (token.denies('delete:posts')) {
   *   console.log('User cannot delete posts')
   * }
   */
  denies(ability: string) {
    return !this.abilities.includes(ability) && !this.abilities.includes('*')
  }

  /**
   * Authorize ability access using the current access token
   *
   * @param ability - The ability to authorize
   *
   * @throws {E_UNAUTHORIZED_ACCESS} When the token denies the ability
   *
   * @example
   * token.authorize('write:posts') // Throws if not allowed
   * console.log('Authorization successful')
   */
  authorize(ability: string) {
    if (this.denies(ability)) {
      throw new E_UNAUTHORIZED_ACCESS('Unauthorized access', { guardDriverName: 'access_tokens' })
    }
  }

  /**
   * Check if the token has been expired. Verifies
   * the "expiresAt" timestamp with the current
   * date.
   *
   * Tokens with no expiry never expire
   *
   * @example
   * if (token.isExpired()) {
   *   console.log('Token has expired')
   * } else {
   *   console.log('Token is still valid')
   * }
   */
  isExpired() {
    if (!this.expiresAt) {
      return false
    }

    return this.expiresAt < new Date()
  }

  /**
   * Verifies the value of a token against the pre-defined hash
   *
   * @param secret - The secret to verify against the stored hash
   *
   * @example
   * const isValid = token.verify(new Secret('user-provided-secret'))
   * if (isValid) {
   *   console.log('Token is valid')
   * }
   */
  verify(secret: Secret<string>): boolean {
    const newHash = createHash('sha256').update(secret.release()).digest('hex')
    return safeEqual(this.hash, newHash)
  }

  /**
   * Converts the token to a JSON representation suitable for API responses
   *
   * @example
   * const tokenData = token.toJSON()
   * console.log(tokenData.type) // 'bearer'
   * console.log(tokenData.token) // 'oat_abc123.def456'
   */
  toJSON() {
    return {
      type: 'bearer',
      name: this.name,
      token: this.value ? this.value.release() : undefined,
      abilities: this.abilities,
      lastUsedAt: this.lastUsedAt,
      expiresAt: this.expiresAt,
    }
  }
}
