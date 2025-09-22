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
import { Secret, base64, safeEqual } from '@adonisjs/core/helpers'

/**
 * Remember me token represents an opaque token that can be
 * used to automatically login a user without asking them
 * to re-login
 *
 * @example
 * const token = new RememberMeToken({
 *   identifier: 1,
 *   tokenableId: 123,
 *   hash: 'sha256hash',
 *   createdAt: new Date(),
 *   updatedAt: new Date(),
 *   expiresAt: new Date(Date.now() + 86400000)
 * })
 */
export class RememberMeToken {
  /**
   * Decodes a publicly shared token and return the series
   * and the token value from it.
   *
   * Returns null when unable to decode the token because of
   * invalid format or encoding.
   *
   * @param value - The token value to decode
   *
   * @example
   * const decoded = RememberMeToken.decode('abc123.def456')
   * if (decoded) {
   *   console.log('Token ID:', decoded.identifier)
   *   console.log('Secret:', decoded.secret.release())
   * }
   */
  static decode(value: string): null | { identifier: string; secret: Secret<string> } {
    /**
     * Ensure value is a string and starts with the prefix.
     */
    if (typeof value !== 'string') {
      return null
    }

    /**
     * Remove prefix from the rest of the token.
     */
    if (!value) {
      return null
    }

    const [identifier, ...tokenValue] = value.split('.')
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
   * @param expiresIn - Expiration time (seconds or duration string)
   *
   * @example
   * const transientToken = RememberMeToken.createTransientToken(123, 32, '30d')
   * // Store transientToken in database
   */
  static createTransientToken(
    userId: string | number | BigInt,
    size: number,
    expiresIn: string | number
  ) {
    const expiresAt = new Date()
    expiresAt.setSeconds(expiresAt.getSeconds() + string.seconds.parse(expiresIn))

    return {
      userId,
      expiresAt,
      ...this.seed(size),
    }
  }

  /**
   * Creates a secret opaque token and its hash.
   *
   * @param size - The size of the random string to generate
   *
   * @example
   * const { secret, hash } = RememberMeToken.seed(32)
   * console.log('Secret:', secret.release())
   * console.log('Hash:', hash)
   */
  static seed(size: number) {
    const seed = string.random(size)
    const secret = new Secret(seed)
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
   * Timestamp at which the token will expire
   */
  expiresAt: Date

  /**
   * Creates a new RememberMeToken instance
   *
   * @param attributes - Token attributes including identifier, user ID, hash, etc.
   *
   * @example
   * const token = new RememberMeToken({
   *   identifier: 1,
   *   tokenableId: 123,
   *   hash: 'sha256hash',
   *   createdAt: new Date(),
   *   updatedAt: new Date(),
   *   expiresAt: new Date(Date.now() + 86400000)
   * })
   */
  constructor(attributes: {
    identifier: string | number | BigInt
    tokenableId: string | number | BigInt
    hash: string
    createdAt: Date
    updatedAt: Date
    expiresAt: Date
    secret?: Secret<string>
  }) {
    this.identifier = attributes.identifier
    this.tokenableId = attributes.tokenableId
    this.hash = attributes.hash
    this.createdAt = attributes.createdAt
    this.updatedAt = attributes.updatedAt
    this.expiresAt = attributes.expiresAt

    /**
     * Compute value when secret is provided
     */
    if (attributes.secret) {
      this.value = new Secret(
        `${base64.urlEncode(String(this.identifier))}.${base64.urlEncode(
          attributes.secret.release()
        )}`
      )
    }
  }

  /**
   * Check if the token has been expired. Verifies
   * the "expiresAt" timestamp with the current
   * date.
   *
   * @example
   * if (token.isExpired()) {
   *   console.log('Remember me token has expired')
   * } else {
   *   console.log('Token is still valid')
   * }
   */
  isExpired() {
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
   *   console.log('Remember me token is valid')
   * }
   */
  verify(secret: Secret<string>): boolean {
    const newHash = createHash('sha256').update(secret.release()).digest('hex')
    return safeEqual(this.hash, newHash)
  }
}
