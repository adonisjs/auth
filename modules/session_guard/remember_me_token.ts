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
 */
export class RememberMeToken {
  /**
   * Decodes a publicly shared token and return the series
   * and the token value from it.
   *
   * Returns null when unable to decode the token because of
   * invalid format or encoding.
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
   */
  isExpired() {
    return this.expiresAt < new Date()
  }

  /**
   * Verifies the value of a token against the pre-defined hash
   */
  verify(secret: Secret<string>): boolean {
    const newHash = createHash('sha256').update(secret.release()).digest('hex')
    return safeEqual(this.hash, newHash)
  }
}
