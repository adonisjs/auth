/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { Secret } from '@adonisjs/core/helpers'
import type { HttpContext } from '@adonisjs/core/http'
import type { Exception } from '@adonisjs/core/exceptions'
import type { LucidModel } from '@adonisjs/lucid/types/model'

import type { AccessToken } from './access_token.js'
import type { PROVIDER_REAL_USER } from '../../src/symbols.js'

/**
 * Options accepted by the tokens provider that uses lucid
 * database service to fetch and persist tokens.
 */
export type DbAccessTokensProviderOptions<TokenableModel extends LucidModel> = {
  /**
   * The user model for which to generate tokens. Note, the model
   * is not used for tokens, but is used to associate a user
   * with the token
   */
  tokenableModel: TokenableModel

  /**
   * Database table to use for querying tokens.
   *
   * Defaults to "auth_access_tokens"
   */
  table?: string

  /**
   * The default expiry for all the tokens. You can also customize
   * expiry at the time of creating a token as well.
   *
   * By default tokens do not expire
   */
  expiresIn?: string | number

  /**
   * The length for the token secret. A secret is a cryptographically
   * secure random string.
   *
   * Defaults to 40
   */
  tokenSecretLength?: number

  /**
   * A unique type for the value. The type is used to identify a
   * bucket of tokens within the storage layer.
   *
   * Defaults to auth_token
   */
  type?: string

  /**
   * A unique prefix to append to the publicly shared token value.
   *
   * Defaults to oat_
   */
  prefix?: string
}

/**
 * The database columns expected at the database level
 */
export type AccessTokenDbColumns = {
  /**
   * Token primary key. It can be an integer, bigInteger or
   * even a UUID or any other string based value.
   *
   * The id should not have ". (dots)" inside it.
   */
  id: number | string | BigInt

  /**
   * The user or entity for whom the token is
   * generated
   */
  tokenable_id: string | number | BigInt

  /**
   * A unique type for the token. It is used to
   * unique identify tokens within the storage
   * layer.
   */
  type: string

  /**
   * Optional name for the token
   */
  name: string | null

  /**
   * Token hash is used to verify the token shared
   * with the user
   */
  hash: string

  /**
   * Timestamps
   */
  created_at: Date
  updated_at: Date

  /**
   * An array of abilities stored as JSON.
   */
  abilities: string[]

  /**
   * The date after which the token will be considered
   * expired.
   *
   * A null value means the token is long-lived
   */
  expires_at: null | Date

  /**
   * Last time the token was used for authentication
   */
  last_used_at: null | Date
}

/**
 * Access token providers are used verify an access token
 * during authentication
 */
export interface AccessTokensProviderContract<Tokenable extends LucidModel> {
  /**
   * Create a token for a given user
   */
  create(
    user: InstanceType<Tokenable>,
    abilities?: string[],
    options?: {
      name?: string
      expiresIn?: string | number
    }
  ): Promise<AccessToken>

  /**
   * Verifies a publicly shared access token and returns an
   * access token for it.
   */
  verify(tokenValue: Secret<string>): Promise<AccessToken | null>
}

/**
 * A lucid model with a tokens provider to verify tokens during
 * authentication
 */
export type LucidTokenable<TokenableProperty extends string> = LucidModel & {
  [K in TokenableProperty]: AccessTokensProviderContract<LucidModel>
}

/**
 * Options accepted by the user provider that uses a lucid
 * model to lookup a user during authentication and verify
 * tokens
 */
export type AccessTokensLucidUserProviderOptions<
  TokenableProperty extends string,
  Model extends LucidTokenable<TokenableProperty>,
> = {
  tokens: TokenableProperty
  model: () => Promise<{ default: Model }>
}

/**
 * Guard user is an adapter between the user provider
 * and the guard.
 *
 * The guard is user provider agnostic and therefore it
 * needs a adapter to known some basic info about the
 * user.
 */
export type AccessTokensGuardUser<RealUser> = {
  getId(): string | number | BigInt
  getOriginal(): RealUser
}

/**
 * The user provider used by access tokens guard to lookup
 * users and verify tokens.
 */
export interface AccessTokensUserProviderContract<RealUser> {
  [PROVIDER_REAL_USER]: RealUser

  /**
   * Create a user object that acts as an adapter between
   * the guard and real user value.
   */
  createUserForGuard(user: RealUser): Promise<AccessTokensGuardUser<RealUser>>

  /**
   * Create a token for a given user
   */
  createToken(
    user: RealUser,
    abilities?: string[],
    options?: {
      name?: string
      expiresIn?: string | number
    }
  ): Promise<AccessToken>

  /**
   * Find a user by the user id.
   */
  findById(identifier: string | number | BigInt): Promise<AccessTokensGuardUser<RealUser> | null>

  /**
   * Verify a token by its publicly shared value.
   */
  verifyToken(tokenValue: Secret<string>): Promise<AccessToken | null>
}

/**
 * Events emitted by the access tokens guard during
 * authentication
 */
export type AccessTokensGuardEvents<RealUser> = {
  /**
   * Attempting to authenticate the user
   */
  'access_tokens_auth:authentication_attempted': {
    ctx: HttpContext
    guardName: string
  }

  /**
   * Authentication was successful
   */
  'access_tokens_auth:authentication_succeeded': {
    ctx: HttpContext
    guardName: string
    user: RealUser
    token: AccessToken
  }

  /**
   * Authentication failed
   */
  'access_tokens_auth:authentication_failed': {
    ctx: HttpContext
    guardName: string
    error: Exception
  }
}
