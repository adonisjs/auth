/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { HttpContext } from '@adonisjs/core/http'
import type { Exception } from '@adonisjs/core/exceptions'
import type { LucidModel } from '@adonisjs/lucid/types/model'
import type { PROVIDER_REAL_USER } from '../../src/symbols.ts'

/**
 * A lucid model with verify credentials method to verify user
 * credentials during authentication.
 */
export type LucidAuthenticatable = LucidModel & {
  /**
   * Verify credentials method should return the user instance
   * or throw an exception
   *
   * @param uid - The username or user identifier
   * @param password - The password to verify
   */
  verifyCredentials(uid: string, password: string): Promise<InstanceType<LucidAuthenticatable>>
}

/**
 * Options accepted by the user provider that uses a lucid
 * model to lookup a user during authentication and verify
 * credentials
 */
export type BasicAuthLucidUserProviderOptions<Model extends LucidAuthenticatable> = {
  /**
   * The model to use for users lookup
   */
  model: () => Promise<{ default: Model }>
}

/**
 * Guard user is an adapter between the user provider
 * and the guard.
 *
 * The guard is user provider agnostic and therefore it
 * needs an adapter to know some basic info about the
 * user.
 */
export type BasicAuthGuardUser<RealUser> = {
  /**
   * Get the unique identifier for the user
   */
  getId(): string | number | BigInt

  /**
   * Get the original user object from the provider
   */
  getOriginal(): RealUser
}

/**
 * The user provider used by basic auth guard to lookup users
 * during authentication
 */
export interface BasicAuthUserProviderContract<RealUser> {
  [PROVIDER_REAL_USER]: RealUser

  /**
   * Create a user object that acts as an adapter between
   * the guard and real user value.
   *
   * @param user - The real user object from the provider
   */
  createUserForGuard(user: RealUser): Promise<BasicAuthGuardUser<RealUser>>

  /**
   * Verify user credentials and must return an instance of the
   * user back or null when the credentials are invalid
   *
   * @param uid - The username or user identifier
   * @param password - The password to verify
   */
  verifyCredentials(uid: string, password: string): Promise<BasicAuthGuardUser<RealUser> | null>
}

/**
 * Events emitted by the basic auth guard
 */
export type BasicAuthGuardEvents<User> = {
  /**
   * Attempting to authenticate the user
   */
  'basic_auth:authentication_attempted': {
    ctx: HttpContext
    guardName: string
  }

  /**
   * Authentication was successful
   */
  'basic_auth:authentication_succeeded': {
    ctx: HttpContext
    guardName: string
    user: User
  }

  /**
   * Authentication failed
   */
  'basic_auth:authentication_failed': {
    ctx: HttpContext
    guardName: string
    error: Exception
  }
}
