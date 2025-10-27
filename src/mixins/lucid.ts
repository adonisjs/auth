/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { Hash, HashManager } from '@adonisjs/core/hash'
import { RuntimeException } from '@adonisjs/core/exceptions'
import { beforeSave, type BaseModel } from '@adonisjs/lucid/orm'
import type { NormalizeConstructor } from '@adonisjs/core/types/helpers'
import { E_INVALID_CREDENTIALS } from '../errors.ts'

type UserWithUserFinderRow = {
  verifyPassword(plainPassword: string): Promise<boolean>
}

type UserWithUserFinderClass<
  Model extends NormalizeConstructor<typeof BaseModel> = NormalizeConstructor<typeof BaseModel>,
> = Model & {
  hashPassword<T extends UserWithUserFinderClass>(this: T, user: InstanceType<T>): Promise<void>
  findForAuth<T extends UserWithUserFinderClass>(
    this: T,
    uids: string[],
    value: string
  ): Promise<InstanceType<T> | null>
  verifyCredentials<T extends UserWithUserFinderClass>(
    this: T,
    uid: string,
    password: string
  ): Promise<InstanceType<T>>
  new (...args: any[]): UserWithUserFinderRow
}

/**
 * Mixing to add user lookup and password verification methods
 * on a model.
 *
 * Under the hood, this mixin defines following methods and hooks
 *
 * - beforeSave hook to hash user password
 * - findForAuth method to find a user during authentication
 * - verifyCredentials method to verify user credentials and prevent
 *   timing attacks.
 *
 * @param hash - Function that returns a Hash instance for password hashing
 * @param options - Configuration options with uids and password column name
 *
 * @example
 * import { withAuthFinder } from '@adonisjs/auth/mixins/lucid'
 *
 * class User extends withAuthFinder(hash, {
 *   uids: ['email', 'username'],
 *   passwordColumnName: 'password'
 * })(BaseModel) {
 *   // User model implementation
 * }
 */
export function withAuthFinder(
  hash: (() => Hash) | HashManager<any>,
  options?: {
    uids?: string[]
    passwordColumnName?: string
  }
) {
  let normalizedOptions = { uids: ['email'], passwordColumnName: 'password', ...options }
  let hashFactory = typeof hash === 'function' ? hash : () => hash.use()

  return function <Model extends NormalizeConstructor<typeof BaseModel>>(
    superclass: Model
  ): UserWithUserFinderClass<Model> {
    class UserWithUserFinder extends superclass {
      /**
       * Hook to hash user password when creating or updating
       * the user model.
       *
       * @param user - The user instance being saved
       *
       * @example
       * // This hook runs automatically before saving
       * const user = new User()
       * user.password = 'plaintext'
       * await user.save() // password will be hashed automatically
       */
      @beforeSave()
      static async hashPassword<T extends UserWithUserFinderClass>(this: T, user: InstanceType<T>) {
        if (user.$dirty[normalizedOptions.passwordColumnName]) {
          ;(user as any)[normalizedOptions.passwordColumnName] = await hashFactory().make(
            (user as any)[normalizedOptions.passwordColumnName]
          )
        }
      }

      /**
       * Finds the user for authentication via "verifyCredentials".
       * Feel free to override this method to customize the user
       * lookup behavior.
       *
       * @param uids - Array of column names to search in
       * @param value - The value to search for
       *
       * @example
       * const user = await User.findForAuth(['email', 'username'], 'john@example.com')
       */
      static findForAuth<T extends UserWithUserFinderClass>(
        this: T,
        uids: string[],
        value: string
      ): Promise<InstanceType<T> | null> {
        const query = this.query()
        uids.forEach((uid) => query.orWhere(uid, value))
        return query.limit(1).first()
      }

      /**
       * Find a user by uid and verify their password. This method is
       * safe from timing attacks.
       *
       * @param uid - The user identifier (email, username, etc.)
       * @param password - The plain text password to verify
       *
       * @throws {E_INVALID_CREDENTIALS} When credentials are invalid
       *
       * @example
       * const user = await User.verifyCredentials('john@example.com', 'password123')
       * console.log('Authenticated user:', user.email)
       */
      static async verifyCredentials<T extends UserWithUserFinderClass>(
        this: T,
        uid: string,
        password: string
      ) {
        /**
         * Fail when uid or the password are missing
         */
        if (!uid || !password) {
          throw new E_INVALID_CREDENTIALS('Invalid user credentials')
        }

        const user = await this.findForAuth(normalizedOptions.uids, uid)
        if (!user) {
          await hashFactory().make(password)
          throw new E_INVALID_CREDENTIALS('Invalid user credentials')
        }

        if (await user.verifyPassword(password)) {
          return user
        }

        throw new E_INVALID_CREDENTIALS('Invalid user credentials')
      }

      /**
       * Verifies the plain password against the user's password
       * hash
       *
       * @param plainPassword - The plain text password to verify
       *
       * @throws {RuntimeException} When password column value is undefined or null
       *
       * @example
       * const isValid = await user.verifyPassword('password123')
       * if (isValid) {
       *   console.log('Password is correct')
       * }
       */
      verifyPassword(plainPassword: string): Promise<boolean> {
        const passwordHash = (this as any)[normalizedOptions.passwordColumnName]
        if (!passwordHash) {
          throw new RuntimeException(
            `Cannot verify password. The value for "${normalizedOptions.passwordColumnName}" column is undefined or null`
          )
        }
        return hashFactory().verify(passwordHash, plainPassword)
      }
    }

    return UserWithUserFinder
  }
}
