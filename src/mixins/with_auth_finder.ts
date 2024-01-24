/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { Hash } from '@adonisjs/core/hash'
import { RuntimeException } from '@adonisjs/core/exceptions'
import { beforeSave, type BaseModel } from '@adonisjs/lucid/orm'
import type { NormalizeConstructor } from '@adonisjs/core/types/helpers'
import { E_INVALID_CREDENTIALS } from '../errors.js'

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
 */
export function withAuthFinder(
  hash: () => Hash,
  options: {
    uids: string[]
    passwordColumnName: string
  }
) {
  return <Model extends NormalizeConstructor<typeof BaseModel>>(superclass: Model) => {
    class UserWithUserFinder extends superclass {
      /**
       * Hook to verify user password when creating or updating
       * the user model.
       */
      @beforeSave()
      static async hashPassword<T extends typeof UserWithUserFinder>(
        this: T,
        user: InstanceType<T>
      ) {
        if (user.$dirty[options.passwordColumnName]) {
          ;(user as any)[options.passwordColumnName] = await hash().make(
            (user as any)[options.passwordColumnName]
          )
        }
      }

      /**
       * Finds the user for authentication via "verifyCredentials".
       * Feel free to override this method customize the user
       * lookup behavior.
       */
      static findForAuth<T extends typeof UserWithUserFinder>(
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
       */
      static async verifyCredentials<T extends typeof UserWithUserFinder>(
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

        const user = await this.findForAuth(options.uids, uid)
        if (!user) {
          await hash().make(password)
          throw new E_INVALID_CREDENTIALS('Invalid user credentials')
        }

        const passwordHash = (user as any)[options.passwordColumnName]
        if (!passwordHash) {
          throw new RuntimeException(
            `Cannot verify password during login. The value of column "${options.passwordColumnName}" is undefined or null`
          )
        }

        if (await hash().verify(passwordHash, password)) {
          return user
        }

        throw new E_INVALID_CREDENTIALS('Invalid user credentials')
      }
    }

    return UserWithUserFinder
  }
}
