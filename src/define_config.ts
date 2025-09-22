/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { configProvider } from '@adonisjs/core'
import type { ConfigProvider } from '@adonisjs/core/types'
import type { GuardConfigProvider, GuardFactory } from './types.ts'

/**
 * Config resolved by the "defineConfig" method
 */
export type ResolvedAuthConfig<
  KnownGuards extends Record<string, GuardFactory | GuardConfigProvider<GuardFactory>>,
> = {
  default: keyof KnownGuards
  guards: {
    [K in keyof KnownGuards]: KnownGuards[K] extends GuardConfigProvider<infer A>
      ? A
      : KnownGuards[K]
  }
}

/**
 * Define configuration for the auth package. The function returns
 * a config provider that is invoked inside the auth service
 * provider
 *
 * @param config - Configuration object with default guard and available guards
 *
 * @example
 * import { defineConfig } from '@adonisjs/auth'
 * import { sessionGuard, sessionUserProvider } from '@adonisjs/auth/session'
 *
 * const authConfig = defineConfig({
 *   default: 'web',
 *   guards: {
 *     web: sessionGuard({
 *       useRememberMeTokens: false,
 *       provider: sessionUserProvider({
 *         model: () => import('#models/user')
 *       })
 *     })
 *   }
 * })
 */
export function defineConfig<
  KnownGuards extends Record<string, GuardFactory | GuardConfigProvider<GuardFactory>>,
>(config: {
  default: keyof KnownGuards
  guards: KnownGuards
}): ConfigProvider<ResolvedAuthConfig<KnownGuards>> {
  return configProvider.create(async (app) => {
    const guardsList = Object.keys(config.guards)
    const guards = {} as Record<string, GuardFactory>

    for (let guardName of guardsList) {
      const guard = config.guards[guardName]
      if (typeof guard === 'function') {
        guards[guardName] = guard
      } else {
        guards[guardName] = await guard.resolver(guardName, app)
      }
    }

    return {
      default: config.default,
      guards: guards,
    } as ResolvedAuthConfig<KnownGuards>
  })
}
