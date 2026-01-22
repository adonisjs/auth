/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { HttpContext } from '@adonisjs/core/http'
import type { ConfigProvider } from '@adonisjs/core/types'

import { SessionGuard } from './guard.ts'
import type { GuardConfigProvider } from '../../src/types.ts'
import { SessionLucidUserProvider } from './user_providers/lucid.ts'
import type {
  SessionGuardOptions,
  LucidAuthenticatable,
  SessionUserProviderContract,
  SessionLucidUserProviderOptions,
  SessionWithTokensUserProviderContract,
} from './types.ts'

/**
 * Configures session guard for authentication using HTTP sessions
 *
 * @param config - Configuration object containing the user provider and session options
 *
 * @example
 * const guard = sessionGuard({
 *   useRememberMeTokens: false,
 *   provider: sessionUserProvider({
 *     model: () => import('#models/user')
 *   })
 * })
 */
export function sessionGuard<
  UseRememberTokens extends boolean,
  UserProvider extends UseRememberTokens extends true
    ? SessionWithTokensUserProviderContract<unknown>
    : SessionUserProviderContract<unknown>,
>(
  config: {
    provider: UserProvider | ConfigProvider<UserProvider>
  } & SessionGuardOptions<UseRememberTokens>
): GuardConfigProvider<(ctx: HttpContext) => SessionGuard<UseRememberTokens, UserProvider>> {
  return {
    async resolver(name, app) {
      const emitter = await app.container.make('emitter')
      const provider =
        'resolver' in config.provider ? await config.provider.resolver(app) : config.provider
      return (ctx) => new SessionGuard(name, ctx, config, emitter as any, provider)
    },
  }
}

/**
 * Configures user provider that uses Lucid models to authenticate
 * users using sessions
 *
 * @param config - Configuration options for the Lucid user provider
 *
 * @example
 * const userProvider = sessionUserProvider({
 *   model: () => import('#models/user')
 * })
 */
export function sessionUserProvider<Model extends LucidAuthenticatable>(
  config: SessionLucidUserProviderOptions<Model>
): SessionLucidUserProvider<Model> {
  return new SessionLucidUserProvider(config)
}
