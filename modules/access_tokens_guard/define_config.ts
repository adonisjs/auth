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

import { AccessTokensGuard } from './guard.ts'
import type { GuardConfigProvider } from '../../src/types.ts'
import { AccessTokensLucidUserProvider } from './user_providers/lucid.ts'
import type {
  LucidTokenable,
  AccessTokensUserProviderContract,
  AccessTokensLucidUserProviderOptions,
} from './types.ts'

/**
 * Configures access tokens guard for authentication
 */
export function tokensGuard<
  UserProvider extends AccessTokensUserProviderContract<unknown>,
>(config: {
  provider: UserProvider | ConfigProvider<UserProvider>
}): GuardConfigProvider<(ctx: HttpContext) => AccessTokensGuard<UserProvider>> {
  return {
    async resolver(name, app) {
      const emitter = await app.container.make('emitter')
      const provider =
        'resolver' in config.provider ? await config.provider.resolver(app) : config.provider
      return (ctx) => new AccessTokensGuard(name, ctx, emitter as any, provider)
    },
  }
}

/**
 * Configures user provider that uses Lucid models to verify
 * access tokens and find users during authentication.
 */
export function tokensUserProvider<
  TokenableProperty extends string,
  Model extends LucidTokenable<TokenableProperty>,
>(
  config: AccessTokensLucidUserProviderOptions<TokenableProperty, Model>
): AccessTokensLucidUserProvider<TokenableProperty, Model> {
  return new AccessTokensLucidUserProvider(config)
}
