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

import { BasicAuthGuard } from './guard.ts'
import type { GuardConfigProvider } from '../../src/types.ts'
import { BasicAuthLucidUserProvider } from './user_providers/lucid.ts'
import type {
  LucidAuthenticatable,
  BasicAuthUserProviderContract,
  BasicAuthLucidUserProviderOptions,
} from './types.ts'

/**
 * Configures basic auth guard for authentication using HTTP Basic Authentication
 *
 * @param config - Configuration object containing the user provider
 *
 * @example
 * const guard = basicAuthGuard({
 *   provider: basicAuthUserProvider({
 *     model: () => import('#models/user')
 *   })
 * })
 */
export function basicAuthGuard<
  UserProvider extends BasicAuthUserProviderContract<unknown>,
>(config: {
  provider: UserProvider | ConfigProvider<UserProvider>
}): GuardConfigProvider<(ctx: HttpContext) => BasicAuthGuard<UserProvider>> {
  return {
    async resolver(name, app) {
      const emitter = await app.container.make('emitter')
      const provider =
        'resolver' in config.provider ? await config.provider.resolver(app) : config.provider
      return (ctx) => new BasicAuthGuard(name, ctx, emitter as any, provider)
    },
  }
}

/**
 * Configures user provider that uses Lucid models to authenticate
 * users using basic auth credentials
 *
 * @param config - Configuration options for the Lucid user provider
 *
 * @example
 * const userProvider = basicAuthUserProvider({
 *   model: () => import('#models/user')
 * })
 */
export function basicAuthUserProvider<Model extends LucidAuthenticatable>(
  config: BasicAuthLucidUserProviderOptions<Model>
): BasicAuthLucidUserProvider<Model> {
  return new BasicAuthLucidUserProvider(config)
}
