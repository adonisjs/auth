/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { configProvider } from '@adonisjs/core'
import { RuntimeException } from '@adonisjs/core/exceptions'
import type { ApplicationService } from '@adonisjs/core/types'

import type { AuthService } from '../src/types.js'
import { AuthManager } from '../src/auth_manager.js'

declare module '@adonisjs/core/types' {
  export interface ContainerBindings {
    'auth.manager': AuthService
  }
}

export default class AuthProvider {
  constructor(protected app: ApplicationService) {}

  register() {
    this.app.container.singleton('auth.manager', async () => {
      const authConfigProvider = this.app.config.get('auth')
      const config = await configProvider.resolve<any>(this.app, authConfigProvider)

      if (!config) {
        throw new RuntimeException(
          'Invalid config exported from "config/auth.ts" file. Make sure to use the defineConfig method'
        )
      }

      return new AuthManager(config)
    })
  }
}
