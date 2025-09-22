/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { type FakeGuard } from '../../../factories/auth/main.js'

/**
 * Guard to use for testing
 */
export type Guards = {
  web: () => FakeGuard
}

/**
 * Inferrring types for the authenticators, since
 * the japa plugins relies on the singleton
 * service
 */
declare module '@adonisjs/auth/types' {
  interface Authenticators extends Guards {}
}
