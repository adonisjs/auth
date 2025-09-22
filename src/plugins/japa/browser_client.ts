/*
 * @adoniss/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/// <reference types="@japa/plugin-adonisjs" />
/// <reference types="@adonisjs/session/plugins/browser_client" />

import type { PluginFn } from '@japa/runner/types'
import { decoratorsCollection } from '@japa/browser-client'
import { RuntimeException } from '@adonisjs/core/exceptions'
import type { ApplicationService } from '@adonisjs/core/types'

import debug from '../../debug.ts'
import type { Authenticators, GuardContract, GuardFactory } from '../../types.ts'

declare module 'playwright' {
  export interface BrowserContext {
    /**
     * Login a user using the default authentication guard when
     * using the browser context to make page visits
     */
    loginAs(
      ...args: {
        [K in keyof Authenticators]: Authenticators[K] extends GuardFactory
          ? ReturnType<Authenticators[K]> extends GuardContract<unknown>
            ? Parameters<ReturnType<Authenticators[K]>['authenticateAsClient']>
            : never
          : never
      }[keyof Authenticators]
    ): Promise<void>

    /**
     * Define the authentication guard for login
     */
    withGuard<K extends keyof Authenticators>(
      guard: K
    ): {
      /**
       * Login a user using a specific auth guard
       */
      loginAs(
        ...args: ReturnType<Authenticators[K]> extends GuardContract<unknown>
          ? Parameters<ReturnType<Authenticators[K]>['authenticateAsClient']>
          : never
      ): Promise<void>
    }
  }
}

/**
 * Browser API client to authenticate users when making
 * HTTP requests using the Japa Browser client.
 *
 * @param app - The AdonisJS application service instance
 *
 * @example
 * import { authBrowserClient } from '@adonisjs/auth/plugins/japa/browser_client'
 *
 * export const plugins: PluginFn[] = [
 *   authBrowserClient(app)
 * ]
 */
export const authBrowserClient = (app: ApplicationService) => {
  const pluginFn: PluginFn = async function () {
    debug('installing auth browser client plugin')

    const auth = await app.container.make('auth.manager')

    decoratorsCollection.register({
      context(context) {
        /**
         * Define the authentication guard for login and perform
         * login
         */
        context.withGuard = function (guardName) {
          return {
            async loginAs(...args) {
              const client = auth.createAuthenticatorClient()
              const guard = client.use(guardName) as GuardContract<unknown>
              const requestData = await guard.authenticateAsClient(
                ...(args as [user: unknown, ...any[]])
              )

              /* c8 ignore next 17 */
              if (requestData.headers) {
                throw new RuntimeException(
                  `Cannot use "${guard.driverName}" guard with browser client`
                )
              }

              if (requestData.cookies) {
                debug('defining cookies with browser context %O', requestData.cookies)
                Object.keys(requestData.cookies).forEach((cookie) => {
                  context.setCookie(cookie, requestData.cookies![cookie])
                })
              }

              if (requestData.session) {
                debug('defining session with browser context %O', requestData.session)
                context.setSession(requestData.session)
              }
            },
          }
        }

        /**
         * Login a user using the default authentication guard when
         * using the browser context to make page visits
         */
        context.loginAs = async function (user, ...args) {
          const client = auth.createAuthenticatorClient()
          const guard = client.use() as GuardContract<unknown>
          const requestData = await guard.authenticateAsClient(user, ...args)

          /* c8 ignore next 15 */
          if (requestData.headers) {
            throw new RuntimeException(`Cannot use "${guard.driverName}" guard with browser client`)
          }

          if (requestData.cookies) {
            debug('defining cookies with browser context %O', requestData.cookies)
            Object.keys(requestData.cookies).forEach((cookie) => {
              context.setCookie(cookie, requestData.cookies![cookie])
            })
          }

          if (requestData.session) {
            debug('defining session with browser context %O', requestData.session)
            context.setSession(requestData.session)
          }
        }
      },
    })
  }

  return pluginFn
}
