/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/// <reference types="@adonisjs/session/plugins/api_client" />

import type { PluginFn } from '@japa/runner/types'
import { ApiClient, ApiRequest } from '@japa/api-client'
import type { ApplicationService } from '@adonisjs/core/types'

import debug from '../../debug.ts'
import type { Authenticators, GuardContract, GuardFactory } from '../../types.ts'

declare module '@japa/api-client' {
  export interface ApiRequest {
    authData: {
      guard: keyof Authenticators | '__default__'
      args: [unknown, ...any[]]
    }

    /**
     * Login a user using the default authentication guard
     * when making an API call
     */
    loginAs(
      ...args: {
        [K in keyof Authenticators]: Authenticators[K] extends GuardFactory
          ? ReturnType<Authenticators[K]> extends GuardContract<unknown>
            ? Parameters<ReturnType<Authenticators[K]>['authenticateAsClient']>
            : never
          : never
      }[keyof Authenticators]
    ): this

    /**
     * Define the authentication guard for login
     */
    withGuard<K extends keyof Authenticators, Self extends ApiRequest>(
      this: Self,
      guard: K
    ): {
      /**
       * Login a user using a specific auth guard
       */
      loginAs(
        ...args: ReturnType<Authenticators[K]> extends GuardContract<any>
          ? Parameters<ReturnType<Authenticators[K]>['authenticateAsClient']>
          : never
      ): Self
    }
  }
}

/**
 * Auth API client to authenticate users when making
 * HTTP requests using the Japa API client
 *
 * @param app - The AdonisJS application service instance
 *
 * @example
 * import { authApiClient } from '@adonisjs/auth/plugins/japa/api_client'
 *
 * export const plugins: PluginFn[] = [
 *   authApiClient(app)
 * ]
 */
export const authApiClient = (app: ApplicationService) => {
  const pluginFn: PluginFn = function () {
    debug('installing auth api client plugin')

    /**
     * Login a user using the default authentication guard
     * when making an API call
     */
    ApiRequest.macro('loginAs', function (this: ApiRequest, user, ...args: any[]) {
      this.authData = {
        guard: '__default__',
        args: [user, ...args],
      }
      return this
    })

    /**
     * Define the authentication guard for login
     */
    ApiRequest.macro('withGuard', function <
      K extends keyof Authenticators,
      Self extends ApiRequest,
    >(this: Self, guard: K) {
      return {
        loginAs: (...args) => {
          this.authData = {
            guard,
            args: args,
          }
          return this
        },
      }
    })

    /**
     * Hook into the request and login the user
     */
    ApiClient.setup(async (request) => {
      const auth = await app.container.make('auth.manager')
      const authData = request['authData']
      if (!authData) {
        return
      }

      const client = auth.createAuthenticatorClient()
      const guard = authData.guard === '__default__' ? client.use() : client.use(authData.guard)
      const requestData = await (guard as GuardContract<unknown>).authenticateAsClient(
        ...authData.args
      )

      /* c8 ignore next 13 */
      if (requestData.headers) {
        debug('defining headers with api client request %O', requestData.headers)
        request.headers(requestData.headers)
      }
      if (requestData.session) {
        debug('defining session with api client request %O', requestData.session)
        request.withSession(requestData.session)
      }
      if (requestData.cookies) {
        debug('defining session with api client request %O', requestData.session)
        request.cookies(requestData.cookies)
      }
    })
  }

  return pluginFn
}
