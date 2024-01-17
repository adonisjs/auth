/// <reference types="@adonisjs/core/providers/edge_provider" />

import type { HttpContext } from '@adonisjs/core/http'
import type { NextFn } from '@adonisjs/core/types/http'

import type { Authenticator } from '../authenticator.js'
import type { Authenticators, GuardFactory } from '../types.js'

/**
 * The "InitializeAuthMiddleware" is used to create a request
 * specific authenticator instance for every HTTP request.
 *
 * This middleware does not protect routes from unauthenticated
 * users. Please use the "auth" middleware for that.
 */
export default class InitializeAuthMiddleware {
  async handle(ctx: HttpContext, next: NextFn) {
    const auth = await ctx.containerResolver.make('auth.manager')

    /**
     * Initialize the authenticator for the current HTTP
     * request
     */
    ctx.auth = auth.createAuthenticator(ctx)

    /**
     * Sharing authenticator with templates
     */
    if ('view' in ctx) {
      ctx.view.share({ auth: ctx.auth })
    }

    return next()
  }
}

declare module '@adonisjs/core/http' {
  export interface HttpContext {
    auth: Authenticator<
      Authenticators extends Record<string, GuardFactory> ? Authenticators : never
    >
  }
}
