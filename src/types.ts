/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { HttpContext } from '@adonisjs/core/http'
import type { ApplicationService, ConfigProvider } from '@adonisjs/core/types'

import type { AuthManager } from './auth_manager.ts'
import type { GUARD_KNOWN_EVENTS } from './symbols.ts'

/**
 * Authentication response to login a user as a client.
 * This response is used by Japa plugins to set up authentication
 * state during testing.
 *
 * @example
 * const response: AuthClientResponse = {
 *   cookies: { 'auth-token': 'abc123' },
 *   session: { userId: 1 },
 *   headers: { 'Authorization': 'Bearer token' }
 * }
 */
export interface AuthClientResponse {
  /**
   * HTTP headers to be set for authentication
   */
  headers?: Record<string, any>

  /**
   * Cookies to be set for authentication
   */
  cookies?: Record<string, any>

  /**
   * Session data to be set for authentication
   */
  session?: Record<string, any>
}

/**
 * A set of properties a guard must implement to authenticate
 * incoming HTTP requests. This is the core contract that all
 * authentication guards must follow.
 *
 * @template User - The type of the authenticated user
 *
 * @example
 * class SessionGuard implements GuardContract<User> {
 *   readonly driverName = 'session'
 *   user?: User
 *   isAuthenticated = false
 *   authenticationAttempted = false
 *
 *   async authenticate(): Promise<User> {
 *     // Implementation
 *   }
 * }
 */
export interface GuardContract<User> {
  /**
   * A unique name for the guard driver (e.g., 'session', 'api', 'basic')
   */
  readonly driverName: string

  /**
   * Reference to the currently authenticated user.
   * Undefined when not authenticated.
   */
  user?: User

  /**
   * Returns logged-in user or throws an exception.
   * Use this when you need to ensure the user is authenticated.
   *
   * @throws {RuntimeException} When user is not authenticated
   */
  getUserOrFail(): User

  /**
   * A boolean to know if the current request has been authenticated.
   * Returns false if authentication was not attempted.
   */
  isAuthenticated: boolean

  /**
   * Whether or not the authentication has been attempted
   * during the current request. Used to differentiate between
   * "not attempted" and "attempted but failed".
   */
  authenticationAttempted: boolean

  /**
   * Authenticates the current request and throws an
   * exception if the request is not authenticated.
   *
   * @throws {E_UNAUTHORIZED_ACCESS} When authentication fails
   */
  authenticate(): Promise<User>

  /**
   * Check if the current request has been authenticated
   * without throwing an exception. Use this for optional
   * authentication scenarios.
   */
  check(): Promise<boolean>

  /**
   * The method is used to authenticate the user as client
   * during testing. This method should return cookies, headers,
   * or session state that can be used to simulate authentication.
   *
   * @param user - The user to authenticate as
   * @param args - Additional arguments specific to the guard
   */
  authenticateAsClient(user: User, ...args: any[]): Promise<AuthClientResponse>

  /**
   * Symbol for inferring the events emitted by a specific guard.
   * Used internally for type inference of guard events.
   */
  [GUARD_KNOWN_EVENTS]: unknown
}

/**
 * The guard factory method is called to create an instance
 * of a guard during an HTTP request. Each guard factory receives
 * the HTTP context and returns a configured guard instance.
 *
 * @param ctx - The HTTP context for the current request
 *
 * @example
 * const sessionGuardFactory: GuardFactory = (ctx) => {
 *   return new SessionGuard(ctx)
 * }
 */
export type GuardFactory = (ctx: HttpContext) => GuardContract<unknown>

/**
 * Config provider for registering guards. Used for lazy loading
 * of guard factories. The resolver function is called with the
 * guard name and application instance to create the factory.
 *
 * @template Factory - The guard factory type
 *
 * @example
 * const guardProvider: GuardConfigProvider<SessionGuardFactory> = {
 *   resolver: async (name, app) => {
 *     const sessionConfig = await app.container.make('session.config')
 *     return (ctx) => new SessionGuard(ctx, sessionConfig)
 *   }
 * }
 */
export type GuardConfigProvider<Factory extends GuardFactory> = {
  /**
   * Resolver function that creates the guard factory
   *
   * @param name - The name of the guard being resolved
   * @param app - The application service instance
   */
  resolver: (name: string, app: ApplicationService) => Promise<Factory>
}

/**
 * Authenticators are inferred inside the user application
 * from the config file. This interface is augmented automatically
 * when you define your auth configuration.
 *
 * @example
 * // After defining your auth config, this interface will be augmented:
 * declare module '@adonisjs/auth/types' {
 *   interface Authenticators {
 *     web: SessionGuardFactory
 *     api: TokenGuardFactory
 *   }
 * }
 */
export interface Authenticators {}

/**
 * Infer authenticators from the auth config. This utility type
 * extracts the guards configuration from a config provider.
 *
 * @template Config - The auth config provider type
 *
 * @example
 * type MyAuthenticators = InferAuthenticators<typeof authConfig>
 * // Results in: { web: SessionGuardFactory, api: TokenGuardFactory }
 */
export type InferAuthenticators<
  Config extends ConfigProvider<{
    default: unknown
    guards: unknown
  }>,
> = Awaited<ReturnType<Config['resolver']>>['guards']

/**
 * Helper to convert union to intersection. This utility type
 * transforms a union of types into an intersection of types.
 * Used internally for merging guard events.
 *
 * @template U - The union type to convert
 *
 * @example
 * type Union = { a: string } | { b: number }
 * type Intersection = UnionToIntersection<Union>
 * // Results in: { a: string } & { b: number }
 */
type UnionToIntersection<U> = (U extends any ? (k: U) => void : never) extends (k: infer I) => void
  ? I
  : never

/**
 * Infer events based upon the configured authenticators.
 * This type extracts and merges all events from all configured
 * guards into a single intersection type.
 *
 * @template KnownAuthenticators - Record of guard names to guard factories
 *
 * @example
 * type AuthEvents = InferAuthEvents<{
 *   web: SessionGuardFactory
 *   api: TokenGuardFactory
 * }>
 * // Results in intersection of all guard events
 */
export type InferAuthEvents<KnownAuthenticators extends Record<string, GuardFactory>> =
  UnionToIntersection<
    {
      [K in keyof KnownAuthenticators]: ReturnType<
        KnownAuthenticators[K]
      >[typeof GUARD_KNOWN_EVENTS]
    }[keyof KnownAuthenticators]
  >

/**
 * Auth service is a singleton instance of the AuthManager
 * configured using the config stored within the user app.
 * This interface is used for dependency injection and provides
 * type-safe access to the auth manager.
 *
 * @example
 * // In a service or controller:
 * class UserController {
 *   constructor(private auth: AuthService) {}
 *
 *   async login() {
 *     const user = await this.auth.createAuthenticator(ctx).authenticate()
 *   }
 * }
 */
export interface AuthService extends AuthManager<
  Authenticators extends Record<string, GuardFactory> ? Authenticators : never
> {}
