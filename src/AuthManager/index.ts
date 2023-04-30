/*
 * @adonisjs/auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Exception, ManagerConfigValidator } from '@poppinss/utils'

import {
  AuthConfig,
  GuardsList,
  OATGuardConfig,
  SessionGuardConfig,
  LucidProviderConfig,
  AuthManagerContract,
  ExtendGuardCallback,
  BasicAuthGuardConfig,
  UserProviderContract,
  DatabaseProviderConfig,
  ExtendProviderCallback,
  ExtendClientCallback,
  ExtendTokenProviderCallback,
} from '@ioc:Adonis/Addons/Auth'

import { ApplicationContract } from '@ioc:Adonis/Core/Application'
import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'

import { Auth } from '../Auth'

/**
 * Auth manager to manage guards and providers object. The extend API can
 * be used to add custom guards and providers
 */
export class AuthManager implements AuthManagerContract {
  /**
   * Extended set of testing clients
   */
  private extendedClients: Map<string, ExtendClientCallback> = new Map()

  /**
   * Extended set of providers
   */
  private extendedProviders: Map<string, ExtendProviderCallback> = new Map()

  /**
   * Extend set of token providers
   */
  private extendedTokenProviders: Map<string, ExtendTokenProviderCallback> = new Map()

  /**
   * Extend set of guards
   */
  private extendedGuards: Map<string, ExtendGuardCallback> = new Map()

  /**
   * Reference to the default guard
   */
  public defaultGuard = this.config.guard

  constructor(public application: ApplicationContract, private config: AuthConfig) {
    const validator = new ManagerConfigValidator(config, 'auth', 'config/auth')
    validator.validateDefault('guard')
    validator.validateList('guards', 'guard')
  }

  /**
   * Verifies and returns an instance of the event emitter
   */
  private getEmitter() {
    const hasEmitter = this.application.container.hasBinding('Adonis/Core/Event')
    if (!hasEmitter) {
      throw new Exception('"Adonis/Core/Event" is required by the auth provider')
    }

    return this.application.container.use('Adonis/Core/Event')
  }

  /**
   * Lazily makes an instance of the lucid provider
   */
  private makeLucidProvider(config: LucidProviderConfig<any>) {
    return new (require('../UserProviders/Lucid').LucidProvider)(this.application, config)
  }

  /**
   * Lazily makes an instance of the database provider
   */
  private makeDatabaseProvider(config: DatabaseProviderConfig) {
    const Database = this.application.container.use('Adonis/Lucid/Database')
    return new (require('../UserProviders/Database').DatabaseProvider)(
      this.application,
      config,
      Database
    )
  }

  /**
   * Returns an instance of the extended provider
   */
  private makeExtendedProvider(mapping: string, config: any) {
    const providerCallback = this.extendedProviders.get(config.driver)
    if (!providerCallback) {
      throw new Exception(`Invalid provider "${config.driver}"`)
    }

    return providerCallback(this, mapping, config)
  }

  /**
   * Lazily makes an instance of the token database provider
   */
  private makeTokenDatabaseProvider(config: DatabaseProviderConfig) {
    const Database = this.application.container.use('Adonis/Lucid/Database')
    return new (require('../TokenProviders/Database').TokenDatabaseProvider)(config, Database)
  }

  /**
   * Lazily makes an instance of the token redis provider
   */
  private makeTokenRedisProvider(config: DatabaseProviderConfig) {
    if (!this.application.container.hasBinding('Adonis/Addons/Redis')) {
      throw new Exception('"@adonisjs/redis" is required to use the "redis" token provider')
    }

    const Redis = this.application.container.use('Adonis/Addons/Redis')
    return new (require('../TokenProviders/Redis').TokenRedisProvider)(config, Redis)
  }

  /**
   * Returns an instance of the extended provider
   */
  private makeExtendedTokenProvider(config: any) {
    const tokenProviderCallback = this.extendedTokenProviders.get(config.driver)
    if (!tokenProviderCallback) {
      throw new Exception(`Invalid token provider "${config.driver}"`)
    }

    return tokenProviderCallback(this, config)
  }

  /**
   * Returns an instance of the session guard
   */
  private makeSessionGuard(
    mapping: string,
    config: SessionGuardConfig<any>,
    provider: UserProviderContract<any>,
    ctx: HttpContextContract
  ) {
    const { SessionGuard } = require('../Guards/Session')
    return new SessionGuard(mapping, config, this.getEmitter(), provider, ctx)
  }

  /**
   * Returns an instance of the session guard
   */
  private makeOatGuard(
    mapping: string,
    config: OATGuardConfig<any>,
    provider: UserProviderContract<any>,
    ctx: HttpContextContract
  ) {
    const { OATGuard } = require('../Guards/Oat')
    const tokenProvider = this.makeTokenProviderInstance(config.tokenProvider)
    return new OATGuard(mapping, config, this.getEmitter(), provider, ctx, tokenProvider)
  }

  /**
   * Returns an instance of the basic auth guard
   */
  private makeBasicAuthGuard(
    mapping: string,
    config: BasicAuthGuardConfig<any>,
    provider: UserProviderContract<any>,
    ctx: HttpContextContract
  ) {
    const { BasicAuthGuard } = require('../Guards/BasicAuth')
    return new BasicAuthGuard(mapping, config, this.getEmitter(), provider, ctx)
  }

  /**
   * Returns an instance of the extended guard
   */
  private makeExtendedGuard(
    mapping: string,
    config: any,
    provider: UserProviderContract<any>,
    ctx: HttpContextContract
  ) {
    const guardCallback = this.extendedGuards.get(config.driver)
    if (!guardCallback) {
      throw new Exception(`Invalid guard driver "${config.driver}" property`)
    }

    return guardCallback(this, mapping, config, provider, ctx)
  }

  /**
   * Returns an instance of the session client
   */
  private makeSessionClient(
    mapping: string,
    config: SessionGuardConfig<any>,
    provider: UserProviderContract<any>
  ) {
    const { SessionClient } = require('../Clients/Session')
    return new SessionClient(mapping, config, provider)
  }

  /**
   * Returns an instance of the session client
   */
  private makeOatClient(
    mapping: string,
    config: OATGuardConfig<any>,
    provider: UserProviderContract<any>
  ) {
    const { OATClient } = require('../Clients/Oat')
    const tokenProvider = this.makeTokenProviderInstance(config.tokenProvider)
    return new OATClient(mapping, config, provider, tokenProvider)
  }

  /**
   * Returns an instance of the extended client
   */
  private makeExtendedClient(mapping: string, config: any, provider: UserProviderContract<any>) {
    const clientCallback = this.extendedClients.get(config.driver)
    if (!clientCallback) {
      throw new Exception(`Invalid guard driver "${config.driver}" property`)
    }

    return clientCallback(this, mapping, config, provider)
  }

  /**
   * Makes client instance for the defined driver inside the
   * mapping config.
   */
  private makeClientInstance(
    mapping: string,
    mappingConfig: any,
    provider: UserProviderContract<any>
  ) {
    if (!mappingConfig || !mappingConfig.driver) {
      throw new Exception('Invalid auth config, missing "driver" property')
    }

    switch (mappingConfig.driver) {
      case 'session':
        return this.makeSessionClient(mapping, mappingConfig, provider)
      case 'oat':
        return this.makeOatClient(mapping, mappingConfig, provider)
      case 'basic':
        throw new Exception(
          'There is no testing client for basic auth. Use "request.basicAuth" method instead'
        )
      default:
        return this.makeExtendedClient(mapping, mappingConfig, provider)
    }
  }

  /**
   * Makes instance of a provider based upon the driver value
   */
  private makeUserProviderInstance(mapping: string, providerConfig: any) {
    if (!providerConfig || !providerConfig.driver) {
      throw new Exception('Invalid auth config, missing "provider" or "provider.driver" property')
    }

    switch (providerConfig.driver) {
      case 'lucid':
        return this.makeLucidProvider(providerConfig)
      case 'database':
        return this.makeDatabaseProvider(providerConfig)
      default:
        return this.makeExtendedProvider(mapping, providerConfig)
    }
  }

  /**
   * Makes instance of a provider based upon the driver value
   */
  private makeTokenProviderInstance(providerConfig: any) {
    if (!providerConfig || !providerConfig.driver) {
      throw new Exception(
        'Invalid auth config, missing "tokenProvider" or "tokenProvider.driver" property'
      )
    }

    switch (providerConfig.driver) {
      case 'database':
        return this.makeTokenDatabaseProvider(providerConfig)
      case 'redis':
        return this.makeTokenRedisProvider(providerConfig)
      default:
        return this.makeExtendedTokenProvider(providerConfig)
    }
  }

  /**
   * Makes guard instance for the defined driver inside the
   * mapping config.
   */
  private makeGuardInstance(
    mapping: string,
    mappingConfig: any,
    provider: UserProviderContract<any>,
    ctx: HttpContextContract
  ) {
    if (!mappingConfig || !mappingConfig.driver) {
      throw new Exception('Invalid auth config, missing "driver" property')
    }

    switch (mappingConfig.driver) {
      case 'session':
        return this.makeSessionGuard(mapping, mappingConfig, provider, ctx)
      case 'oat':
        return this.makeOatGuard(mapping, mappingConfig, provider, ctx)
      case 'basic':
        return this.makeBasicAuthGuard(mapping, mappingConfig, provider, ctx)
      default:
        return this.makeExtendedGuard(mapping, mappingConfig, provider, ctx)
    }
  }

  /**
   * Make an instance of a given mapping for the current HTTP request.
   */
  public makeMapping(ctx: HttpContextContract, mapping: keyof GuardsList) {
    const mappingConfig = this.config.guards[mapping]

    if (mappingConfig === undefined) {
      throw new Exception(
        `Invalid guard "${mapping}". Make sure the guard is defined inside the config/auth file`
      )
    }

    const provider = this.makeUserProviderInstance(mapping, mappingConfig.provider)
    return this.makeGuardInstance(mapping, mappingConfig, provider, ctx)
  }

  /**
   * Returns an instance of the testing
   */
  public client(mapping: keyof GuardsList) {
    const mappingConfig = this.config.guards[mapping]

    if (mappingConfig === undefined) {
      throw new Exception(
        `Invalid guard "${mapping}". Make sure the guard is defined inside the config/auth file`
      )
    }

    const provider = this.makeUserProviderInstance(mapping, mappingConfig.provider)
    return this.makeClientInstance(mapping, mappingConfig, provider)
  }

  /**
   * Returns an instance of the auth class for the current request
   */
  public getAuthForRequest(ctx: HttpContextContract) {
    return new Auth(this, ctx)
  }

  /**
   * Extend auth by adding custom providers and guards
   */
  public extend(type: 'provider', name: string, callback: ExtendProviderCallback): void
  public extend(type: 'token', name: string, callback: ExtendTokenProviderCallback): void
  public extend(type: 'guard', name: string, callback: ExtendGuardCallback): void
  public extend(type: 'client', name: string, callback: ExtendClientCallback): void
  public extend(
    type: 'provider' | 'token' | 'guard' | 'client',
    name: string,
    callback:
      | ExtendProviderCallback
      | ExtendTokenProviderCallback
      | ExtendGuardCallback
      | ExtendClientCallback
  ) {
    if (type === 'provider') {
      this.extendedProviders.set(name, callback as ExtendProviderCallback)
      return
    }

    if (type === 'token') {
      this.extendedTokenProviders.set(name, callback as ExtendTokenProviderCallback)
      return
    }

    if (type === 'client') {
      this.extendedClients.set(name, callback as ExtendClientCallback)
      return
    }

    if (type === 'guard') {
      this.extendedGuards.set(name, callback as ExtendGuardCallback)
      return
    }
  }
}
