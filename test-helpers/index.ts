/*
 * @adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import 'reflect-metadata'
import { join, sep, posix } from 'path'
import { MarkOptional } from 'ts-essentials'
import { Filesystem } from '@poppinss/dev-utils'
import { LucidModel } from '@ioc:Adonis/Lucid/Orm'
import { RedisManagerContract } from '@ioc:Adonis/Addons/Redis'
import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import { ApplicationContract } from '@ioc:Adonis/Core/Application'
import { DatabaseContract, QueryClientContract } from '@ioc:Adonis/Lucid/Database'

import { OATGuard } from '../src/Guards/Oat'
import { SessionGuard } from '../src/Guards/Session'
import { BasicAuthGuard } from '../src/Guards/BasicAuth'
import { LucidProvider } from '../src/UserProviders/Lucid'
import { DatabaseProvider } from '../src/UserProviders/Database'
import { TokenRedisProvider } from '../src/TokenProviders/Redis'
import { TokenDatabaseProvider } from '../src/TokenProviders/Database'

import {
  LucidProviderModel,
  LucidProviderConfig,
  LucidProviderContract,
  TokenProviderContract,
  DatabaseProviderConfig,
  DatabaseProviderContract,
  DatabaseTokenProviderConfig,
} from '@ioc:Adonis/Addons/Auth'

import { Application } from '@adonisjs/core/build/standalone'

export const fs = new Filesystem(join(__dirname, '__app'))

/**
 * Setup application
 */
export async function setupApplication(
  additionalProviders?: string[],
  environment: 'web' | 'repl' | 'test' = 'test'
) {
  await fs.add('.env', '')
  await fs.add(
    'config/app.ts',
    `
		export const appKey = 'averylong32charsrandomsecretkey',
		export const http = {
			cookie: {},
			trustProxy: () => true,
		}
	`
  )

  await fs.add(
    'config/hash.ts',
    `
		const hashConfig = {
			default: 'bcrypt' as const,
			list: {
				bcrypt: {
					driver: 'bcrypt',
					rounds: 10,
				},
			},
		}

		export default hashConfig
	`
  )

  await fs.add(
    'config/session.ts',
    `
		const sessionConfig = {
			driver: 'cookie',
			cookieName: 'adonis-session',
			clearWithBrowser: false,
			age: '2h',
			cookie: {
				path: '/',
			},
		}

		export default sessionConfig
	`
  )

  await fs.add(
    'config/database.ts',
    `const databaseConfig = {
			connection: 'primary',
			connections: {
				primary: {
					client: 'sqlite3',
					connection: {
						filename: '${join(fs.basePath, 'primary.sqlite3').split(sep).join(posix.sep)}',
					},
				},
				secondary: {
					client: 'sqlite3',
					connection: {
						filename: '${join(fs.basePath, 'secondary.sqlite3').split(sep).join(posix.sep)}',
					},
				},
			}
		}

		export default databaseConfig`
  )

  await fs.add(
    'config/auth.ts',
    `const authConfig = {
			guard: 'web',
			guards: {
				web: {
				},
			}
		}

		export default authConfig`
  )

  await fs.add(
    'config/redis.ts',
    `const redisConfig = {
			connection: 'local',
			connections: {
				local: {},
        localDb1: {
          db: '2'
        }
			}
		}
		export default redisConfig`
  )

  const app = new Application(fs.basePath, environment, {
    aliases: {
      App: './app',
    },
    providers: [
      '@adonisjs/core',
      '@adonisjs/repl',
      '@adonisjs/session',
      '@adonisjs/lucid',
      '@adonisjs/redis',
    ].concat(additionalProviders || []),
  })

  await app.setup()
  await app.registerProviders()
  await app.bootProviders()

  return app
}

/**
 * Create the users tables
 */
async function createUsersTable(client: QueryClientContract) {
  await client.schema.createTable('users', (table) => {
    table.increments('id').notNullable().primary()
    table.string('username').notNullable().unique()
    table.string('email').notNullable().unique()
    table.string('password')
    table.string('remember_me_token').nullable()
    table.boolean('is_active').notNullable().defaultTo(1)
    table.string('country').notNullable().defaultTo('IN')
  })
}

/**
 * Create the api tokens tables
 */
async function createTokensTable(client: QueryClientContract) {
  await client.schema.createTable('api_tokens', (table) => {
    table.increments('id').notNullable().primary()
    table.integer('user_id').notNullable().unsigned()
    table.string('name').notNullable()
    table.string('type').notNullable()
    table.string('token').notNullable()
    table.timestamp('expires_at', { useTz: true }).nullable()
    table.string('ip_address').nullable()
    table.string('device_name').nullable()
    table.timestamps(true)
  })
}

/**
 * Returns default config for the lucid provider
 */
export function getLucidProviderConfig<User extends LucidProviderModel>(
  config: MarkOptional<LucidProviderConfig<User>, 'driver' | 'uids' | 'identifierKey' | 'user'>
) {
  const defaults: LucidProviderConfig<User> = {
    driver: 'lucid' as const,
    uids: ['username', 'email' as any],
    model: config.model,
    identifierKey: 'id',
  }
  return defaults
}

/**
 * Returns default config for the database provider
 */
export function getDatabaseProviderConfig() {
  const defaults: DatabaseProviderConfig = {
    driver: 'database' as const,
    uids: ['username', 'email'],
    identifierKey: 'id',
    usersTable: 'users',
  }
  return defaults
}

/**
 * Performs an initial setup
 */
export async function setup(application: ApplicationContract) {
  const db = application.container.use('Adonis/Lucid/Database')
  await createUsersTable(db.connection())
  await createUsersTable(db.connection('secondary'))
  await createTokensTable(db.connection())
  await createTokensTable(db.connection('secondary'))
}

/**
 * Performs cleanup
 */
export async function cleanup(application: ApplicationContract) {
  const db = application.container.use('Adonis/Lucid/Database')
  await db.connection().schema.dropTableIfExists('users')
  await db.connection('secondary').schema.dropTableIfExists('users')
  await db.manager.closeAll()
  await fs.cleanup()
}

/**
 * Reset database tables
 */
export async function reset(application: ApplicationContract) {
  const db = application.container.use('Adonis/Lucid/Database')
  await db.connection().truncate('users')
  await db.connection('secondary').truncate('users')

  await db.connection().truncate('api_tokens')
  await db.connection('secondary').truncate('api_tokens')
}

/**
 * Returns an instance of the lucid provider
 */
export function getLucidProvider<User extends LucidProviderModel>(
  application: ApplicationContract,
  config: MarkOptional<LucidProviderConfig<User>, 'driver' | 'uids' | 'identifierKey' | 'user'>
) {
  const defaults = getLucidProviderConfig(config)
  const normalizedConfig = Object.assign(defaults, config) as LucidProviderConfig<User>
  return new LucidProvider(application, normalizedConfig) as unknown as LucidProviderContract<User>
}

/**
 * Returns an instance of the database provider
 */
export function getDatabaseProvider(
  application: ApplicationContract,
  config: Partial<DatabaseProviderConfig>
) {
  const defaults = getDatabaseProviderConfig()
  const normalizedConfig = Object.assign(defaults, config) as DatabaseProviderConfig
  return new DatabaseProvider(
    application,
    normalizedConfig,
    application.container.use('Adonis/Lucid/Database')
  ) as unknown as DatabaseProviderContract<any>
}

/**
 * Returns an instance of the session driver.
 */
export function getSessionDriver(
  app: ApplicationContract,
  provider: DatabaseProviderContract<any> | LucidProviderContract<any>,
  providerConfig: DatabaseProviderConfig | LucidProviderConfig<any>,
  ctx: HttpContextContract,
  name?: string
) {
  const config = {
    driver: 'session' as const,
    loginRoute: '/login',
    provider: providerConfig,
  }

  return new SessionGuard(
    name || 'session',
    config,
    app.container.use('Adonis/Core/Event'),
    provider,
    ctx
  )
}

/**
 * Returns an instance of the api tokens guard.
 */
export function getApiTokensGuard(
  app: ApplicationContract,
  provider: DatabaseProviderContract<any> | LucidProviderContract<any>,
  providerConfig: DatabaseProviderConfig | LucidProviderConfig<any>,
  ctx: HttpContextContract,
  tokensProvider: TokenProviderContract,
  tokenProviderConfig?: DatabaseTokenProviderConfig
) {
  const config = {
    driver: 'oat' as const,
    tokenProvider: tokenProviderConfig || {
      driver: 'database' as const,
      table: 'api_tokens',
    },
    provider: providerConfig,
  }

  return new OATGuard(
    'api',
    config,
    app.container.use('Adonis/Core/Event'),
    provider,
    ctx,
    tokensProvider
  )
}

/**
 * Returns an instance of the basic auth guard.
 */
export function getBasicAuthGuard(
  app: ApplicationContract,
  provider: DatabaseProviderContract<any> | LucidProviderContract<any>,
  providerConfig: DatabaseProviderConfig | LucidProviderConfig<any>,
  ctx: HttpContextContract
) {
  const config = {
    driver: 'basic' as const,
    realm: 'Login',
    provider: providerConfig,
  }

  return new BasicAuthGuard('basic', config, app.container.use('Adonis/Core/Event'), provider, ctx)
}

/**
 * Returns the database token provider
 */
export function getTokensDbProvider(db: DatabaseContract) {
  return new TokenDatabaseProvider(
    {
      table: 'api_tokens',
      driver: 'database',
    },
    db
  )
}

/**
 * Returns the database token provider
 */
export function getTokensRedisProvider(redis: RedisManagerContract) {
  return new TokenRedisProvider(
    {
      driver: 'redis',
      redisConnection: 'local',
    },
    redis
  )
}

/**
 * Returns the user model
 */
export function getUserModel(BaseModel: LucidModel) {
  const UserModel = class User extends BaseModel {
    public id: number
    public username: string
    public password: string
    public email: string
    public rememberMeToken: string
  }

  UserModel.boot()
  UserModel.$addColumn('id', { isPrimary: true })
  UserModel.$addColumn('username', {})
  UserModel.$addColumn('email', {})
  UserModel.$addColumn('password', {})
  UserModel.$addColumn('rememberMeToken', {})

  return UserModel
}

/**
 * Signs value to be set as cookie header
 */
export function signCookie(app: ApplicationContract, value: any, name: string) {
  return `${name}=s:${app.container
    .use('Adonis/Core/Encryption')
    .verifier.sign(value, undefined, name)}`
}

/**
 * Encrypt value to be set as cookie header
 */
export function encryptCookie(app: ApplicationContract, value: any, name: string) {
  return `${name}=e:${app.container.use('Adonis/Core/Encryption').encrypt(value, undefined, name)}`
}

/**
 * Decrypt cookie
 */
export function decryptCookie(app: ApplicationContract, cookie: any, name: string) {
  const cookieValue = decodeURIComponent(cookie.split(';')[0]).replace(`${name}=`, '').slice(2)

  return app.container.use('Adonis/Core/Encryption').decrypt<any>(cookieValue, name)
}

/**
 * Unsign cookie
 */
export function unsignCookie(app: ApplicationContract, cookie: any, name: string) {
  const cookieValue = decodeURIComponent(cookie.split(';')[0]).replace(`${name}=`, '').slice(2)

  return app.container.use('Adonis/Core/Encryption').verifier.unsign<any>(cookieValue, name)
}

/**
 * Mocks action on a object
 */
export function mockAction(collection: any, name: string, verifier: any) {
  collection[name] = function (...args: any[]) {
    verifier(...args)
    delete collection[name]
  }
}

/**
 * Mocks property on a object
 */
export function mockProperty(collection: any, name: string, value: any) {
  Object.defineProperty(collection, name, {
    get() {
      delete collection[name]
      return value
    },
    enumerable: true,
    configurable: true,
  })
}
