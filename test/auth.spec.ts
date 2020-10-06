/*
 * @adonisjs/auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import test from 'japa'
import 'reflect-metadata'
import { DatabaseContract } from '@ioc:Adonis/Lucid/Database'

import { AuthManager } from '../src/AuthManager'
import { SessionGuard } from '../src/Guards/Session'
import { LucidProvider } from '../src/UserProviders/Lucid'
import { DatabaseProvider } from '../src/UserProviders/Database'
import { TokenDatabaseProvider } from '../src/TokenProviders/Database'

import {
	setup,
	reset,
	getDb,
	getCtx,
	cleanup,
	getModel,
	container,
	mockAction,
	mockProperty,
	getUserModel,
	getLucidProviderConfig,
	getDatabaseProviderConfig,
} from '../test-helpers'

let db: DatabaseContract
let BaseModel: ReturnType<typeof getModel>

test.group('Auth', (group) => {
	group.before(async () => {
		db = await getDb()
		BaseModel = getModel(db)
		await setup(db)
	})

	group.after(async () => {
		await cleanup(db)
	})

	group.afterEach(async () => {
		await reset(db)
	})

	test('make and cache instance of the session guard', (assert) => {
		const User = getUserModel(BaseModel)

		const manager = new AuthManager(container, {
			guard: 'session',
			list: {
				api: {
					driver: 'oat',
					tokenProvider: {
						driver: 'database',
						table: 'api_tokens',
					},
					provider: getLucidProviderConfig({ model: User }),
				},
				basic: {
					driver: 'basic',
					provider: getLucidProviderConfig({ model: User }),
				},
				session: {
					driver: 'session',
					provider: getLucidProviderConfig({ model: User }),
				},
				sessionDb: {
					driver: 'session',
					provider: getDatabaseProviderConfig(),
				},
			},
		})

		const ctx = getCtx()
		const auth = manager.getAuthForRequest(ctx)
		const mapping = auth.use('session')
		mapping['isCached'] = true

		assert.equal(auth.use('session')['isCached'], true)
		assert.instanceOf(mapping, SessionGuard)
		assert.instanceOf(mapping.provider, LucidProvider)
	})

	test('proxy all methods to the default driver', async (assert) => {
		const User = getUserModel(BaseModel)

		const manager = new AuthManager(container, {
			guard: 'custom',
			list: {
				custom: {
					driver: 'custom',
					provider: getLucidProviderConfig({ model: User }),
				},
				session: {
					driver: 'session',
					provider: getLucidProviderConfig({ model: User }),
				},
				sessionDb: {
					driver: 'session',
					provider: getDatabaseProviderConfig(),
				},
			},
		} as any)

		class CustomGuard {}
		const guardInstance = new CustomGuard()

		const ctx = getCtx()
		const auth = manager.getAuthForRequest(ctx)

		manager.extend('guard', 'custom', () => {
			return guardInstance as any
		})

		/**
		 * Test attempt
		 */
		mockAction(guardInstance, 'attempt', function (
			uid: string,
			secret: string,
			rememberMe: boolean
		) {
			assert.equal(uid, 'foo')
			assert.equal(secret, 'secret')
			assert.equal(rememberMe, true)
		})
		await auth.attempt('foo', 'secret', true)

		/**
		 * Test verify credentails
		 */
		mockAction(guardInstance, 'verifyCredentials', function (uid: string, secret: string) {
			assert.equal(uid, 'foo')
			assert.equal(secret, 'secret')
		})
		await auth.verifyCredentials('foo', 'secret')

		/**
		 * Test login
		 */
		mockAction(guardInstance, 'login', function (user: any, rememberMe: boolean) {
			assert.deepEqual(user, { id: 1 })
			assert.equal(rememberMe, true)
		})
		await auth.login({ id: 1 }, true)

		/**
		 * Test loginViaId
		 */
		mockAction(guardInstance, 'loginViaId', function (id: number, rememberMe: boolean) {
			assert.deepEqual(id, 1)
			assert.equal(rememberMe, true)
		})
		await auth.loginViaId(1, true)

		/**
		 * Test logout
		 */
		mockAction(guardInstance, 'logout', function (renewToken: boolean) {
			assert.equal(renewToken, true)
		})
		await auth.logout(true)

		/**
		 * Test authenticate
		 */
		mockAction(guardInstance, 'authenticate', function () {
			assert.isTrue(true)
		})
		await auth.authenticate()

		/**
		 * Test check
		 */
		mockAction(guardInstance, 'check', function () {
			assert.isTrue(true)
		})
		await auth.check()

		/**
		 * Test isGuest
		 */
		mockProperty(guardInstance, 'isGuest', false)
		assert.isFalse(auth.isGuest)

		/**
		 * Test user
		 */
		mockProperty(guardInstance, 'user', { id: 1 })
		assert.deepEqual(auth.user, { id: 1 })

		/**
		 * Test isLoggedIn
		 */
		mockProperty(guardInstance, 'isLoggedIn', true)
		assert.isTrue(auth.isLoggedIn)

		/**
		 * Test isLoggedOut
		 */
		mockProperty(guardInstance, 'isLoggedOut', true)
		assert.isTrue(auth.isLoggedOut)

		/**
		 * Test authenticationAttempted
		 */
		mockProperty(guardInstance, 'authenticationAttempted', true)
		assert.isTrue(auth.authenticationAttempted)
	})

	test('update default guard', (assert) => {
		const User = getUserModel(BaseModel)

		const manager = new AuthManager(container, {
			guard: 'session',
			list: {
				session: {
					driver: 'session',
					provider: getLucidProviderConfig({ model: User }),
				},
				basic: {
					driver: 'basic',
					provider: getLucidProviderConfig({ model: User }),
				},
				api: {
					driver: 'oat',
					tokenProvider: {
						driver: 'database',
						table: 'api_tokens',
					},
					provider: getLucidProviderConfig({ model: User }),
				},
				sessionDb: {
					driver: 'session',
					provider: getDatabaseProviderConfig(),
				},
			},
		})

		const ctx = getCtx()
		const auth = manager.getAuthForRequest(ctx)
		auth.defaultGuard = 'sessionDb'

		assert.equal(auth.name, 'sessionDb')
		assert.instanceOf(auth.provider, DatabaseProvider)
	})

	test('serialize toJSON', (assert) => {
		const User = getUserModel(BaseModel)

		const manager = new AuthManager(container, {
			guard: 'session',
			list: {
				session: {
					driver: 'session',
					provider: getLucidProviderConfig({ model: User }),
				},
				api: {
					driver: 'oat',
					tokenProvider: {
						driver: 'database',
						table: 'api_tokens',
					},
					provider: getLucidProviderConfig({ model: User }),
				},
				basic: {
					driver: 'basic',
					provider: getLucidProviderConfig({ model: User }),
				},
				sessionDb: {
					driver: 'session',
					provider: getDatabaseProviderConfig(),
				},
			},
		})

		const ctx = getCtx()
		const auth = manager.getAuthForRequest(ctx)
		auth.defaultGuard = 'sessionDb'
		auth.use()

		assert.deepEqual(auth.toJSON(), {
			defaultGuard: 'sessionDb',
			guards: {
				sessionDb: {
					isLoggedIn: false,
					isGuest: true,
					viaRemember: false,
					user: undefined,
					authenticationAttempted: false,
					isAuthenticated: false,
				},
			},
		})
	})

	test('make oat guard', (assert) => {
		const User = getUserModel(BaseModel)

		const manager = new AuthManager(container, {
			guard: 'api',
			list: {
				api: {
					driver: 'oat',
					tokenProvider: {
						driver: 'database',
						table: 'api_tokens',
					},
					provider: getLucidProviderConfig({ model: User }),
				},
				basic: {
					driver: 'basic',
					provider: getLucidProviderConfig({ model: User }),
				},
				session: {
					driver: 'session',
					provider: getLucidProviderConfig({ model: User }),
				},
				sessionDb: {
					driver: 'session',
					provider: getDatabaseProviderConfig(),
				},
			},
		})

		const ctx = getCtx()
		const auth = manager.getAuthForRequest(ctx).use('api')

		assert.equal(auth.name, 'api')
		assert.instanceOf(auth.provider, LucidProvider)
		assert.instanceOf(auth.tokenProvider, TokenDatabaseProvider)
	})

	test('return user_id when foreignKey is missing', (assert) => {
		const User = getUserModel(BaseModel)

		const manager = new AuthManager(container, {
			guard: 'api',
			list: {
				api: {
					driver: 'oat',
					tokenProvider: {
						driver: 'database',
						table: 'api_tokens',
					},
					provider: getLucidProviderConfig({ model: User }),
				},
				basic: {
					driver: 'basic',
					provider: getLucidProviderConfig({ model: User }),
				},
				session: {
					driver: 'session',
					provider: getLucidProviderConfig({ model: User }),
				},
				sessionDb: {
					driver: 'session',
					provider: getDatabaseProviderConfig(),
				},
			},
		})

		const ctx = getCtx()
		const auth = manager.getAuthForRequest(ctx).use('api')

		assert.instanceOf(auth.tokenProvider, TokenDatabaseProvider)
		assert.equal(auth.tokenProvider.foreignKey, 'user_id')
	})

	test('return the foreignKey when not missing', (assert) => {
		const User = getUserModel(BaseModel)

		const manager = new AuthManager(container, {
			guard: 'api',
			list: {
				api: {
					driver: 'oat',
					tokenProvider: {
						driver: 'database',
						table: 'api_tokens',
						foreignKey: 'account_id',
					},
					provider: getLucidProviderConfig({ model: User }),
				},
				basic: {
					driver: 'basic',
					provider: getLucidProviderConfig({ model: User }),
				},
				session: {
					driver: 'session',
					provider: getLucidProviderConfig({ model: User }),
				},
				sessionDb: {
					driver: 'session',
					provider: getDatabaseProviderConfig(),
				},
			},
		})

		const ctx = getCtx()
		const auth = manager.getAuthForRequest(ctx).use('api')

		assert.instanceOf(auth.tokenProvider, TokenDatabaseProvider)
		assert.equal(auth.tokenProvider.foreignKey, 'account_id')
	})
})
