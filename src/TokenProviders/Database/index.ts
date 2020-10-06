/*
 * @adonisjs/auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { DateTime } from 'luxon'
import { safeEqual } from '@poppinss/utils'
import { DatabaseContract } from '@ioc:Adonis/Lucid/Database'
import {
	TokenProviderContract,
	ProviderTokenContract,
	DatabaseTokenProviderConfig,
} from '@ioc:Adonis/Addons/Auth'

import { ProviderToken } from '../../Tokens/ProviderToken'

/**
 * Database backend tokens provider
 */
export class TokenDatabaseProvider implements TokenProviderContract {
	constructor(private config: DatabaseTokenProviderConfig, private db: DatabaseContract) {}

	/**
	 * Returns the query client for database queries
	 */
	private getQueryClient() {
		return this.config.connection
			? this.db.connection(this.config.connection)
			: this.db.connection()
	}

	/**
	 * The foreign key column
	 */
	private foreignKey = this.config.foreignKey || 'user_id'

	/**
	 * Returns the builder query for a given token + type
	 */
	private getLookupQuery(tokenId: string) {
		return this.getQueryClient().from(this.config.table).where('id', tokenId)
	}

	/**
	 * Reads the token using the lookup token id
	 */
	public async read(tokenId: string, tokenHash: string): Promise<ProviderTokenContract | null> {
		const client = this.getQueryClient()

		/**
		 * Find token using id
		 */
		const tokenRow = await this.getLookupQuery(tokenId).first()
		if (!tokenRow || !tokenRow.token) {
			return null
		}

		/**
		 * Ensure hash of the user provided value is same as the one inside
		 * the database
		 */
		if (!safeEqual(tokenRow.token, tokenHash)) {
			return null
		}

		const {
			name,
			[this.foreignKey]: userId,
			token: value,
			expires_at: expiresAt,
			type,
			...meta
		} = tokenRow
		let normalizedExpiryDate: undefined | DateTime

		/**
		 * Parse dialect date to an instance of Luxon
		 */
		if (expiresAt instanceof Date) {
			normalizedExpiryDate = DateTime.fromJSDate(expiresAt)
		} else if (expiresAt && typeof expiresAt === 'string') {
			normalizedExpiryDate = DateTime.fromFormat(expiresAt, client.dialect.dateTimeFormat)
		} else if (expiresAt && typeof expiresAt === 'number') {
			normalizedExpiryDate = DateTime.fromMillis(expiresAt)
		}

		/**
		 * Ensure token isn't expired
		 */
		if (
			normalizedExpiryDate &&
			normalizedExpiryDate.diff(DateTime.local(), 'millisecond').milliseconds <= 0
		) {
			return null
		}

		const token = new ProviderToken(name, value, userId, type)
		token.expiresAt = expiresAt
		token.meta = meta
		return token
	}

	/**
	 * Saves the token and returns the persisted token lookup id.
	 */
	public async write(token: ProviderToken): Promise<string> {
		const client = this.getQueryClient()

		/**
		 * Payload to save to the database
		 */
		const payload = {
			[this.foreignKey]: token.userId,
			name: token.name,
			token: token.tokenHash,
			type: token.type,
			expires_at: token.expiresAt ? token.expiresAt.toFormat(client.dialect.dateTimeFormat) : null,
			created_at: DateTime.local().toFormat(client.dialect.dateTimeFormat),
			...token.meta,
		}

		const [persistedToken] = await client.table(this.config.table).insert(payload).returning('id')
		return String(persistedToken)
	}

	/**
	 * Removes a given token
	 */
	public async destroy(tokenId: string) {
		await this.getLookupQuery(tokenId).delete()
	}
}
