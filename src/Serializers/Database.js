'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const { ioc } = require('@adonisjs/fold')
const debug = require('debug')('adonis:auth')

class DatabaseSerializer {
  constructor (Hash) {
    this.Hash = Hash
    this._config = null
    this._queryCallback = null
    this._Db = ioc.use('Adonis/Src/Database')
  }

  /* istanbul ignore next */
  /**
   * Dependencies to be injected by Ioc container
   *
   * @attribute inject
   *
   * @return {Array}
   */
  static get inject () {
    return ['Adonis/Src/Hash']
  }

  /**
   * Returns an instance of the model query
   *
   * @method _getQuery
   *
   * @param  {String} [table = this.table]
   *
   * @return {Object}
   *
   * @private
   */
  _getQuery (table = this.table) {
    const query = this._Db.connection(this.connection).table(table)
    if (typeof (this._queryCallback) === 'function') {
      this._queryCallback(query)
      this._queryCallback = null
    }
    return query
  }

  /**
   * The connection to be used for making
   * database queries
   *
   * @attribute connection
   *
   * @return {String}
   */
  get connection () {
    return this._config.connection || ''
  }

  /**
   * The table name for fetching user
   *
   * @attribute table
   *
   * @return {String}
   */
  get table () {
    return this._config.table
  }

  /**
   * Returns the primary key for the
   * model. It is used to set the
   * session key
   *
   * @attribute primaryKey
   *
   * @return {String}
   */
  get primaryKey () {
    return this._config.primaryKey
  }

  /**
   * The foriegn key for tokens table
   *
   * @attribute foreignKey
   *
   * @return {String}
   */
  get foreignKey () {
    return this._config.foreignKey
  }

  /**
   * The tokens table
   *
   * @attribute tokensTable
   *
   * @return {String}
   */
  get tokensTable () {
    return this._config.tokensTable
  }

  /**
   * Setup config on the serializer instance. It
   * is import and needs to be done as the
   * first step before using the serializer.
   *
   * @method setConfig
   *
   * @param  {Object}  config
   */
  setConfig (config) {
    this._config = config
  }

  /**
   * Add runtime constraints to the query builder. It
   * is helpful when auth has extra constraints too
   *
   * @method query
   *
   * @param  {Function} callback
   *
   * @chainable
   */
  query (callback) {
    this._queryCallback = callback
    return this
  }

  /**
   * Returns a user instance using the primary
   * key
   *
   * @method findById
   *
   * @param  {Number|String} id
   *
   * @return {User|Null}  The model instance or `null`
   */
  async findById (id) {
    debug('finding user with primary key as %s', id)
    return this._getQuery().where(this.primaryKey, id).first()
  }

  /**
   * Finds a user using the uid field
   *
   * @method findByUid
   *
   * @param  {String}  uid
   *
   * @return {Model|Null} The model instance or `null`
   */
  async findByUid (uid) {
    debug('finding user with %s as %s', this._config.uid, uid)
    return this._getQuery().where(this._config.uid, uid).first()
  }

  /**
   * Validates the password field on the user model instance
   *
   * @method validateCredentails
   *
   * @param  {Model}            user
   * @param  {String}            password
   *
   * @return {Boolean}
   */
  async validateCredentails (user, password) {
    if (!user || !user[this._config.password]) {
      return false
    }
    return this.Hash.verify(password, user[this._config.password])
  }

  /**
   * Finds a user with token
   *
   * @method findByToken
   *
   * @param  {String}    token
   * @param  {String}    type
   *
   * @return {Object|Null}
   */
  async findByToken (token, type) {
    debug('finding user for %s token', token)
    const self = this

    return this
      ._getQuery()
      .whereExists(function () {
        this
          .from(self.tokensTable)
          .where({ token, type, is_revoked: false })
          .whereRaw(
            `${self._config.table}.${self.primaryKey} = ${self.tokensTable}.${self.foreignKey}`
          )
      }).first()
  }

  /**
   * Save token for a user. Tokens are usually secondary
   * way to login a user when their primary login is
   * expired
   *
   * @method saveToken
   *
   * @param  {Object}  user
   * @param  {String}  token
   * @param  {String}  type
   *
   * @return {void}
   */
  async saveToken (user, token, type) {
    const foreignKeyValue = user[this.primaryKey]

    const insertPayload = {
      token,
      type,
      is_revoked: false,
      [this.foreignKey]: foreignKeyValue
    }

    debug('saving token for %s user with %j payload', foreignKeyValue, insertPayload)
    await this._getQuery(this.tokensTable).insert(insertPayload)
  }

  /**
   * Revoke token(s) or all tokens for a given user
   *
   * @method revokeTokens
   *
   * @param  {Object}           user
   * @param  {Array|String}     [tokens = null]
   * @param  {Boolean}          [inverse = false]
   *
   * @return {Number}           Number of impacted rows
   */
  async revokeTokens (user, tokens = null, inverse = false) {
    const foreignKeyValue = user[this.primaryKey]

    const query = this._getQuery(this.tokensTable)
    if (tokens) {
      tokens = tokens instanceof Array === true ? tokens : [tokens]
      inverse ? query.whereNotIn('token', tokens) : query.whereIn('token', tokens)
      debug('revoking %j tokens for %s user', tokens, user.primaryKeyValue)
    } else {
      debug('revoking all tokens for %s user', user.primaryKeyValue)
    }

    query.where(this.foreignKey, foreignKeyValue)
    return query.update({ is_revoked: true })
  }

  /**
   * Returns all non-revoked list of tokens for a given user.
   *
   * @method listTokens
   * @async
   *
   * @param  {Object}   user
   * @param  {String}   type
   *
   * @return {Object}
   */
  async listTokens (user, type) {
    const foreignKeyValue = user[this.primaryKey]

    const query = this._getQuery(this.tokensTable)
    query.where({ type, is_revoked: false }).where(this.foreignKey, foreignKeyValue)
    return query
  }

  /**
   * Returns an empty array as the fake results
   *
   * @method fakeResult
   *
   * @return {Array}
   */
  fakeResult () {
    return []
  }
}

module.exports = DatabaseSerializer
