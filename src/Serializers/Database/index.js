'use strict'

/**
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const NE = require('node-exceptions')
const util = require('../../../lib/util')

class DatabaseSerializer {

  constructor (Database, Hash) {
    this.database = Database
    this.hash = Hash
  }

  /**
   * dependencies to be injected by the IoC container
   * @return {Array}
   */
  static get inject () {
    return ['Adonis/Src/Database', 'Adonis/Src/Hash']
  }

  /**
   * returns primaryKey to be used for saving sessions
   *
   * @param  {Object} options
   * @return {String}
   *
   * @public
   */
  primaryKey (options) {
    return options.primaryKey
  }

  /**
   * decorates database query object by passing options
   * query to where object.
   *
   * @param  {Object} query
   * @param  {Object} options
   *
   * @private
   */
  _decorateQuery (query, options) {
    if (options.query) {
      query.andWhere(options.query)
    }
  }

  /**
   * returns the model instance by model primary key
   *
   * @param  {Number} id
   * @param  {Object} options   - Options defined as the config
   * @return {Object}
   *
   * @public
   */
  * findById (id, options) {
    return yield this.database.from(options.table).where(options.primaryKey, id).first()
  }

  /**
   * returns model instance using the user credentials
   *
   * @param  {String} email
   * @param  {Object} options   - Options defined as the config
   * @return {Object}
   *
   * @public
   */
  * findByCredentials (email, options) {
    const query = this.database.from(options.table).where(options.uid, email)
    this._decorateQuery(query, options)
    return yield query.first()
  }

  /**
   * finds a token using token model and it's related user.
   * It is important to set a belongsTo relation with the
   * user model.
   *
   * @param  {String} token
   * @param  {Object} options
   * @return {Object}
   *
   * @public
   */
  * findByToken (token, options) {
    const query = this.database.from(options.table).where('token', token).andWhere('is_revoked', false)
    this._decorateQuery(query, options)
    return yield query.first()
  }

  /**
   * retrusn user for a given token
   * @param  {Object} token
   * @return {Object}
   *
   * @public
   */
  * getUserForToken (token, options) {
    return yield this.database.from(options.userTable).where(options.primaryKey, token.user_id).first()
  }

  /**
   * tells whether token object is a valid token
   * object or not.
   *
   * @param  {Object}
   * @return {Boolean}
   */
  _isValidTokenObject (token) {
    return (token && token.forever) || (token && Date.parse(token.expiry))
  }

  /**
   * makes token expiry date by adding milliseconds
   * to the current date.
   *
   * @param  {Number} expiry
   * @return {Date}
   *
   * @private
   */
  _getTokenExpiryDate (expiry) {
    return new Date(Date.now() + expiry)
  }

  /**
   * saves a new token for a given user.
   *
   * @param  {Object} user
   * @param  {String} token
   * @param  {Object} options
   * @param  {Number} expiry
   * @returns {Object} - Saved token instance
   *
   * @public
   */
  * saveToken (user, token, options, expiry) {
    const primaryKeyValue = user[options.primaryKey]
    if (!primaryKeyValue) {
      throw new NE.RuntimeException(`Cannot save token as value for ${options.primaryKey} is missing`)
    }
    const tokenObject = {
      token: token,
      user_id: primaryKeyValue,
      forever: !expiry,
      expiry: expiry ? this._getTokenExpiryDate(expiry) : null,
      is_revoked: false
    }
    const isSaved = yield this.database.into(options.table).insert(tokenObject)
    return isSaved ? tokenObject : null
  }

  /**
   * revokes tokens for a given user.
   *
   * @param  {Object} user
   * @param  {Array} tokens
   * @param  {Boolean} reverse
   * @param  {Object} options
   * @returns {Number} - Number of affected rows
   *
   * @public
   */
  * revokeTokens (user, tokens, reverse, options) {
    const primaryKeyValue = user[options.primaryKey]
    if (!primaryKeyValue) {
      throw new NE.RuntimeException(`Cannot save revoke tokens as value for ${options.primaryKey} is missing`)
    }
    const userTokens = this.database.from(options.table).where('user_id', primaryKeyValue)
    if (tokens) {
      const method = reverse ? 'whereNotIn' : 'whereIn'
      userTokens[method]('token', tokens)
    }
    return yield userTokens.update('is_revoked', true)
  }

  /**
   * validates a token by making user a user for the corresponding
   * token exists and the token has not been expired.
   *
   * @param  {Object} token   - token model resolved from findByToken
   * @param  {Object} options
   * @return {Boolean}
   *
   * @public
   */
  * validateToken (token, options) {
    /**
     * return false when token is not a valid
     * tokenObject
     */
    if (!this._isValidTokenObject(token)) {
      return false
    }

    /**
     * return the user when token life is set to forever
     */
    if (token.forever) {
      return true
    }

    /**
     * check whether the expiry date is over the current
     * date/time
     */
    const expiry = token.expiry
    return util.dateDiff(new Date(), new Date(expiry)) > 0
  }

  /**
   * validates user crendentials using the model instance and
   * the password. It makes use of Hash provider.
   *
   * @param  {Object} user
   * @param  {String} password
   * @param  {Object} options
   * @return {Boolean}
   *
   * @public
   */
  * validateCredentials (user, password, options) {
    if (!user || !user[options.password]) {
      yield this.hash.verify(password, 'dummypassword')
      return false
    }
    const actualPassword = user[options.password]
    try {
      return yield this.hash.verify(password, actualPassword)
    } catch (e) {
      return false
    }
  }

}

module.exports = DatabaseSerializer
