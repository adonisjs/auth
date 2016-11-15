'use strict'

/**
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * NOTE
 * Bind the instance to the IoC container.
*/

const Ioc = require('adonis-fold').Ioc
const util = require('../../../lib/util')

class LucidSerializer {

  constructor (Hash) {
    this.hash = Hash
  }

  /**
   * dependencies to be auto injected by the IoC container
   * @return {Array}
   * @private
   */
  static get inject () {
    return ['Adonis/Src/Hash']
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
    return this._getModel(options.model).primaryKey
  }

  /**
   * returns the model from the Ioc container if parameter
   * is a string, otherwise returns the actual binding.
   *
   * @param  {String|Object} model
   * @return {Object}
   * @throws Error when unable to find binding from the IoC container.
   *
   * @private
   */
  _getModel (model) {
    return typeof (model) === 'string' ? Ioc.use(model) : model
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
    const model = this._getModel(options.model)
    return yield model.find(id)
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
    const model = this._getModel(options.model)
    const query = model.query().where(options.uid, email)
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
    const model = this._getModel(options.model)
    const query = model.query().where('token', token).andWhere('is_revoked', false)
    this._decorateQuery(query, options)
    return yield query.with('user').first()
  }

  /**
   * return user for a given token
   *
   * @param  {Object} token
   * @return {Object}
   *
   * @public
   */
  * getUserForToken (token) {
    // since user is eagerLoaded with token, we just need
    // to pull the user out of it.
    return token.get('user')
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
    const tokenObject = {
      token: token,
      forever: !expiry,
      expiry: expiry ? this._getTokenExpiryDate(expiry) : null,
      is_revoked: false
    }
    const Token = this._getModel(options.model)
    const tokenInstance = new Token(tokenObject)
    const isSaved = yield user.apiTokens().save(tokenInstance)
    return isSaved ? tokenInstance : null
  }

  /**
   * revokes tokens for a given user.
   *
   * @param  {Object} user
   * @param  {Array} tokens
   * @param  {Boolean} reverse
   * @returns {Number} - Number of affected rows
   *
   * @public
   */
  * revokeTokens (user, tokens, reverse) {
    const userTokens = user.apiTokens()
    if (tokens) {
      const method = reverse ? 'whereNotIn' : 'whereIn'
      userTokens[method]('token', tokens)
    }
    return yield userTokens.update({'is_revoked': true})
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
     * return false when token or the user related to token
     * does not exists.
     */
    if (!token || !token.get || !token.get('user')) {
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
    const expiry = token.toJSON().expiry
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

module.exports = LucidSerializer
