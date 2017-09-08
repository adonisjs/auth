'use strict'

/**
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const GE = require('@adonisjs/generic-exceptions')

/**
 * This exception is raised when user is not found. This usally
 * happens when trying to authenticate user using their
 * credentials.
 *
 * @class UserNotFoundException
 */
class UserNotFoundException extends GE.LogicalException {
  static invoke (message) {
    return new this(message, 401, 'E_USER_NOT_FOUND')
  }

  /**
   * Handle user not found exception, this method does a
   * lot of work to find the correct way to handle the
   * exception. Try reading the code to understand
   * it.
   *
   * @method handle
   *
   * @param  {Number} options.status
   * @param  {Object} options.request
   * @param  {Object} options.response
   * @param  {Object} options.session
   * @param  {Object} options.auth
   *
   * @return {void}
   */
  async handle ({ status }, { request, response, session, auth }) {
    const isJSON = request.accepts(['html', 'json']) === 'json'
    const errorMessages = [{ field: auth.uidField, message: `Cannot find user with provided ${auth.uidField}` }]

    /**
     * If request is json then return a json response
     */
    if (isJSON) {
      response.status(status).send(errorMessages)
      return
    }

    /**
     * If auth scheme is session, then flash the data
     * back to the form
     */
    if (auth.scheme === 'session') {
      session.withErrors(errorMessages).flashExcept([auth.passwordField])
      await session.commit()
      response.redirect('back')
      return
    }

    /**
     * If using basic auth, then prompt user with a native
     * browser dialog
     */
    if (auth.scheme === 'basic') {
      response.header('WWW-Authenticate', 'Basic realm="example"')
      response.status(status).send('Access denied')
      return
    }

    /**
     * Fallback to json response
     */
    response.status(status).send(errorMessages)
  }
}

/**
 * This exception is raised when user password mis-matches. This usally
 * happens when trying to authenticate user using their credentials.
 *
 * @class PasswordMisMatchException
 */
class PasswordMisMatchException extends GE.LogicalException {
  static invoke (message) {
    return new this(message, 401, 'E_PASSWORD_MISMATCH')
  }

  /**
   * Handle password mis-match exception, this method does a
   * lot of work to find the correct way to handle the
   * exception. Try reading the code to understand
   * it.
   *
   * @method handle
   *
   * @param  {Number} options.status
   * @param  {Object} options.request
   * @param  {Object} options.response
   * @param  {Object} options.session
   * @param  {Object} options.auth
   *
   * @return {void}
   */
  async handle ({ status }, { request, response, session, auth }) {
    const isJSON = request.accepts(['html', 'json']) === 'json'
    const errorMessages = [{ field: auth.passwordField, message: 'Invalid user password' }]

    /**
     * If request is json then return a json response
     */
    if (isJSON) {
      response.status(status).send(errorMessages)
      return
    }

    /**
     * If auth scheme is session, then flash the data
     * back to the form
     */
    if (auth.scheme === 'session') {
      session.withErrors(errorMessages).flashExcept([auth.passwordField])
      await session.commit()
      response.redirect('back')
      return
    }

    /**
     * If using basic auth, then prompt user with a native
     * browser dialog
     */
    if (auth.scheme === 'basic') {
      response.header('WWW-Authenticate', 'Basic realm="example"')
      response.status(status).send('Access denied')
      return
    }

    /**
     * Fallback to json response
     */
    response.status(status).send(errorMessages)
  }
}

/**
 * This exception is raised when basic auth credentials are
 * missing.
 *
 * @class InvalidBasicAuthException
 */
class InvalidBasicAuthException extends GE.LogicalException {
  /**
   * The basic auth header/credentials are missing
   *
   * @method invoke
   *
   * @return {Object}
   */
  static invoke () {
    return new this('Cannot parse or read Basic auth header', 401, 'E_MISSING_AUTH_HEADER')
  }

  /**
   * Handle the exception itself
   *
   * @method handle
   *
   * @param  {Number} options.status
   * @param  {Object} options.response
   * @param  {Object} options.request
   *
   * @return {void}
   */
  handle ({ status }, { request, response }) {
    const isJSON = request.accepts(['html', 'json']) === 'json'

    if (!isJSON) {
      response.header('WWW-Authenticate', 'Basic realm="example"')
      response.status(status).send('Access denied')
      return
    }

    const error = [{ field: null, message: 'Basic auth header is missing' }]
    response.status(status).send(error)
  }
}

/**
 * This exception is raised when user session is invalid
 *
 * @class InvalidSessionException
 * @constructor
 */
class InvalidSessionException extends GE.LogicalException {
  static invoke () {
    return new this('Invalid session', 401, 'E_INVALID_SESSION')
  }
}

/**
 * This exception is raised when jwt token is invalid or
 * unable to find user for JWT token.
 *
 * @class InvalidJwtToken
 */
class InvalidJwtToken extends GE.LogicalException {
  static invoke (message) {
    return new this(message || 'The Jwt token is invalid', 401, 'E_INVALID_JWT_TOKEN')
  }
}

/**
 * This exception is raised when jwt refresh token is
 * invalid.
 *
 * @class InvalidRefreshToken
 */
class InvalidRefreshToken extends GE.LogicalException {
  static invoke (refreshToken) {
    return new this(`Invalid refresh token ${refreshToken}`, 401, 'E_INVALID_JWT_REFRESH_TOKEN')
  }
}

/**
 * This exception is raised when jwt token is expired
 *
 * @class ExpiredJwtToken
 */
class ExpiredJwtToken extends GE.LogicalException {
  static invoke () {
    return new this('The jwt token has been expired. Generate a new one to continue', 401, 'E_JWT_TOKEN_EXPIRED')
  }
}

/**
 * This exception is raised when API token is invalid
 *
 * @constructor InvalidApiToken
 */
class InvalidApiToken extends GE.LogicalException {
  static invoke () {
    return new this('The api token is missing or invalid', 401, 'E_INVALID_API_TOKEN')
  }
}

module.exports = {
  UserNotFoundException,
  PasswordMisMatchException,
  InvalidJwtToken,
  InvalidRefreshToken,
  ExpiredJwtToken,
  InvalidBasicAuthException,
  InvalidApiToken,
  InvalidSessionException
}
