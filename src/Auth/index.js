'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const _ = require('lodash')
const AuthManager = require('./Manager')
const GE = require('@adonisjs/generic-exceptions')

/**
 * The proxy handler to proxy all authenticator
 * instance methods
 *
 * @type {Object}
 */
const proxyHandler = {
  get (target, name) {
    /**
     * if node is inspecting then stick to target properties
     */
    if (typeof (name) === 'symbol' || name === 'inspect') {
      return target[name]
    }

    /**
     * if value exists on target, return that
     */
    if (typeof (target[name]) !== 'undefined') {
      return target[name]
    }

    /**
     * Fallback to authenticator instance
     */
    if (typeof (target.authenticatorInstance[name]) === 'function') {
      return target.authenticatorInstance[name].bind(target.authenticatorInstance)
    }

    return target.authenticatorInstance[name]
  }
}

/**
 * The auth class is used to authenticate users using a pre-defined
 * authenticator in the auth config.
 *
 * This class proxies all the methods of the `scheme` that is currently
 * in use. So do make sure to refer the schemes API.
 *
 * @class Auth
 * @module Lucid
 * @constructor
 *
 * @param {Context} ctx     Request context
 * @param {Config}  Config  Reference to config provider
 */
class Auth {
  constructor (ctx, Config) {
    this._ctx = ctx
    this.Config = Config
    this._authenticatorsPool = {}
    this.authenticatorInstance = this.authenticator()
    return new Proxy(this, proxyHandler)
  }

  /**
   * Newup an authenticator instance for a given name. The names must be a
   * reference for the `keys` inside the `config/auth.js` file.
   *
   * @method authenticator
   *
   * @param  {String}      name
   *
   * @return {Scheme}
   */
  authenticator (name) {
    name = name || this.Config.get('auth.authenticator')

    /**
     * if authenticator instance exists, please return it
     */
    if (this._authenticatorsPool[name]) {
      return this._authenticatorsPool[name]
    }

    const config = this.Config.get(`auth.${name}`)

    /**
     * Throws exception when config is defined or missing
     */
    if (!config || !_.size(config)) {
      throw GE.RuntimeException.missingConfig(`auth.${name}`, 'config/auth.js')
    }

    /**
     * Throws exception if any of the required config keys are
     * missing
     */
    if (!_.every([config.serializer, config.scheme])) {
      throw GE.RuntimeException.incompleteConfig(['serializer', 'scheme'], 'config/auth.js', `auth.${name}`)
    }

    /**
     * Configuring serializer
     */
    const serializerInstance = AuthManager.getSerializer(config.serializer)
    serializerInstance.setConfig(config)

    /**
     * Configuring scheme
     */
    const schemeInstance = AuthManager.getScheme(config.scheme)
    schemeInstance.setOptions(config, serializerInstance)
    schemeInstance.setCtx(this._ctx)

    /**
     * Storing scheme instance inside pool
     */
    this._authenticatorsPool[name] = schemeInstance
    return schemeInstance
  }
}

module.exports = Auth
