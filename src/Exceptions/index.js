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
class PasswordMisMatchException extends NE.LogicalException {}
class InvalidLoginException extends NE.LogicalException {}
class TokeNotFoundException extends NE.LogicalException {}
class InvalidTokenException extends NE.LogicalException {}

module.exports = { PasswordMisMatchException, InvalidArgumentException: NE.InvalidArgumentException, InvalidLoginException, InvalidTokenException, TokeNotFoundException }
