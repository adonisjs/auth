'use strict'

const GE = require('@adonisjs/generic-exceptions')

class AllowGuestOnly {
  async handle ({ auth, request }, next) {
    let loggedIn = false

    try {
      await auth.check()
      loggedIn = true
    } catch (e) {}

    if (loggedIn) {
      throw new GE.HttpException(`Only guest user can access the route ${request.method()} ${request.url()}`, 403, 'E_GUEST_ONLY')
    }

    await next()
  }
}

module.exports = AllowGuestOnly
