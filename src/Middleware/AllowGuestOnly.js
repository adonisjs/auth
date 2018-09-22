'use strict'

const GE = require('@adonisjs/generic-exceptions')

class AllowGuestOnly {
  async handle ({ auth, request }, next) {
    try {
      await auth.check()

      throw new GE.HttpException(`Only guest user can access the route ${request.method()} ${request.url()}`, 403, 'E_GUEST_ONLY')
    } catch (e) {}

    await next()

  }
}

module.exports = AllowGuestOnly
