'use strict'

const GE = require('@adonisjs/generic-exceptions')

class AllowGuestOnly {
  async handle ({ auth, response }, next) {
    try {
      await auth.check()

      throw new GE.HttpException(`Only guest user can access the route ${ctx.request.method()} ${ctx.request.url()}`, 403, 'E_GUEST_ONLY')
    } catch (e) {}

    await next()

  }
}

module.exports = AllowGuestOnly
