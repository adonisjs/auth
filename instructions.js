'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const path = require('path')

async function makeConfigFile (cli) {
  const authenticator = await cli.command.choice('Which authenticator you would like to use', [
    {
      name: 'Session',
      value: 'session'
    },
    {
      name: 'Jwt',
      value: 'jwt'
    },
    {
      name: 'Basic Auth',
      value: 'basic'
    },
    {
      name: 'Api Tokens',
      value: 'api'
    },
    {
      name: 'Plain Token',
      value: 'token'
    }
  ])

  const serializer = await cli.command.choice('Which serializer you would like to use', [
    {
      name: 'Lucid',
      value: 'lucid'
    },
    {
      name: 'Database',
      value: 'database'
    }
  ])

  try {
    await cli.makeConfig('auth.js', path.join(__dirname, './templates/auth.mustache'), {
      authenticator,
      lucid: serializer === 'lucid',
      database: serializer === 'database'
    })

    cli.command.completed('create', 'config/auth.js')
  } catch (error) {
    console.log(error)
  }
}

async function copyUserModel (cli) {
  try {
    await cli.copy(
      path.join(__dirname, 'templates', 'User.js'),
      path.join(cli.appDir, 'Models/User.js')
    )
    cli.command.completed('create', 'Models/User.js')
  } catch (error) {
    console.log(error)
  }
}

async function copyTokenModel (cli) {
  try {
    await cli.copy(
      path.join(__dirname, 'templates', 'Token.js'),
      path.join(cli.appDir, 'Models/Token.js')
    )
    cli.command.completed('create', 'Models/Token.js')
  } catch (error) {
    console.log(error)
  }
}

async function copyUserHook (cli) {
  try {
    await cli.copy(
      path.join(__dirname, 'templates', 'UserHook.js'),
      path.join(cli.appDir, 'Models/Hooks/User.js')
    )
    cli.command.completed('create', 'Models/Hooks/User.js')
  } catch (error) {
    console.log(error)
  }
}

async function copyUserMigration (cli) {
  try {
    const migrationsFile = cli.helpers.migrationsPath(`${new Date().getTime()}_user.js`)
    await cli.copy(
      path.join(__dirname, 'templates', 'UserSchema.js'),
      path.join(migrationsFile)
    )
    cli.command.completed('create', migrationsFile.replace(cli.helpers.appRoot(), '').replace(path.sep, ''))
  } catch (error) {
    console.log(error)
  }
}

async function copyTokenMigration (cli) {
  try {
    const migrationsFile = cli.helpers.migrationsPath(`${new Date().getTime()}_token.js`)
    await cli.copy(
      path.join(__dirname, 'templates', 'TokenSchema.js'),
      path.join(migrationsFile)
    )
    cli.command.completed('create', migrationsFile.replace(cli.helpers.appRoot(), '').replace(path.sep, ''))
  } catch (error) {
    console.log(error)
  }
}

module.exports = async (cli) => {
  await makeConfigFile(cli)
  await copyUserModel(cli)
  await copyTokenModel(cli)
  await copyUserHook(cli)
  await copyUserMigration(cli)
  await copyTokenMigration(cli)
}
