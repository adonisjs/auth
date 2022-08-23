/*
 * @adonisjs/auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { join } from 'path'
import * as sinkStatic from '@adonisjs/sink'
import { string } from '@poppinss/utils/build/helpers'
import { ApplicationContract } from '@ioc:Adonis/Core/Application'

type InstructionsState = {
  modelName?: string
  modelReference?: string
  modelNamespace?: string

  usersTableName: string
  usersSchemaName: string

  tokensTableName: string
  tokensSchemaName: string

  provider: 'lucid' | 'database'
  tokensProvider: 'database' | 'redis'
  guards: ('web' | 'api' | 'basic')[]

  hasGuard: {
    web: boolean
    api: boolean
    basic: boolean
  }
}

// const USER_MIGRATION_TIME_PREFIX = '1587988332388'
// const TOKENS_MIGRATION_TIME_PREFIX = '1592489784670'

/**
 * Base path to contract stub partials
 */
const CONTRACTS_PARTIALS_BASE = './contract/partials'

/**
 * Base path to config stub partials
 */
const CONFIG_PARTIALS_BASE = './config/partials'

/**
 * Prompt choices for the provider selection
 */
const PROVIDER_PROMPT_CHOICES = [
  {
    name: 'lucid' as const,
    message: 'Lucid',
    hint: ' (Uses Data Models)',
  },
  {
    name: 'database' as const,
    message: 'Database',
    hint: ' (Uses Database QueryBuilder)',
  },
]

/**
 * Prompt choices for the guard selection
 */
const GUARD_PROMPT_CHOICES = [
  {
    name: 'web' as const,
    message: 'Web',
    hint: ' (Uses sessions for managing auth state)',
  },
  {
    name: 'api' as const,
    message: 'API tokens',
    hint: ' (Uses database backed opaque tokens)',
  },
  {
    name: 'basic' as const,
    message: 'Basic Auth',
    hint: ' (Uses HTTP Basic auth for authenticating requests)',
  },
]

/**
 * Prompt choices for the tokens provider selection
 */
const TOKENS_PROVIDER_PROMPT_CHOICES = [
  {
    name: 'database' as const,
    message: 'Database',
    hint: ' (Uses SQL table for storing API tokens)',
  },
  {
    name: 'redis' as const,
    message: 'Redis',
    hint: ' (Uses Redis for storing API tokens)',
  },
]

/**
 * Returns absolute path to the stub relative from the templates
 * directory
 */
function getStub(...relativePaths: string[]) {
  return join(__dirname, 'templates', ...relativePaths)
}

/**
 * Creates the model file
 */
function makeModel(
  projectRoot: string,
  app: ApplicationContract,
  sink: typeof sinkStatic,
  state: InstructionsState
) {
  const modelsDirectory = app.resolveNamespaceDirectory('models') || 'app/Models'
  const modelPath = join(modelsDirectory, `${state.modelName}.ts`)

  const template = new sink.files.MustacheFile(projectRoot, modelPath, getStub('model.txt'))
  if (template.exists()) {
    sink.logger.action('create').skipped(`${modelPath} file already exists`)
    return
  }

  template.apply(state).commit()
  sink.logger.action('create').succeeded(modelPath)
}

/**
 * Create the migration file
 */
function makeUsersMigration(
  projectRoot: string,
  app: ApplicationContract,
  sink: typeof sinkStatic,
  state: InstructionsState
) {
  const migrationsDirectory = app.directoriesMap.get('migrations') || 'database'
  const migrationPath = join(migrationsDirectory, `${Date.now()}_${state.usersTableName}.ts`)

  const template = new sink.files.MustacheFile(
    projectRoot,
    migrationPath,
    getStub('migrations/auth.txt')
  )
  if (template.exists()) {
    sink.logger.action('create').skipped(`${migrationPath} file already exists`)
    return
  }

  template.apply(state).commit()
  sink.logger.action('create').succeeded(migrationPath)
}

/**
 * Create the migration file
 */
function makeTokensMigration(
  projectRoot: string,
  app: ApplicationContract,
  sink: typeof sinkStatic,
  state: InstructionsState
) {
  const migrationsDirectory = app.directoriesMap.get('migrations') || 'database'
  const migrationPath = join(migrationsDirectory, `${Date.now()}_${state.tokensTableName}.ts`)

  const template = new sink.files.MustacheFile(
    projectRoot,
    migrationPath,
    getStub('migrations/api_tokens.txt')
  )
  if (template.exists()) {
    sink.logger.action('create').skipped(`${migrationPath} file already exists`)
    return
  }

  template.apply(state).commit()
  sink.logger.action('create').succeeded(migrationPath)
}

/**
 * Create the middleware(s)
 */
function makeMiddleware(
  projectRoot: string,
  app: ApplicationContract,
  sink: typeof sinkStatic,
  state: InstructionsState
) {
  const middlewareDirectory = app.resolveNamespaceDirectory('middleware') || 'app/Middleware'

  /**
   * Auth middleware
   */
  const authPath = join(middlewareDirectory, 'Auth.ts')
  const authTemplate = new sink.files.MustacheFile(
    projectRoot,
    authPath,
    getStub('middleware/Auth.txt')
  )
  if (authTemplate.exists()) {
    sink.logger.action('create').skipped(`${authPath} file already exists`)
  } else {
    authTemplate.apply(state).commit()
    sink.logger.action('create').succeeded(authPath)
  }

  /**
   * Silent auth middleware
   */
  const silentAuthPath = join(middlewareDirectory, 'SilentAuth.ts')
  const silentAuthTemplate = new sink.files.MustacheFile(
    projectRoot,
    silentAuthPath,
    getStub('middleware/SilentAuth.txt')
  )
  if (silentAuthTemplate.exists()) {
    sink.logger.action('create').skipped(`${silentAuthPath} file already exists`)
  } else {
    silentAuthTemplate.apply(state).commit()
    sink.logger.action('create').succeeded(silentAuthPath)
  }
}

/**
 * Creates the contract file
 */
function makeContract(
  projectRoot: string,
  app: ApplicationContract,
  sink: typeof sinkStatic,
  state: InstructionsState
) {
  const contractsDirectory = app.directoriesMap.get('contracts') || 'contracts'
  const contractPath = join(contractsDirectory, 'auth.ts')

  const template = new sink.files.MustacheFile(
    projectRoot,
    contractPath,
    getStub('contract/auth.txt')
  )
  template.overwrite = true

  const partials: any = {
    provider: getStub(CONTRACTS_PARTIALS_BASE, `user-provider-${state.provider}.txt`),
  }

  state.guards.forEach((guard) => {
    partials[`${guard}_guard`] = getStub(CONTRACTS_PARTIALS_BASE, `${guard}-guard.txt`)
  })

  template.apply(state).partials(partials).commit()
  sink.logger.action('create').succeeded(contractPath)
}

/**
 * Makes the auth config file
 */
function makeConfig(
  projectRoot: string,
  app: ApplicationContract,
  sink: typeof sinkStatic,
  state: InstructionsState
) {
  const configDirectory = app.directoriesMap.get('config') || 'config'
  const configPath = join(configDirectory, 'auth.ts')

  const template = new sink.files.MustacheFile(projectRoot, configPath, getStub('config/auth.txt'))
  template.overwrite = true

  const partials: any = {
    provider: getStub(CONFIG_PARTIALS_BASE, `user-provider-${state.provider}.txt`),
    token_provider: getStub(CONFIG_PARTIALS_BASE, `tokens-provider-${state.tokensProvider}.txt`),
  }

  state.guards.forEach((guard) => {
    partials[`${guard}_guard`] = getStub(CONFIG_PARTIALS_BASE, `${guard}-guard.txt`)
  })

  template.apply(state).partials(partials).commit()
  sink.logger.action('create').succeeded(configPath)
}

/**
 * Prompts user to select the provider
 */
async function getProvider(sink: typeof sinkStatic) {
  return sink.getPrompt().choice('Select provider for finding users', PROVIDER_PROMPT_CHOICES, {
    validate(choice) {
      return choice && choice.length ? true : 'Select the provider for finding users'
    },
  })
}

/**
 * Prompts user to select the tokens provider
 */
async function getTokensProvider(sink: typeof sinkStatic) {
  return sink
    .getPrompt()
    .choice('Select the provider for storing API tokens', TOKENS_PROVIDER_PROMPT_CHOICES, {
      validate(choice) {
        return choice && choice.length ? true : 'Select the provider for storing API tokens'
      },
    })
}

/**
 * Prompts user to select one or more guards
 */
async function getGuard(sink: typeof sinkStatic) {
  return sink
    .getPrompt()
    .multiple(
      'Select which guard you need for authentication (select using space)',
      GUARD_PROMPT_CHOICES,
      {
        validate(choices) {
          return choices && choices.length
            ? true
            : 'Select one or more guards for authenticating users'
        },
      }
    )
}

/**
 * Prompts user for the model name
 */
async function getModelName(sink: typeof sinkStatic): Promise<string> {
  return sink.getPrompt().ask('Enter model name to be used for authentication', {
    validate(value) {
      return !!value.trim().length
    },
  })
}

/**
 * Prompts user for the table name
 */
async function getTableName(sink: typeof sinkStatic): Promise<string> {
  return sink.getPrompt().ask('Enter the database table name to look up users', {
    validate(value) {
      return !!value.trim().length
    },
  })
}

/**
 * Prompts user for the table name
 */
async function getMigrationConsent(sink: typeof sinkStatic, tableName: string): Promise<boolean> {
  return sink
    .getPrompt()
    .confirm(`Create migration for the ${sink.logger.colors.underline(tableName)} table?`)
}

/**
 * Instructions to be executed when setting up the package.
 */
export default async function instructions(
  projectRoot: string,
  app: ApplicationContract,
  sink: typeof sinkStatic
) {
  const state: InstructionsState = {
    usersTableName: '',
    tokensTableName: 'api_tokens',
    tokensSchemaName: 'ApiTokens',
    usersSchemaName: '',
    provider: 'lucid',
    tokensProvider: 'database',
    guards: [],
    hasGuard: {
      web: false,
      api: false,
      basic: false,
    },
  }

  state.provider = await getProvider(sink)
  state.guards = await getGuard(sink)

  /**
   * Need booleans for mustache templates
   */
  state.guards.forEach((guard) => (state.hasGuard[guard] = true))

  /**
   * Make model when provider is lucid otherwise prompt for the database
   * table name
   */
  if (state.provider === 'lucid') {
    const modelName = await getModelName(sink)
    state.modelName = string.pascalCase(string.singularize(modelName.replace(/(\.ts|\.js)$/, '')))
    state.usersTableName = string.pluralize(string.snakeCase(state.modelName))
    state.modelReference = string.camelCase(string.singularize(state.modelName))
    state.modelNamespace = `${app.namespacesMap.get('models') || 'App/Models'}/${state.modelName}`
  } else {
    state.usersTableName = await getTableName(sink)
  }

  const usersMigrationConsent = await getMigrationConsent(sink, state.usersTableName)
  let tokensMigrationConsent = false

  /**
   * Only ask for the consent when using the api guard
   */
  if (state.hasGuard.api) {
    state.tokensProvider = await getTokensProvider(sink)
    if (state.tokensProvider === 'database') {
      tokensMigrationConsent = await getMigrationConsent(sink, state.tokensTableName)
    }
  }

  /**
   * Pascal case
   */
  const camelCaseSchemaName = string.camelCase(`${state.usersTableName}_schema`)
  state.usersSchemaName = `${camelCaseSchemaName
    .charAt(0)
    .toUpperCase()}${camelCaseSchemaName.slice(1)}`

  /**
   * Make model when prompted for it
   */
  if (state.modelName) {
    makeModel(projectRoot, app, sink, state)
  }

  /**
   * Make users migration file
   */
  if (usersMigrationConsent) {
    makeUsersMigration(projectRoot, app, sink, state)
  }

  /**
   * Make tokens migration file
   */
  if (tokensMigrationConsent) {
    makeTokensMigration(projectRoot, app, sink, state)
  }

  /**
   * Make contract file
   */
  makeContract(projectRoot, app, sink, state)

  /**
   * Make config file
   */
  makeConfig(projectRoot, app, sink, state)

  /**
   * Make middleware
   */
  makeMiddleware(projectRoot, app, sink, state)
}
