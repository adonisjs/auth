/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// import { test } from '@japa/runner'
// import { fileURLToPath } from 'node:url'
// import { IgnitorFactory } from '@adonisjs/core/factories'
// import Configure from '@adonisjs/core/commands/configure'

// const BASE_URL = new URL('./tmp/', import.meta.url)

// test.group('Configure', (group) => {
//   group.each.setup(({ context }) => {
//     context.fs.baseUrl = BASE_URL
//     context.fs.basePath = fileURLToPath(BASE_URL)
//   })

//   test('create config file and register provider', async ({ fs, assert }) => {
//     const ignitor = new IgnitorFactory()
//       .withCoreProviders()
//       .withCoreConfig()
//       .create(BASE_URL, {
//         importer: (filePath) => {
//           if (filePath.startsWith('./') || filePath.startsWith('../')) {
//             return import(new URL(filePath, BASE_URL).href)
//           }

//           return import(filePath)
//         },
//       })

//     // await fs.create('.env', '')
//     // await fs.createJson('tsconfig.json', {})
//     // await fs.create('start/env.ts', `export default Env.create(new URL('./'), {})`)
//     // await fs.create('start/kernel.ts', `router.use([])`)
//     // await fs.create('adonisrc.ts', `export default defineConfig({}) {}`)

//     const app = ignitor.createApp('web')
//     await app.init()
//     await app.boot()

//     const ace = await app.container.make('ace')
//     const command = await ace.create(Configure, ['../../../index.js'])
//     await command.exec()

//     // await assert.fileExists('config/session.ts')
//     // await assert.fileExists('adonisrc.ts')
//     // await assert.fileContains('adonisrc.ts', '@adonisjs/session/session_provider')
//     // await assert.fileContains('config/session.ts', 'defineConfig')
//     // await assert.fileContains('.env', 'SESSION_DRIVER=cookie')
//     // await assert.fileContains(
//     //   'start/env.ts',
//     //   `SESSION_DRIVER: Env.schema.enum(['cookie', 'redis', 'file', 'memory'] as const)`
//     // )
//   }).timeout(60 * 1000)
// })
