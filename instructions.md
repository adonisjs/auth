## Register provider

Once installed the authentication provider, make sure to register the provider inside `start/app.js` file in order to make use of it.

```js
const providers = [
  '@adonisjs/auth/providers/AuthProvider'
]
```

## Register global middleware

Next you need to do is register couple of middleware to ensure everything works as expected.

Middleware are defined inside `start/kernel.js` file. Make sure to define the middleware after `Adonis/Middleware/Session`, since authentication relies on sessions unless you are using JWT etc.

Note: Make sure you have setup sessions middleware ( if using session scheme )

```js
const globalMiddleware = [
  'Adonis/Middleware/Session', // after this
  'Adonis/Middleware/AuthInit'
]
```

**For Websocket, register the middleware inside `start/wsKernel.js` file.**

## Register named middleware

The named middleware is used to authenticate selected routes by applying the middleware on them and is registered within the same `start/kernel.js` file.

```js
const namedMiddleware = {
  auth: 'Adonis/Middleware/Auth',
  guest: 'Adonis/Middleware/AllowGuestOnly'
}
```

Once done 🔒 you are ready to authenticate your routes.

```js
Route
  .get('/profile', 'UserController.profile')
  .middleware('auth')
```
**For Websocket, register the middleware inside `start/wsKernel.js` file.**

Also you can instruct the middleware to use a different `authenticator`

```js
Route
  .get('/profile', 'UserController.profile')
  .middleware('auth:basic')
```

## Testing

The testing client is used to login users when writing tests. Make sure to register the trait before using the `loginVia` method.

```js
trait('Auth/Client')
```

If using sessions, make sure the `Auth/Client` trait comes before the `Session/Client`.

