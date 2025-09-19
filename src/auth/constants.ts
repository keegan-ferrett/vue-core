import type { InjectionKey } from 'vue'
// import type { Auth0VueClient } from './interfaces';

/**
 * @ignore
 */
export const AUTH_TOKEN = 'app$auth'

/**
 * Injection token used to `provide` the `Auth0VueClient` instance. Can be used to pass to `inject()`
 *
 * ```js
 * inject(AUTH0_INJECTION_KEY)
 * ```
 */
export const AUTH_INJECTION_KEY: InjectionKey<any> = Symbol(AUTH_TOKEN)

/**
  *
  */
export const AUTH_ACCESS_TOKEN_KEY: string = 'auth:access-token'
export const AUTH_REFRESH_TOKEN_KEY: string = 'auth:refresh-token'
