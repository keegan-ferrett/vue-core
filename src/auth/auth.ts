import { Tokens } from './tokens'
import { AUTH_INJECTION_KEY, AUTH_TOKEN } from './constants'
import { ref, type App, type Ref } from 'vue'
import axios from 'axios'
import { jwtDecode } from 'jwt-decode'
import { type RouteLocationNormalizedGeneric } from 'vue-router'
import { bufferToBase64UrlEncoded, getRandomBytes, sha256 } from './utils'

// export interface OpenIDConfiguration {
//   authorization_endpoint: string
//   token_endpoint?: string
//   issuer?: string
//   // code_challenge_methods_supported?: string[];
//   [key: string]: unknown
// }

// export interface AuthorizationRequestOptions {
//   /** Redirect URL registered with the OAuth provider */
//   redirectUri: string
//   scope?: string | string[]
//   responseType?: string
//   state?: string
//   codeVerifier?: string
//   codeChallengeMethod?: 'S256' | 'plain'
//   extraParams?: Record<string, string>
// }

export interface TokenRequestOptions {
  /** Authorization code received from the authorization server */
  code: string
}

export interface ClientCredentialsRequestOptions {
  /** Scopes to request */
  scope?: string | string[]
  /** Additional parameters to include in the token request */
  extraParams?: Record<string, string>
}

/**
 * Parameters for obtaining a new token via refresh_token grant.
 */
export interface RefreshTokenRequestOptions {
  /** The refresh token issued by the authorization server */
  refreshToken: string
  /** Scopes to request (if different from original scopes) */
  scope?: string | string[]
  /** Additional parameters to include in the token request */
  extraParams?: Record<string, string>
}

export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in?: number
  refresh_token?: string
  id_token?: string
  [key: string]: unknown
}

/**
 * New Types for v2
 */

export interface OIDConfiguration {
  authorization_endpoint: string
  token_endpoint: string
  redirect_url: string
  client_id: string
  client_secret?: string
  scopes: string | string[]
  extraParams?: Record<string, string>;
}



/**
 * OAuth2 client supporting the PKCE Authorization Code flow.
 */
export class OAuthClient {
  public isAuthenticated: Ref<boolean> = ref(false);
  public isLoading: Ref<boolean> = ref(false);

  /**
   * @param config OpenID provider configuration
   * @param clientId OAuth2 client identifier (used for all grant requests)
   * @param clientSecret OAuth2 client secret (optional, if required by provider)
   */
  constructor(
    private config: OIDConfiguration,
    private tokens: Tokens = new Tokens()
  ) {
    this.tokens.readTokens()

    if (this.tokens.accessToken !== undefined) {
      this.isAuthenticated.value = true
    }
  }

  /**
   * @param app Vue app the plugin is being attached to
   */
  install(app: App) {
    app.config.globalProperties[AUTH_TOKEN] = this;
    app.provide(AUTH_INJECTION_KEY, this as OAuthClient);
  }

  private static base64url(buffer: any | string): string {
    return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }

  /**
   * Generates a high-entropy cryptographic random string for PKCE code_verifier.
   */
  private static generateCodeVerifier(): string {
    return OAuthClient.base64url(getRandomBytes(48))
  }

  /**
   * Generates a PKCE code_challenge from the given code_verifier using SHA-256.
   * @param codeVerifier the code_verifier to hash
   */
  public static async generateCodeChallenge(codeVerifier: string): Promise<string> {
    const hash = await sha256(codeVerifier)
    const b64Hash = bufferToBase64UrlEncoded(hash)
    // return OAuthClient.base64url(hash)
    return b64Hash
  }

  /**
   * Generates a random string, useful for state.
   */
  public static generateState(): string {
    // return OAuthClient.base64url(getRandomBytes(16))
    return '1'
  }

  /**
   * Builds the authorization URL for the OAuth2 Authorization Code Flow with PKCE.
   *
   * @param opts Options for the authorization request
   * @returns An object containing the URL to redirect the user to, the codeVerifier, and state.
   */
  public async createAuthorizationRequest(): Promise<{ url: string; codeVerifier: string; state: string }> {
    const { scopes, client_id, redirect_url, } = this.config
    const state = OAuthClient.generateState()
    const codeVerifier = OAuthClient.generateCodeVerifier()

    const method = 'S256'
    // const methods = this.config.code_challenge_methods_supported || ['plain'];
    // const method: 'S256' | 'plain' = codeChallengeMethod
    //   ? codeChallengeMethod
    //   : methods.includes('S256')
    //     ? 'S256'
    //     : 'plain';
    //
    // const codeChallenge =
    //   method === 'S256' ? await OAuthClient.generateCodeChallenge(codeVerifier) : codeVerifier;
    const codeChallenge = await OAuthClient.generateCodeChallenge(codeVerifier)
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: client_id,
      redirect_uri: redirect_url,
      ...(scopes ? { scope: Array.isArray(scopes) ? scopes.join(' ') : scopes } : {}),
      state,
      code_challenge: codeChallenge,
      code_challenge_method: method,
      ...this.config.extraParams,
    })


    return {
      url: `${this.config.authorization_endpoint}?${params.toString()}`,
      codeVerifier,
      state,
    }
  }

  public async loginWithRedirect(routeState?: RouteLocationNormalizedGeneric) {
    const authRequest = await this.createAuthorizationRequest()

    window.sessionStorage.setItem('auth:code-verifier', authRequest.codeVerifier)
    window.sessionStorage.setItem('auth:state', authRequest.state)

    if (routeState !== undefined) {
      window.sessionStorage.setItem('auth:app-target-path', routeState.fullPath)
    }

    window.location.replace(authRequest.url)
  }

  /**
   * Exchanges an authorization code for tokens (access, refresh, id) at the token endpoint.
   * @param opts parameters for the token request
   */
  public async exchangeCodeForToken(opts: TokenRequestOptions): Promise<TokenResponse> {
    const codeVerifier = window.sessionStorage.getItem('auth:code-verifier')
    if (!codeVerifier) {
      throw new Error('Code verifier not found')
    }

    const state = window.sessionStorage.getItem('auth:state')
    if (!state) {
      throw new Error('State not found')
    }

    const { client_id, client_secret, redirect_url, extraParams, } = this.config
    const { code } = opts

    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirect_url,
      client_id: client_id,
      code_verifier: codeVerifier,
      ...extraParams,
    })

    if (client_secret) {
      params.set('client_secret', client_secret)
    }

    const response = await axios.post<TokenResponse>(
      this.config.token_endpoint,
      params.toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    )

    const data = response.data
    this.tokens = new Tokens()
    this.tokens.setTokens(data.access_token, data.refresh_token)
    this.isAuthenticated.value = true

    return response.data
  }

  /**
   * Exchanges a refresh token for new tokens at the token endpoint.
   * @param opts parameters for the refresh token request
   */
  // public async exchangeRefreshToken(opts: RefreshTokenRequestOptions): Promise<TokenResponse> {
  //   if (!this.config.token_endpoint) {
  //     throw new Error('token_endpoint is not defined in OpenID configuration')
  //   }
  //   const { refreshToken, scope, extraParams = {} } = opts
  //   const params = new URLSearchParams({
  //     grant_type: 'refresh_token',
  //     refresh_token: refreshToken,
  //     client_id: this.config.client_id,
  //     ...(this.config.client_secret ? { client_secret: this.config.client_secret } : {}),
  //     ...(scope ? { scope: Array.isArray(scope) ? scope.join(' ') : scope } : {}),
  //     ...extraParams,
  //   })
  //   const response = await axios.post<TokenResponse>(
  //     this.config.token_endpoint,
  //     params.toString(),
  //     { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
  //   )
  //   return response.data
  // }

  public async checkSession(route: RouteLocationNormalizedGeneric): Promise<string | undefined> {
    const urlParams = route.query;
    const code = urlParams['code']

    if (code !== undefined && typeof code == 'string') {
      console.log('Checking session & have code');
      this.isLoading.value = true;

      const response = await this.exchangeCodeForToken({
        code: code
      })

      this.isLoading.value = false
      const target = sessionStorage.getItem('auth:app-target-path') ?? undefined

      sessionStorage.removeItem('auth:app-target-path')

      return target
    }

    return undefined
  }

  get accessToken(): string | undefined {
    return this.tokens.accessToken
  }

  get accessTokenValid(): boolean {
    if (this.accessToken === undefined) return false
    const decoded = jwtDecode(this.accessToken)

    if (decoded.exp !== undefined) {
      const now = new Date()
      const expires = decoded.exp * 1000
      if (expires < now.getTime()) return false
    }
    return true
  }
}
