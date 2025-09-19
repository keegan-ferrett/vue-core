import { AUTH_ACCESS_TOKEN_KEY, AUTH_REFRESH_TOKEN_KEY } from "./constants"

export class Tokens {
  constructor(
    private _accessToken?: string,
    private _refreshToken?: string,
  ) { }

  public get accessToken() {
    return this._accessToken
  }

  public get refreshToken() {
    return this._refreshToken
  }

  public setTokens(accessToken?: string | undefined, refreshToken?: string | undefined) {
    this._accessToken = accessToken
    this._refreshToken = refreshToken
    this.saveTokens()
  }

  public saveTokens() {
    if (this._accessToken) {
      window.sessionStorage.setItem(AUTH_ACCESS_TOKEN_KEY, this._accessToken)
    }

    if (this._refreshToken) {
      window.sessionStorage.setItem(AUTH_REFRESH_TOKEN_KEY, this._refreshToken)
    }
  }

  public readTokens() {
    this._accessToken = window.sessionStorage.getItem(AUTH_ACCESS_TOKEN_KEY) ?? undefined
    this._refreshToken = window.sessionStorage.getItem(AUTH_REFRESH_TOKEN_KEY) ?? undefined
  }
}
