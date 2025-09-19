export * from './auth'
export * from './guard'

import { inject } from "vue";
import { OAuthClient, type OIDConfiguration } from "./auth";
import { AUTH_INJECTION_KEY } from "./constants";

export function createAuth(
  clientOptions: OIDConfiguration,
) {
  return new OAuthClient(clientOptions);
}

/**
 * Returns the registered AuthClient instance using Vue's `inject`.
 * @returns An instance of AuthClient
 */
export function useAuth(): OAuthClient {
  return inject(AUTH_INJECTION_KEY) as OAuthClient;
}

