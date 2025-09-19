import { unref } from "vue";
import { useAuth } from ".";
import type { RouteLocationNormalizedGeneric } from "vue-router";

export const authGuard = async (to: RouteLocationNormalizedGeneric, from: RouteLocationNormalizedGeneric) => {
  const client = useAuth();

  const redirect = await client.checkSession(to)
  if (redirect) {
    return redirect
  }

  if (unref(client.isAuthenticated) && client.accessTokenValid) {
    return true;
  }

  await client.loginWithRedirect(to)

  return false;
};
