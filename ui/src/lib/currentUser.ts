const DEFAULT_USER_ID = "admin@kagent.dev";
const USER_ID_KEY = "kagent_user_id";

export function getCurrentUserId(): string {
  if (typeof window === "undefined") return DEFAULT_USER_ID;
  return window.localStorage.getItem(USER_ID_KEY) || DEFAULT_USER_ID;
}
