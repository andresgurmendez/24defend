const STORAGE_KEY = '24defend_api_key'

// sessionStorage (not localStorage): the key is cleared when the tab closes
// instead of persisting indefinitely on a shared machine.
export function getStoredApiKey(): string | null {
  return sessionStorage.getItem(STORAGE_KEY)
}

export function setStoredApiKey(key: string): void {
  sessionStorage.setItem(STORAGE_KEY, key)
}

export function clearStoredApiKey(): void {
  sessionStorage.removeItem(STORAGE_KEY)
}
