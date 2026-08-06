import type { DailyDomainsResponse, TelemetryStats } from './types'
import { clearStoredApiKey, getStoredApiKey } from './auth'

// In dev this defaults to "/api", proxied by Vite (vite.config.ts) to
// https://api.24defend.com to avoid CORS without touching the backend.
// In production, point this at the real API origin once CORS is enabled
// there (see plan's "fases futuras").
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '/api'

export class ApiError extends Error {
  status?: number

  constructor(message: string, status?: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function getJson<T>(path: string, headers?: HeadersInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, { headers })
  } catch {
    throw new ApiError('No se pudo conectar con la API de 24Defend.')
  }

  if (!response.ok) {
    throw new ApiError(`La API respondió con un error (${response.status}).`, response.status)
  }

  return (await response.json()) as T
}

// GET /telemetry/stats requires X-API-Key (same key that gates /admin/*) —
// it's our full threat-intel feed and must not be scrapeable by anyone with
// the dashboard URL. Reads the key entered at login (see lib/auth.ts); a
// 401 means the stored key is invalid/expired, so we clear it and surface
// an ApiError the caller can route to /login on.
export async function fetchTelemetryStats(): Promise<TelemetryStats> {
  const key = getStoredApiKey()
  try {
    return await getJson<TelemetryStats>('/telemetry/stats', key ? { 'X-API-Key': key } : undefined)
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      clearStoredApiKey()
    }
    throw err
  }
}

// Used by the login form to validate the entered key against the real
// endpoint before storing it and navigating past the guard.
export async function verifyApiKey(key: string): Promise<boolean> {
  try {
    await getJson<TelemetryStats>('/telemetry/stats', { 'X-API-Key': key })
    return true
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) return false
    throw err
  }
}

// Both cover only cache entries checked in the last 48h (see
// backend/app/routes/admin.py lines 29-67) — used to enrich top_domains
// with a best-effort classification, not a full historical join.
export function fetchDailyBlacklist(): Promise<DailyDomainsResponse> {
  return getJson<DailyDomainsResponse>('/daily-blacklist')
}

export function fetchDailyFalsePositives(): Promise<DailyDomainsResponse> {
  return getJson<DailyDomainsResponse>('/daily-false-positives')
}
