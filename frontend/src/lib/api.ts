import type { DailyDomainsResponse, TelemetryStats } from './types'

// Local dev must point at an explicit API — never silently fall back to
// prod, where a dashboard key typed during dev would round-trip through
// the shared prod backend (PR #14 review finding #5). See
// frontend/.env.development / .env.production.
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL
if (import.meta.env.DEV && !API_BASE_URL) {
  throw new Error(
    'VITE_API_BASE_URL is not set. Local dev must point at an explicit API ' +
      '(see frontend/.env.development) instead of silently falling back to prod.',
  )
}

export class ApiError extends Error {
  status?: number

  constructor(message: string, status?: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

// credentials: 'include' on every call — the dashboard session lives in an
// HttpOnly cookie (see backend/app/auth.py), not in anything the frontend
// can read or send explicitly (PR #14 review findings #1/#2).
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, { credentials: 'include', ...init })
  } catch {
    throw new ApiError('No se pudo conectar con la API de 24Defend.')
  }

  if (!response.ok) {
    throw new ApiError(`La API respondió con un error (${response.status}).`, response.status)
  }

  return (await response.json()) as T
}

export async function fetchTelemetryStats(): Promise<TelemetryStats> {
  return request<TelemetryStats>('/telemetry/stats')
}

// Cheap probe the RequireAuth route guard calls on every mount to verify
// the session cookie is still valid before rendering the dashboard, rather
// than trusting client-side state (PR #14 review finding #6).
export async function checkDashboardSession(): Promise<boolean> {
  try {
    await request('/telemetry/session')
    return true
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) return false
    throw err
  }
}

// Exchanges the dashboard key for a session; on success the backend sets
// an HttpOnly cookie via Set-Cookie — the frontend never sees or stores
// the credential itself.
export async function loginToDashboard(key: string): Promise<boolean> {
  try {
    await request('/telemetry/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dashboard_key: key }),
    })
    return true
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) return false
    throw err
  }
}

export async function logoutFromDashboard(): Promise<void> {
  try {
    await request('/telemetry/logout', { method: 'POST' })
  } catch {
    // Best-effort — the cookie is short-lived regardless, and the caller
    // navigates away either way.
  }
}

// Both cover only cache entries checked in the last 48h (see
// backend/app/routes/admin.py lines 29-67) — used to enrich top_domains
// with a best-effort classification, not a full historical join.
export function fetchDailyBlacklist(): Promise<DailyDomainsResponse> {
  return request<DailyDomainsResponse>('/daily-blacklist')
}

export function fetchDailyFalsePositives(): Promise<DailyDomainsResponse> {
  return request<DailyDomainsResponse>('/daily-false-positives')
}
