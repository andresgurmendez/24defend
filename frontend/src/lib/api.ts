import type { DailyDomainsResponse, TelemetryStats } from './types'

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

async function getJson<T>(path: string): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}${path}`)
  } catch {
    throw new ApiError('No se pudo conectar con la API de 24Defend.')
  }

  if (!response.ok) {
    throw new ApiError(`La API respondió con un error (${response.status}).`, response.status)
  }

  return (await response.json()) as T
}

export function fetchTelemetryStats(): Promise<TelemetryStats> {
  return getJson<TelemetryStats>('/telemetry/stats')
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
