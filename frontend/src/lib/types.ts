// Mirrors the response shape of GET /telemetry/stats
// (backend/app/routes/telemetry.py, lines 224-231).

export interface AggregateSessionStats {
  total_queries: number
  cache_hits: number
  bloom_whitelist_hits: number
  bloom_blacklist_hits: number
  infrastructure_allowed: number
  brand_rule_warns: number
  ml_warns: number
  api_calls: number
  blocks: number
  warns: number
}

export interface TopDomain {
  domain: string
  count: number
}

// Mirrors GET /daily-blacklist and GET /daily-false-positives
// (backend/app/routes/admin.py, lines 29-67). Both are public, unauthenticated,
// and only cover cache entries checked in the last 48h.
export interface DailyDomainsResponse {
  domains: string[]
  updated_at: string
}

export type DomainClassification = 'confirmed' | 'false_positive' | 'unclassified'

export interface TelemetryStats {
  total_events: number
  total_session_reports: number
  by_event_type: Record<string, number>
  by_layer: Record<string, number>
  top_domains: TopDomain[]
  aggregate_session_stats: AggregateSessionStats
}

export const DETECTION_LAYER_LABELS: Record<string, string> = {
  bloom_blacklist: 'Bloom blacklist',
  brand_rules: 'Reglas de marca',
  ml_classifier: 'Clasificador ML',
  agent: 'Agente IA',
  runtime_blacklist: 'Blacklist en sesión',
  investigation: 'Investigación',
  daily_blacklist: 'Blacklist diaria',
}

export const EVENT_TYPE_LABELS: Record<string, string> = {
  blocked: 'Bloqueados',
  warned: 'Alertas',
  false_positive_report: 'Reportes de falso positivo',
}
