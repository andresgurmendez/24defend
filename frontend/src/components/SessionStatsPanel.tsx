import { AlertTriangle } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import type { AggregateSessionStats } from '@/lib/types'

interface SessionStatsPanelProps {
  stats: AggregateSessionStats | null
  eventTotals: { blocked: number; warned: number }
  loading?: boolean
}

function pct(numerator: number, denominator: number): string {
  if (!denominator) return '—'
  return `${((numerator / denominator) * 100).toFixed(1)}%`
}

export function SessionStatsPanel({ stats, eventTotals, loading }: SessionStatsPanelProps) {
  const rows = stats
    ? [
        {
          label: 'Consultas DNS verificadas',
          value: stats.total_queries.toLocaleString('es-UY'),
          detail: 'Total de consultas interceptadas por el túnel',
        },
        {
          label: 'Tasa de acierto en caché',
          value: pct(stats.cache_hits, stats.total_queries),
          detail: `${stats.cache_hits.toLocaleString('es-UY')} de ${stats.total_queries.toLocaleString('es-UY')} — la mayoría no llega a re-clasificarse`,
        },
        {
          label: 'Infraestructura permitida',
          value: pct(stats.infrastructure_allowed, stats.total_queries),
          detail: 'CDNs y ad-tech descartados antes de la heurística',
        },
        {
          label: 'Bloom hits (blacklist)',
          value: stats.bloom_blacklist_hits.toLocaleString('es-UY'),
          detail: pct(stats.bloom_blacklist_hits, stats.total_queries) + ' de las consultas',
        },
        {
          label: 'Bloom hits (whitelist)',
          value: stats.bloom_whitelist_hits.toLocaleString('es-UY'),
          detail: pct(stats.bloom_whitelist_hits, stats.total_queries) + ' de las consultas',
        },
        {
          label: 'Alertas silenciosas de ML',
          value: stats.ml_warns.toLocaleString('es-UY'),
          detail: 'Se envían al agente en segundo plano, sin avisar al usuario',
        },
        {
          label: 'Alertas de reglas de marca',
          value: stats.brand_rule_warns.toLocaleString('es-UY'),
          detail: 'Motor de reglas casi no dispara frente al total',
        },
        {
          label: 'Llamadas a la API (agente)',
          value: stats.api_calls.toLocaleString('es-UY'),
          detail: '≈ ML warns, como es esperable',
        },
      ]
    : []

  // Sessions report `blocks`/`warns` as a single overwritten counter per day
  // (known limitation, see plan), while by_event_type counts individual
  // events. When they diverge a lot, the session-level numbers are stale.
  const sessionBlocks = stats?.blocks ?? 0
  const sessionWarns = stats?.warns ?? 0
  const hasDiscrepancy =
    !!stats && (eventTotals.blocked !== sessionBlocks || eventTotals.warned !== sessionWarns)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Salud del sistema (agregado)</CardTitle>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="grid grid-cols-2 gap-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : !stats ? (
          <p className="py-6 text-center text-sm text-[var(--color-text-faint)]">
            Sin estadísticas de sesión todavía.
          </p>
        ) : (
          <>
            <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
              {rows.map((row) => (
                <div
                  key={row.label}
                  className="flex flex-col gap-0.5 border-b border-[var(--color-border)] pb-2"
                >
                  <div className="flex items-baseline justify-between gap-2">
                    <dt className="text-sm text-[var(--color-text-muted)]">{row.label}</dt>
                    <dd className="font-mono text-sm text-[var(--color-text)]">{row.value}</dd>
                  </div>
                  <p className="text-xs text-[var(--color-text-faint)]">{row.detail}</p>
                </div>
              ))}
            </dl>

            {hasDiscrepancy && (
              <div className="mt-4 flex items-start gap-2 rounded-lg border border-[var(--color-warning-soft)] bg-[var(--color-warning-soft)] p-3 text-xs text-[var(--color-warning)]">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <span>
                  Discrepancia: los eventos individuales cuentan {eventTotals.blocked} bloqueos /{' '}
                  {eventTotals.warned} alertas, pero el contador de sesión reporta {sessionBlocks} /{' '}
                  {sessionWarns}. Es una limitación conocida del modelo de datos actual (los
                  contadores de sesión se pisan entre sí por día), no un error de esta pantalla.
                </span>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}
