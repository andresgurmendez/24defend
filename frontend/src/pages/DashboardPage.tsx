import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertTriangle, LogOut, RefreshCw, ShieldBan, ShieldCheck, Smartphone } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { KpiCard } from '@/components/KpiCard'
import { EventsChart } from '@/components/EventsChart'
import { TopDomainsTable } from '@/components/TopDomainsTable'
import { SessionStatsPanel } from '@/components/SessionStatsPanel'
import { VpnBehaviorPanel } from '@/components/VpnBehaviorPanel'
import { ApiError, fetchDailyBlacklist, fetchDailyFalsePositives, fetchTelemetryStats } from '@/lib/api'
import { clearStoredApiKey } from '@/lib/auth'
import type { DomainClassification, TelemetryStats } from '@/lib/types'

export function DashboardPage() {
  const navigate = useNavigate()
  const [stats, setStats] = useState<TelemetryStats | null>(null)
  const [classifications, setClassifications] = useState<Record<string, DomainClassification>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  async function load() {
    setLoading(true)
    setError(null)
    try {
      const data = await fetchTelemetryStats()
      setStats(data)

      // Best-effort enrichment: these two only cover the last 48h, so most
      // historical top_domains will come back "unclassified" — that's
      // expected, not a bug (see TopDomainsTable footnote).
      const [blacklistResult, fpResult] = await Promise.allSettled([
        fetchDailyBlacklist(),
        fetchDailyFalsePositives(),
      ])

      const map: Record<string, DomainClassification> = {}
      if (blacklistResult.status === 'fulfilled') {
        for (const domain of blacklistResult.value.domains) map[domain] = 'confirmed'
      }
      if (fpResult.status === 'fulfilled') {
        for (const domain of fpResult.value.domains) map[domain] = 'false_positive'
      }
      setClassifications(map)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        // fetchTelemetryStats already cleared the stored key on 401.
        navigate('/login', { replace: true })
        return
      }
      setError(err instanceof ApiError ? err.message : 'Ocurrió un error inesperado.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  return (
    <div className="mx-auto flex min-h-screen max-w-6xl flex-col gap-6 px-4 py-6 sm:px-6 lg:px-8">
      <Header
        onRefresh={load}
        onLogout={() => {
          clearStoredApiKey()
          navigate('/login')
        }}
        refreshing={loading}
      />

      {error ? (
        <ErrorState message={error} onRetry={load} />
      ) : (
        <>
          <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
            <KpiCard
              label="Bloqueos totales"
              value={stats?.by_event_type.blocked ?? 0}
              icon={<ShieldBan className="h-4 w-4 text-[var(--color-danger)]" />}
              tone="danger"
              loading={loading}
            />
            <KpiCard
              label="Alertas totales"
              value={stats?.by_event_type.warned ?? 0}
              icon={<AlertTriangle className="h-4 w-4 text-[var(--color-warning)]" />}
              tone="warning"
              loading={loading}
            />
            <KpiCard
              label="Eventos totales"
              value={stats?.total_events ?? 0}
              icon={<ShieldCheck className="h-4 w-4 text-[var(--color-accent)]" />}
              loading={loading}
            />
            <KpiCard
              label="Reportes de sesión"
              value={stats?.total_session_reports ?? 0}
              icon={<ShieldCheck className="h-4 w-4 text-[var(--color-success)]" />}
              tone="success"
              loading={loading}
            />
            <KpiCard
              label="Dispositivos activos"
              value={null}
              icon={<Smartphone className="h-4 w-4 text-[var(--color-text-faint)]" />}
              loading={loading}
              pending
              pendingNote="Requiere conteo por device_id (fase futura)"
            />
          </section>

          <section className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <EventsChart byLayer={stats?.by_layer ?? {}} loading={loading} />
            <TopDomainsTable
              domains={stats?.top_domains ?? []}
              classifications={classifications}
              loading={loading}
            />
          </section>

          <section className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <SessionStatsPanel
              stats={stats?.aggregate_session_stats ?? null}
              eventTotals={{
                blocked: stats?.by_event_type.blocked ?? 0,
                warned: stats?.by_event_type.warned ?? 0,
              }}
              loading={loading}
            />
            <VpnBehaviorPanel />
          </section>

          <p className="pb-4 text-center text-xs text-[var(--color-text-faint)]">
            Datos agregados desde GET /telemetry/stats. Sin filtro por fecha ni conteo real de
            dispositivos activos todavía — se incorpora al conectar /internal/metrics/*.
          </p>
        </>
      )}
    </div>
  )
}

function Header({
  onRefresh,
  onLogout,
  refreshing,
}: {
  onRefresh: () => void
  onLogout: () => void
  refreshing: boolean
}) {
  return (
    <header className="flex flex-wrap items-center justify-between gap-3 pt-2">
      <div>
        <h1 className="text-xl font-semibold text-[var(--color-text)]">Panel interno</h1>
        <p className="text-sm text-[var(--color-text-muted)]">
          Métricas de detección de phishing — 24Defend
        </p>
      </div>
      <div className="flex items-center gap-2">
        <Button variant="outline" size="sm" onClick={onRefresh} disabled={refreshing}>
          <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} />
          Actualizar
        </Button>
        <Button variant="ghost" size="sm" onClick={onLogout}>
          <LogOut className="h-3.5 w-3.5" />
          Salir
        </Button>
      </div>
    </header>
  )
}

function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] py-16 text-center">
      <AlertTriangle className="h-8 w-8 text-[var(--color-danger)]" />
      <p className="text-sm text-[var(--color-text)]">{message}</p>
      <Button variant="outline" size="sm" onClick={onRetry}>
        Reintentar
      </Button>
    </div>
  )
}
