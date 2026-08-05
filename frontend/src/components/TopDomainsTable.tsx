import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Badge } from '@/components/ui/badge'
import type { DomainClassification, TopDomain } from '@/lib/types'

interface TopDomainsTableProps {
  domains: TopDomain[]
  classifications: Record<string, DomainClassification>
  loading?: boolean
}

const CLASSIFICATION_META: Record<
  DomainClassification,
  { label: string; variant: 'danger' | 'success' | 'neutral' }
> = {
  confirmed: { label: 'Confirmado phishing', variant: 'danger' },
  false_positive: { label: 'Falso positivo', variant: 'success' },
  unclassified: { label: 'Sin clasificar', variant: 'neutral' },
}

export function TopDomainsTable({ domains, classifications, loading }: TopDomainsTableProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Dominios más detectados</CardTitle>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="flex flex-col gap-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-9 w-full" />
            ))}
          </div>
        ) : domains.length === 0 ? (
          <p className="py-6 text-center text-sm text-[var(--color-text-faint)]">
            Sin dominios registrados todavía.
          </p>
        ) : (
          <>
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="text-xs text-[var(--color-text-faint)]">
                  <th className="pb-2 font-medium">#</th>
                  <th className="pb-2 font-medium">Dominio</th>
                  <th className="pb-2 font-medium">Eventos</th>
                  <th className="pb-2 pr-1 text-right font-medium">Clasificación</th>
                </tr>
              </thead>
              <tbody>
                {domains.map((d, i) => {
                  const classification = classifications[d.domain] ?? 'unclassified'
                  const meta = CLASSIFICATION_META[classification]
                  return (
                    <tr key={d.domain} className="border-t border-[var(--color-border)]">
                      <td className="py-2.5 text-[var(--color-text-faint)]">{i + 1}</td>
                      <td className="py-2.5 font-mono text-[13px] text-[var(--color-text)]">
                        {d.domain}
                      </td>
                      <td className="py-2.5 text-[var(--color-text-muted)]">{d.count}</td>
                      <td className="py-2.5 pr-1 text-right">
                        <Badge variant={meta.variant}>{meta.label}</Badge>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            <p className="mt-3 text-xs text-[var(--color-text-faint)]">
              La clasificación cruza estos dominios con /daily-blacklist y /daily-false-positives
              (ventana de 48h). "Sin clasificar" no implica que sea seguro ni malicioso — solo que
              no fue confirmado por el agente en las últimas 48h.
            </p>
          </>
        )}
      </CardContent>
    </Card>
  )
}
