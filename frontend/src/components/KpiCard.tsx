import type { ReactNode } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

interface KpiCardProps {
  label: string
  value: number | null
  icon?: ReactNode
  tone?: 'default' | 'danger' | 'warning' | 'success'
  loading?: boolean
  /** No backing data source yet — shows "—" plus a "Pendiente" badge and note instead of a real number. */
  pending?: boolean
  pendingNote?: string
}

const toneClasses: Record<NonNullable<KpiCardProps['tone']>, string> = {
  default: 'text-[var(--color-text)]',
  danger: 'text-[var(--color-danger)]',
  warning: 'text-[var(--color-warning)]',
  success: 'text-[var(--color-success)]',
}

export function KpiCard({
  label,
  value,
  icon,
  tone = 'default',
  loading,
  pending,
  pendingNote,
}: KpiCardProps) {
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between pb-2">
        <CardTitle>{label}</CardTitle>
        {icon}
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-9 w-24" />
        ) : pending ? (
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center gap-2">
              <p className="text-3xl font-semibold tabular-nums text-[var(--color-text-faint)]">
                —
              </p>
              <Badge variant="neutral">Pendiente</Badge>
            </div>
            {pendingNote && (
              <p className="text-xs text-[var(--color-text-faint)]">{pendingNote}</p>
            )}
          </div>
        ) : (
          <p className={cn('text-3xl font-semibold tabular-nums', toneClasses[tone])}>
            {value === null ? '—' : value.toLocaleString('es-UY')}
          </p>
        )}
      </CardContent>
    </Card>
  )
}
