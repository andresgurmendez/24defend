import type { ReactNode } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

interface KpiCardProps {
  label: string
  value: number | null
  icon?: ReactNode
  tone?: 'default' | 'danger' | 'warning' | 'success'
  loading?: boolean
}

const toneClasses: Record<NonNullable<KpiCardProps['tone']>, string> = {
  default: 'text-[var(--color-text)]',
  danger: 'text-[var(--color-danger)]',
  warning: 'text-[var(--color-warning)]',
  success: 'text-[var(--color-success)]',
}

export function KpiCard({ label, value, icon, tone = 'default', loading }: KpiCardProps) {
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between pb-2">
        <CardTitle>{label}</CardTitle>
        {icon}
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-9 w-24" />
        ) : (
          <p className={cn('text-3xl font-semibold tabular-nums', toneClasses[tone])}>
            {value === null ? '—' : value.toLocaleString('es-UY')}
          </p>
        )}
      </CardContent>
    </Card>
  )
}
