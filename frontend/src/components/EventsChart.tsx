import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { DETECTION_LAYER_LABELS } from '@/lib/types'

interface EventsChartProps {
  byLayer: Record<string, number>
  loading?: boolean
}

export function EventsChart({ byLayer, loading }: EventsChartProps) {
  const data = Object.entries(byLayer)
    .map(([layer, count]) => ({
      layer: DETECTION_LAYER_LABELS[layer] ?? layer,
      count,
    }))
    .sort((a, b) => b.count - a.count)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Detecciones por capa</CardTitle>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-64 w-full" />
        ) : data.length === 0 ? (
          <EmptyChart />
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" horizontal={false} />
              <XAxis type="number" stroke="var(--color-text-faint)" fontSize={12} allowDecimals={false} />
              <YAxis
                type="category"
                dataKey="layer"
                stroke="var(--color-text-faint)"
                fontSize={12}
                width={140}
              />
              <Tooltip
                cursor={{ fill: 'var(--color-surface-hover)' }}
                contentStyle={{
                  background: 'var(--color-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 8,
                  fontSize: 13,
                  color: 'var(--color-text)',
                }}
              />
              <Bar dataKey="count" fill="var(--color-accent)" radius={[0, 4, 4, 0]} name="Eventos" />
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  )
}

function EmptyChart() {
  return (
    <div className="flex h-64 items-center justify-center text-sm text-[var(--color-text-faint)]">
      Sin eventos registrados todavía.
    </div>
  )
}
