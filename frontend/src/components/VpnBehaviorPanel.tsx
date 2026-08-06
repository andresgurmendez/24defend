import { ShieldOff } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

const PLANNED_METRICS = [
  'Encendidas vs. apagadas por día',
  'Motivo de apagado (batería, rompe otras apps, falso positivo, manual, etc.)',
  'Apagado desde la app vs. desde Configuración de iOS',
  'Duración promedio de sesión con protección activa',
  'Tasa de reactivación después de un apagado',
]

/**
 * Empty-state placeholder: hoy no existe telemetría de encendido/apagado de VPN
 * ni del motivo (ver ios/TwentyFourDefendPacketTunnel/PacketTunnelProvider.swift,
 * que captura NEProviderStopReason pero solo lo loguea local, nunca al backend).
 * No se inventan datos — ver plan para la instrumentación futura (iOS + backend).
 */
export function VpnBehaviorPanel() {
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle>Comportamiento de VPN</CardTitle>
        <Badge variant="neutral">Pendiente de instrumentación</Badge>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col items-center gap-3 py-6 text-center">
          <ShieldOff className="h-8 w-8 text-[var(--color-text-faint)]" />
          <p className="max-w-md text-sm text-[var(--color-text-muted)]">
            Todavía no se envía al backend ningún evento de encendido/apagado de VPN ni el
            motivo. La app detecta el estado local y hasta el motivo del sistema
            (<code className="text-xs">NEProviderStopReason</code>), pero solo queda en el log
            de diagnóstico del teléfono — nunca viaja a este dashboard.
          </p>
          <div className="mt-1 flex w-full max-w-md flex-col gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-hover)] p-3 text-left">
            <p className="text-xs font-medium text-[var(--color-text)]">
              Una vez instrumentado (iOS + backend), este panel va a mostrar:
            </p>
            <ul className="list-disc space-y-0.5 pl-4 text-xs text-[var(--color-text-faint)]">
              {PLANNED_METRICS.map((metric) => (
                <li key={metric}>{metric}</li>
              ))}
            </ul>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
