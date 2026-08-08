import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent } from '@/components/ui/card'
import { ApiError, loginToDashboard } from '@/lib/api'

export function LoginPage() {
  const navigate = useNavigate()
  const [apiKey, setApiKey] = useState('')
  const [touched, setTouched] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const isValid = apiKey.trim().length > 0

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setTouched(true)
    setError(null)
    if (!isValid || submitting) return

    setSubmitting(true)
    try {
      const ok = await loginToDashboard(apiKey.trim())
      if (!ok) {
        setError('Clave inválida.')
        return
      }
      navigate('/')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Ocurrió un error inesperado.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <Card className="w-full max-w-sm">
        <CardContent className="pt-8">
          <div className="mb-6 flex flex-col items-center gap-3 text-center">
            <div className="flex h-11 w-11 items-center justify-center rounded-full bg-[var(--color-accent-soft)]">
              <ShieldCheck className="h-5 w-5 text-[var(--color-accent)]" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-[var(--color-text)]">24Defend</h1>
              <p className="text-sm text-[var(--color-text-muted)]">Panel interno de métricas</p>
            </div>
          </div>

          <form className="flex flex-col gap-4" onSubmit={handleSubmit} noValidate>
            <div className="flex flex-col gap-1.5">
              <label htmlFor="apiKey" className="text-sm text-[var(--color-text-muted)]">
                Clave de acceso
              </label>
              <Input
                id="apiKey"
                type="password"
                autoComplete="current-password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="••••••••"
              />
              {touched && apiKey.trim().length === 0 && (
                <p className="text-xs text-[var(--color-danger)]">Ingresá la clave de acceso.</p>
              )}
              {error && <p className="text-xs text-[var(--color-danger)]">{error}</p>}
            </div>

            <Button type="submit" className="mt-2 w-full" disabled={submitting}>
              {submitting ? 'Verificando…' : 'Ingresar'}
            </Button>
          </form>

          <p className="mt-6 text-center text-xs text-[var(--color-text-faint)]">
            Acceso restringido al equipo de 24Defend / TONLER S.A.S.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
