import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent } from '@/components/ui/card'

export function LoginPage() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [touched, setTouched] = useState(false)

  const isValid = username.trim().length > 0 && password.length > 0

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setTouched(true)
    if (!isValid) return

    // Fase visual: todavía no hay backend de autenticación. Cuando se
    // conecte POST /internal/auth/login, este handler llama a la API,
    // guarda el JWT y recién ahí navega.
    navigate('/')
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
              <label htmlFor="username" className="text-sm text-[var(--color-text-muted)]">
                Usuario
              </label>
              <Input
                id="username"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="nombre.apellido"
              />
              {touched && username.trim().length === 0 && (
                <p className="text-xs text-[var(--color-danger)]">Ingresá tu usuario.</p>
              )}
            </div>

            <div className="flex flex-col gap-1.5">
              <label htmlFor="password" className="text-sm text-[var(--color-text-muted)]">
                Contraseña
              </label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
              />
              {touched && password.length === 0 && (
                <p className="text-xs text-[var(--color-danger)]">Ingresá tu contraseña.</p>
              )}
            </div>

            <Button type="submit" className="mt-2 w-full">
              Ingresar
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
