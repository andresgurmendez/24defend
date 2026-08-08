import { useEffect, useState, type ReactElement } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { LoginPage } from '@/pages/LoginPage'
import { DashboardPage } from '@/pages/DashboardPage'
import { checkDashboardSession } from '@/lib/api'

// Auth is a short-lived HttpOnly session cookie the browser attaches
// automatically — the SPA can neither read nor cache it. RequireAuth
// re-verifies with a live probe (GET /telemetry/session) on every mount
// instead of trusting any client-side flag, so a rotated/expired key can't
// render a flash of stale authenticated UI (PR #14 review finding #6).
function RequireAuth({ children }: { children: ReactElement }) {
  const [status, setStatus] = useState<'checking' | 'authed' | 'unauthed'>('checking')

  useEffect(() => {
    let cancelled = false
    checkDashboardSession().then((ok) => {
      if (!cancelled) setStatus(ok ? 'authed' : 'unauthed')
    })
    return () => {
      cancelled = true
    }
  }, [])

  if (status === 'checking') return null
  if (status === 'unauthed') return <Navigate to="/login" replace />
  return children
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <RequireAuth>
            <DashboardPage />
          </RequireAuth>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
