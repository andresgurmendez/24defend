import type { ReactElement } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { LoginPage } from '@/pages/LoginPage'
import { DashboardPage } from '@/pages/DashboardPage'
import { getStoredApiKey } from '@/lib/auth'

// Login used to be purely cosmetic — handleSubmit navigated to "/"
// regardless of credentials, and this route had no guard at all, so
// anyone hitting the CloudFront URL saw the dashboard directly by
// navigating to "/". Now gated on a verified API key (see LoginPage /
// lib/auth.ts); this guard is the client-side half — the real boundary
// is /telemetry/stats requiring X-API-Key server-side.
function RequireAuth({ children }: { children: ReactElement }) {
  return getStoredApiKey() ? children : <Navigate to="/login" replace />
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
