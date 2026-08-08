# 24Defend — Panel interno (frontend)

Dashboard interno de métricas para el equipo de 24Defend. Consume `GET /telemetry/stats`
y los endpoints públicos `/daily-blacklist` / `/daily-false-positives`.

## Autenticación

El login es real, contra el backend: `POST /telemetry/login` valida una **dashboard key**
de solo lectura (distinta de la `api_key` de admin que protege `/admin/*`) y, si es
correcta, el backend responde con un cookie `HttpOnly` de sesión (`Set-Cookie`, 12h de
duración). El frontend nunca ve ni guarda la credencial — el cookie es inaccesible desde
JS, así que un XSS en la SPA no puede robarla ni escalar a `/admin/*`.

`RequireAuth` (`src/App.tsx`) no confía en ningún estado local: en cada mount hace un
probe real a `GET /telemetry/session` para confirmar que el cookie sigue siendo válido
antes de renderizar el dashboard. `Salir` llama a `POST /telemetry/logout`, que borra el
cookie server-side.

Ver `backend/app/auth.py` (`require_dashboard_session`) y
`backend/app/routes/telemetry.py` (`/login`, `/logout`, `/session`, `/stats`).

## Stack

- Vite + React 18 + TypeScript
- TailwindCSS v4 + componentes propios estilo shadcn/ui (`src/components/ui`)
- Recharts para gráficos
- React Router

## Desarrollo local

```bash
npm install
npm run dev
```

El servidor de Vite corre en `http://localhost:5173`. No hay proxy de desarrollo: el
backend tiene `CORSMiddleware` configurado (`allow_credentials=True`, origins explícitos)
y la SPA llama directo a `VITE_API_BASE_URL`.

`.env.development` apunta por defecto a un backend local (`http://localhost:8080`) —
**nunca a prod**, para que la dashboard key que tipeás en dev no viaje por el backend
compartido. Corré el backend local:

```bash
cd backend && .venv/bin/uvicorn app.main:app --reload --port 8080
```

y agregá `http://localhost:5173` a `DEFEND_DASHBOARD_CORS_ORIGINS` en su entorno. Si
preferís no correr un backend local, sobreescribí `VITE_API_BASE_URL` en un
`.env.development.local` (gitignoreado) apuntando a un backend de dev compartido — nunca
a prod.

## Variables de entorno

Ver `.env.example`, `.env.development`, `.env.production`. `VITE_API_BASE_URL` es
obligatoria en dev — si falta, `src/lib/api.ts` tira un error explícito en vez de caer
silenciosamente a prod.

## Qué falta (ver `issues.md`)

- `cdk synth`/`deploy` lee `frontend/dist` en synth time — requiere `npm run build`
  manual antes; no hay paso automatizado todavía.
- `DashboardPage.load()` no tiene `AbortController` — race rara de sobre-escritura en
  refrescos manuales muy seguidos.
- `DashboardBucket` con `RemovalPolicy.DESTROY` sin `auto_delete_objects=True` (mismo
  problema pre-existente que `WwwBucket`).

## Deploy a AWS

La infraestructura (`DashboardBucket` + `DashboardCdn` en `infra/stack.py`), el CORS del
backend (`backend/app/config.py` → `dashboard_cors_origins`) y los secrets de
`dashboard_api_key` / `session_secret` ya están en el código. Pasos:

```bash
# 1. Build de producción (usa .env.production → apunta a https://api.24defend.com)
cd frontend
npm install
npm run build   # genera frontend/dist, que el CDK sube a S3

# 2. Cargar credenciales AWS y desplegar infraestructura
cd ../infra
source ../aws.sh
export JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1
export DEFEND_ENV=dev
pip3 install -q -r requirements.txt
cdk deploy defend-dev --require-approval never
```

`cdk deploy` crea el bucket S3, la distribución de CloudFront, el certificado ACM para
`dashboard.24defend.com`, el WAF rate-limit sobre el ALB del backend, y sube
automáticamente `frontend/dist` (vía `BucketDeployment`, con invalidación de CloudFront
incluida).

Después del primer deploy, hay que setear manualmente en Secrets Manager (igual que
`api_key`, ver CLAUDE.md → "Secrets"):

- `defend-dev/dashboard-api-key` — la dashboard key de solo lectura (distinta de
  `defend-dev/api-key`).
- `defend-dev/session-secret` — clave HMAC larga y random para firmar el cookie de
  sesión.

### Validación del certificado ACM (manual, una sola vez)

El DNS de `24defend.com` vive en GoDaddy (no Route53), así que la validación DNS del
certificado no es automática. Después del primer `cdk deploy`:

1. `aws acm list-certificates --region us-east-1` para encontrar el certificado de
   `dashboard.24defend.com` (queda en estado `PENDING_VALIDATION`).
2. `aws acm describe-certificate --certificate-arn <arn> --region us-east-1` para obtener
   el `ResourceRecord` (nombre y valor CNAME) que pide.
3. Agregar ese CNAME en GoDaddy. La validación tarda unos minutos una vez propagado el DNS.
4. Una vez validado el certificado, agregar el CNAME final apuntando el dashboard a
   CloudFront (mismo patrón que `api`/`cdn` en `.claude/skills/deploy.md`):

   | Type  | Name      | Value                                    |
   |-------|-----------|-------------------------------------------|
   | CNAME | dashboard | `<DashboardUrl output de cdk deploy>`     |

### Redeploys posteriores (solo contenido, sin cambios de infra)

```bash
cd frontend && npm run build
cd ../infra && cdk deploy defend-dev --require-approval never
```

(o `aws s3 sync frontend/dist s3://24defend-dashboard-dev --delete` + invalidación manual
de CloudFront, si se prefiere no pasar por CDK para cambios de solo contenido — mismo
patrón que `/deploy-www`).
