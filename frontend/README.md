# 24Defend — Panel interno (frontend)

Dashboard interno de métricas para el equipo de 24Defend. Fase actual: **solo visual**.
No hay autenticación real ni backend de métricas dedicado todavía — el login es una
pantalla estática y el dashboard consume el único endpoint agregado que existe hoy,
`GET /telemetry/stats`.

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

El servidor de Vite corre en `http://localhost:5173` y proxea `/api/*` hacia
`https://api.24defend.com` (ver `vite.config.ts`) para evitar problemas de CORS
sin necesidad de tocar el backend, que hoy no tiene `CORSMiddleware` configurado.

## Variables de entorno

Ver `.env.example`. Por defecto `VITE_API_BASE_URL=/api` usa el proxy de desarrollo.

## Qué falta (fuera de alcance de esta fase, ver el plan)

- Login real contra un backend de autenticación (`POST /internal/auth/login`).
- Tabla `24defend-events` con clave compuesta para corregir el bug de sobreescritura
  de telemetría (hoy cada evento del mismo tipo/día pisa al anterior).
- Endpoints `/internal/metrics/*` con filtros de fecha reales y conteo de
  dispositivos activos.

## Deploy a AWS

La infraestructura (`DashboardBucket` + `DashboardCdn` en `infra/stack.py`) y el CORS
del backend (`backend/app/config.py` → `dashboard_cors_origins`) ya están en el código.
Falta correr el deploy real. Pasos:

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
`dashboard.24defend.com`, y sube automáticamente `frontend/dist` (vía `BucketDeployment`,
con invalidación de CloudFront incluida).

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
