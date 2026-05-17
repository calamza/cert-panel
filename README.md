# Cert-Panel (Let's Encrypt + Cloudflare/AWS)

Proyecto para gestionar certificados Let's Encrypt con desafío DNS:
- Cloudflare (API Token)
- AWS Route53 (credenciales IAM)

Permite:
- Ingreso con Google OAuth
- Control de acceso por usuarios permitidos
- Roles: `admin` (full) y `readonly` (solo descarga)
- Cargar dominios y proveedor DNS desde un panel web
- Emitir certificados para `dominio.com`, `dominio.com.ar`, `dominio.ar`, etc.
- Incluir wildcard (`*.dominio...`) con un checkbox
- Monitorear vencimientos y renovar automáticamente
- Descargar certificados (`fullchain`, `privkey`, `chain`, `cert`) en ZIP

## Requisitos

- Docker + Docker Compose
- DNS gestionado en Cloudflare o Route53

## Levantar

1. Copiar variables de entorno:

```bash
cp .env.example .env
```

2. Completar en `.env`:
- `INITIAL_ALLOWED_USER_EMAIL` (usuario inicial autorizado)
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `PUBLIC_BASE_URL` (ej: `https://certpanel.confiber.com.ar`)

3. Ejecutar:

```bash
docker compose up -d --build
```

Panel: http://localhost:8080

## Login y permisos

- El acceso se hace con Google (`/login`)
- Solo pueden entrar emails que estén en la tabla `users`
- En el primer arranque se crea automáticamente el usuario indicado en `INITIAL_ALLOWED_USER_EMAIL`
- Un `admin` puede:
   - Agregar dominios
   - Emitir/renovar certificados
   - Administrar usuarios
- Un `readonly` solo puede:
   - Ver listado
   - Descargar ZIP de certificados

## Flujo operativo

1. Iniciar sesión con Google
2. Si sos admin, ir a "Agregar dominio"
3. Cargar:
   - dominio base (sin `*.`)
   - email de contacto
   - proveedor (`cloudflare` o `aws`)
   - credenciales según proveedor
   - opción wildcard si corresponde
4. Guardar y luego hacer click en "Emitir"
5. Descargar con "Descargar ZIP"

## Permisos mínimos sugeridos

### Cloudflare
Token con permisos:
- `Zone:DNS:Edit`
- `Zone:Zone:Read`
Sobre la zona del dominio a emitir.

### AWS IAM para Route53
Permisos sobre Route53 para crear/borrar/listar records TXT del challenge.

## Notas importantes

- Let's Encrypt tiene rate limits. Evitá reintentos masivos.
- `credentials/` y `data/` contienen secretos y estado local.
- En producción conviene poner este panel detrás de autenticación (reverse proxy con Basic Auth, SSO, etc.).

## Estructura de certificados

Se guardan en el volumen `certs/letsencrypt`, estructura estándar de certbot:
- `live/<cert_name>/fullchain.pem`
- `live/<cert_name>/privkey.pem`
- `live/<cert_name>/chain.pem`
- `live/<cert_name>/cert.pem`

## Variables de entorno

- `FLASK_SECRET_KEY`: clave de sesión
- `SESSION_COOKIE_SECURE`: `true` si corrés detrás de HTTPS
- `PUBLIC_BASE_URL`: URL pública usada para construir el callback OAuth
- `AUTO_RENEW_DAYS_BEFORE`: umbral de renovación automática (default 30)
- `AUTO_RENEW_INTERVAL_HOURS`: frecuencia del monitor (default 12)
- `INITIAL_ALLOWED_USER_EMAIL`: email inicial con permiso
- `INITIAL_ALLOWED_USER_ROLE`: `admin` o `readonly`
- `GOOGLE_CLIENT_ID`: OAuth client id de Google
- `GOOGLE_CLIENT_SECRET`: OAuth client secret de Google
- `GOOGLE_DISCOVERY_URL`: endpoint OpenID (default Google)

## OAuth redirect_uri_mismatch

Si Google devuelve `Error 400: redirect_uri_mismatch`, verificá que:
- `PUBLIC_BASE_URL` en `.env` coincida con el dominio público real
- En Google OAuth Client estén cargados:
   - Origen autorizado: `https://certpanel.confiber.com.ar`
   - Redirect URI: `https://certpanel.confiber.com.ar/auth/google/callback`

## Runtime productivo

La imagen Docker corre con Gunicorn (WSGI), no con el servidor de desarrollo de Flask.

## Próximos pasos recomendados

- Encriptar credenciales en DB (KMS/Vault)
- Agregar endpoint de salud y alertas (mail/slack)
