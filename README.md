# Let's Encrypt Panel (Cloudflare + AWS Route53)

Proyecto para gestionar certificados Let's Encrypt con desafío DNS:
- Cloudflare (API Token)
- AWS Route53 (credenciales IAM)

Permite:
- Cargar dominios y proveedor DNS desde un panel web
- Emitir certificados para `dominio.com`, `dominio.com.ar`, `dominio.ar`, etc.
- Incluir wildcard (`*.dominio...`) con un checkbox
- Monitorear vencimientos y renovar automáticamente
- Descargar certificados (`fullchain`, `privkey`, `chain`, `cert`) en ZIP

## Requisitos

- Docker + Docker Compose
- DNS gestionado en Cloudflare o Route53

## Levantar

```bash
docker compose up -d --build
```

Panel: http://localhost:8080

## Flujo

1. Ir a "Agregar dominio"
2. Cargar:
   - dominio base (sin `*.`)
   - email de contacto
   - proveedor (`cloudflare` o `aws`)
   - credenciales según proveedor
   - opción wildcard si corresponde
3. Guardar y luego hacer click en "Emitir"
4. Descargar con "Descargar ZIP"

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
- `AUTO_RENEW_DAYS_BEFORE`: umbral de renovación automática (default 30)
- `AUTO_RENEW_INTERVAL_HOURS`: frecuencia del monitor (default 12)

## Próximos pasos recomendados

- Agregar login de usuarios (Flask-Login o reverse proxy)
- Encriptar credenciales en DB (KMS/Vault)
- Agregar endpoint de salud y alertas (mail/slack)
