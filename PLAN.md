# auth-kit — Plan

Módulo de **autenticación reutilizable y configurable** para apps Node + React
de la suite Ubik. Sigue el patrón de `community-kit`: el host inyecta su modelo
de usuario y su almacén, y monta el router tras (o como) su middleware.

## Principios

- **Sin modelo de usuario propio.** auth-kit no posee la tabla de usuarios: el
  host aporta un puente (`users`). Puede apuntar a la BD de una app o a una BD
  común compartida por varias apps (base para el SSO del launcher).
- **Todo configurable.** Hashing de contraseñas, formato de tokens, estrategias
  de autenticación y almacén de estado se eligen en `createAuth({...})`.
- **Cero dependencias obligatorias** más allá de `express`: scrypt y JWT nativo
  con `node:crypto`. `bcryptjs` solo si se elige esa estrategia.
- **Backend (CommonJS) + React (ESM/JSX)**, con estilos propios (`--ak-*`) e
  i18n `es`/`en`, igual que `community-kit`.

## Estructura

```
auth-kit/
  server/                 → auth-kit/server   (CommonJS)
    index.js              createAuth(options)
    middleware.js         requireAuth / optionalAuth / requireRole
    tokens.js             JWT + refresh opaco
    jwt.js                HS256/384/512 con node:crypto
    passwords.js          scrypt (por defecto) | bcryptjs | custom
    store.js              memoria | node:sqlite (tabla ak_kv)
    limiter.js            rate limit en memoria, sin deps
    errors.js / util.js
    strategies/
      password.js         register / login / refresh / logout / me / cambio de contraseña
      magic-link.js       enlace mágico por email (sin contraseña)
      api-key.js          claves de API por usuario
  react/                  → auth-kit/react    (ESM + JSX)
    index.jsx             AuthProvider, useAuth, componentes
    createApi.js          cliente REST con refresh automático
    context.jsx / i18n.js / styles.css
    components/           LoginForm, RegisterForm, MagicLinkForm, ProtectedRoute
  test/                   node:test + express sobre puerto efímero
```

## Contrato del host: `users`

Obligatorio:

| Método                             | Devuelve / hace                    |
| ---------------------------------- | ---------------------------------- |
| `findByLogin(id)` / `findByEmail(id)` | usuario o `null` (identificador de login) |
| `findById(id)`                     | usuario o `null`                   |

Opcional (habilitan más funciones):

| Método                          | Habilita                                  |
| ------------------------------- | ----------------------------------------- |
| `createUser(patch)`             | `POST /register` (`patch` incluye `passwordHash`) |
| `setPasswordHash(id, hash)`     | cambio y reset de contraseña              |
| `updateUser(id, patch)`         | extensiones del host                      |
| `serialize(user)`               | forma pública del usuario (p. ej. sin hash) |

Config relacionada: `passwordField` (por defecto `passwordHash`), `statusField`
(`status`), `activeStatus` (`active`), `defaultRole` (`user`).

## Configuración de `createAuth`

| Opción          | Valores                                                        | Por defecto           |
| --------------- | ------------------------------------------------------------- | --------------------- |
| `users`         | puente obligatorio (ver arriba)                                | —                     |
| `passwords`     | `'scrypt'` \| `'bcryptjs'` \| `{ hash, verify }`               | `'scrypt'`            |
| `tokens`        | `{ secret, ttl, refreshTtl, refresh, algorithm, issuer }`      | `ttl: '1h'`           |
| `strategies`    | `['password','magic-link','api-key', ...]`                     | `['password']`        |
| `identifierField` | campo de login (`'email'`, `'username'`, …)                  | `'email'`             |
| `store` / `db`  | adaptador propio o handle `node:sqlite`                        | memoria               |
| `serialize`     | `(user) => publicUser`                                        | quita el hash         |
| `messages`      | mapa `code -> texto` para errores `auth/<code>`                | inglés                |
| `onMagicLink`   | `({ email, token, url, user }) => void` (envío de email)       | —                     |
| `magicLinkUrl`  | `(token) => url` o plantilla con `{token}`                     | `/magic-link?token=`  |
| `rateLimit`     | `true` \| `false` \| `{ windowMs, max }`                       | `true`                |
| `onEvent`       | `(type, payload) => void` (login, register, …)                 | —                     |

## Endpoints (relativos al mount; p. ej. `/api/auth`)

Password: `POST /register`, `POST /login`, `POST /refresh`, `POST /logout`,
`GET /me`, `POST /password/change`, `POST /password/forgot`,
`POST /password/reset`.
Magic link: `POST /magic-link`, `POST /magic-link/verify`.
API keys: `POST /api-keys`, `GET /api-keys`, `DELETE /api-keys/:id`.

`requireAuth` acepta el token en `Authorization: Bearer`, en `?token=` (para
SSE/EventSource) o una API key en `x-api-key`. Recarga el usuario en cada
petición para que cambios de rol/estado surtan efecto de inmediato.

## Compatibilidad con community-kit

`community-kit` espera un middleware cuyo `getUser` lea `req.user`. `requireAuth`
de auth-kit lo deja preparado, así que se monta directamente:

```js
app.use('/api/community', auth.requireAuth, community.router);
```

## Roadmap

- [ ] Fase 1 — Núcleo: contrato `users`, scrypt, JWT, estrategia password,
      middleware, rate limit, tests.
- [ ] Fase 2 — Estrategias magic-link y api-key + almacén SQLite.
- [ ] Fase 3 — Frontend React: provider, api con refresh, formularios, ruta
      protegida, i18n y estilos.
- [ ] Fase 4 (futuro) — Estrategias OAuth genérica, TOTP/2FA, WebAuthn y
      verificación de email; SSO central para el launcher (mismo `secret` y BD
      común).
