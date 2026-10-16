# auth-kit

Módulo de **autenticación reutilizable y configurable** para apps Node + React.
Empaqueta el backend (router Express + estrategias + middleware) y el frontend
(provider + formularios) de forma **parametrizable**: el host inyecta su modelo
de usuario y su almacén, y elige hashing, tokens y estrategias.

- **Sin modelo de usuario propio**: se conecta mediante un puente (`users`).
  Puede apuntar a la BD de una app o a una **BD común** compartida por varias
  apps (base para el SSO del launcher).
- **Sin dependencias obligatorias** salvo Express: scrypt y JWT nativo con
  `node:crypto`. `bcryptjs` solo si lo eliges.
- **Estrategias pluggables**: password, magic-link y API keys.
- **Compatible con community-kit**: `requireAuth` deja `req.user` listo.

---

## 1. Instalación

```bash
npm install github:ubikee/auth-kit#v0.1.0
```

Requisitos: Node ≥ 22 para el backend (usa `node:crypto`; `node:sqlite` solo si
pasas `db`), React ≥ 18 para el frontend.

### Nota para Vite

`auth-kit/react` es ESM con `.jsx`. Añade a `vite.config.js`:

```js
export default defineConfig({
  optimizeDeps: { exclude: ['auth-kit', 'auth-kit/react'] },
});
```

---

## 2. Backend

### 2.1 Montaje

```js
const express = require('express');
const { createAuth } = require('auth-kit/server');

const app = express();
app.use(express.json());

const auth = createAuth({
  users,                       // (obligatorio) puente al modelo de usuario
  passwords: 'scrypt',         // 'scrypt' | 'bcryptjs' | { hash, verify }
  tokens: { secret: process.env.AUTH_SECRET, ttl: '1h', refreshTtl: '30d' },
  strategies: ['password', 'magic-link', 'api-key'],
  onMagicLink: async ({ email, url }) => sendEmail(email, url),
  magicLinkUrl: 'https://app.example.com/login?token={token}',
});

app.use('/api/auth', auth.router);
app.use(auth.errorHandler);

// Proteger el resto de la app
app.use('/api/community', auth.requireAuth, community.router);
```

`createAuth` devuelve:

| Campo            | Descripción                                              |
| ---------------- | -------------------------------------------------------- |
| `router`         | Router Express con los endpoints de las estrategias       |
| `requireAuth`    | Middleware: exige sesión (Bearer, `?token=` o `x-api-key`)|
| `optionalAuth`   | Middleware: adjunta `req.user` si hay credencial válida   |
| `requireRole`    | `requireRole('admin', ...)` → 403 si el rol no coincide   |
| `hashPassword` / `verifyPassword` | Acceso directo al adaptador elegido       |
| `errorHandler`   | Traduce `AuthError` a `{ error: { code, message } }`      |

### 2.2 Contrato `users`

Obligatorio:

| Método                              | Devuelve / hace                          |
| ----------------------------------- | ---------------------------------------- |
| `findByLogin(id)` o `findByEmail(id)` | usuario o `null` (el identificador por defecto es el email) |
| `findById(id)`                      | usuario o `null`                         |

Opcional: `createUser(patch)` (habilita `/register`), `setPasswordHash(id, hash)`
(cambio/reset). La forma pública del usuario se define con la opción de nivel
superior `serialize(user)` (por defecto elimina el hash).

El identificador de acceso es configurable con `identifierField` (por defecto
`'email'`). Para apps que usan `username`, define `users.findByLogin` y
`identifierField: 'username'`:

```js
createAuth({
  identifierField: 'username',
  users: {
    findByLogin: (username) => db.prepare('SELECT * FROM users WHERE username = ?').get(username),
    findById: (id) => db.prepare('SELECT * FROM users WHERE id = ?').get(id),
  },
});
```

```js
const users = {
  findByEmail: (email) => db.prepare('SELECT * FROM users WHERE email = ?').get(email),
  findById: (id) => db.prepare('SELECT * FROM users WHERE id = ?').get(id),
  createUser: ({ email, name, role, passwordHash }) =>
    insertUser({ email, name, role, password_hash: passwordHash }),
  setPasswordHash: (id, hash) =>
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, id),
};
```

Config relacionada: `passwordField` (`passwordHash`), `statusField` (`status`),
`activeStatus` (`active`), `defaultRole` (`user`). El login lee el hash del
usuario con `user[passwordField]`.

### 2.3 Opciones de `createAuth`

| Opción         | Valores                                                  | Por defecto              |
| -------------- | -------------------------------------------------------- | ------------------------ |
| `users`        | puente obligatorio                                       | —                        |
| `passwords`    | `'scrypt'` \| `'bcryptjs'` \| `{ hash, verify }`         | `'scrypt'`               |
| `tokens`       | `{ secret, ttl, refreshTtl, refresh, algorithm, issuer }`| `ttl: '1h'`              |
| `strategies`   | array de `'password'`, `'magic-link'`, `'api-key'`       | `['password']`           |
| `identifierField` | campo de login (`'email'`, `'username'`, …)           | `'email'`                |
| `passwordField` | campo del hash en el usuario                            | `'passwordHash'`         |
| `store` / `db` | adaptador propio o handle `node:sqlite`                  | memoria                  |
| `serialize`    | `(user) => publicUser`                                   | elimina el hash          |
| `messages`     | mapa `code -> texto` para errores `auth/<code>`          | inglés                   |
| `onMagicLink`  | `({ email, token, url, purpose, user }) => void`         | —                        |
| `magicLinkUrl` | `(token) => url` o plantilla con `{token}`               | `/magic-link?token=`     |
| `magicLinkTtl` | duración (`'15m'`)                                       | `'15m'`                  |
| `rateLimit`    | `true` \| `false` \| `{ windowMs, max }`                 | `true`                   |
| `onEvent`      | `(type, payload) => void`                                | —                        |

El **almacén** (`store`) guarda refresh tokens, magic links, resets y API keys.
Por defecto es en memoria (una instancia); para persistir, pasa `db`
(`node:sqlite`, tabla `ak_kv`) o tu propio adaptador con
`get/set/del/list`.

### 2.4 Endpoints

Password

| Método | Ruta                 | Cuerpo                                  |
| ------ | -------------------- | --------------------------------------- |
| POST   | `/register`          | `{ email, password, name? }`            |
| POST   | `/login`             | `{ email, password }`                   |
| POST   | `/refresh`           | `{ refreshToken }`                      |
| POST   | `/logout`            | `{ refreshToken? }`                     |
| GET    | `/me`                | — (requiere sesión)                     |
| POST   | `/password/change`   | `{ currentPassword, newPassword }`      |
| POST   | `/password/forgot`   | `{ email }`                             |
| POST   | `/password/reset`    | `{ token, newPassword }`                |

Magic link: `POST /magic-link { email }`, `POST /magic-link/verify { token }`.
API keys: `POST /api-keys { label }`, `GET /api-keys`, `DELETE /api-keys/:id`.

Respuestas exitosas incluyen `{ token, expiresIn, refreshToken?, user }`.
Los errores siguen el formato `{ error: { code: 'auth/...', message } }`.

---

## 3. Frontend (React)

### 3.1 API + Provider

```jsx
import {
  createAuthApi,
  createTokenStorage,
  AuthProvider,
  LoginForm,
  ProtectedRoute,
} from 'auth-kit/react';
import 'auth-kit/styles.css';

const storage = createTokenStorage();
export const authApi = createAuthApi({
  basePath: '/api/auth',
  ...storage,
  onUnauthorized: () => { window.location.href = '/login'; },
});

export function AuthScope({ children }) {
  return <AuthProvider api={authApi}>{children}</AuthProvider>;
}
```

### 3.2 Componentes

| Componente        | Props                                                             |
| ----------------- | ---------------------------------------------------------------- |
| `LoginForm`       | `onSuccess?(user)`, `showMagicLink?`, `t?`, `locale?`            |
| `RegisterForm`    | `onSuccess?(user)`, `requireName?`, `t?`, `locale?`             |
| `MagicLinkForm`   | `t?`, `locale?`                                                  |
| `ProtectedRoute`  | `roles?`, `onUnauthenticated?`, `fallback?`, `t?`, `locale?`     |

`useAuth()` expone `{ user, loading, error, isAuthenticated, login, register,
verifyMagicLink, requestMagicLink, forgotPassword, resetPassword, logout,
refresh, setUser, clearError }`.

```jsx
function Profile() {
  const { user } = useAuth();
  return <p>{user.name}</p>;
}

<ProtectedRoute roles={['admin']} onUnauthenticated={() => navigate('/login')}>
  <Profile />
</ProtectedRoute>
```

### 3.3 `createAuthApi(options)`

`{ basePath = '/api/auth', fetchImpl, getToken, getRefreshToken, onTokens,
onUnauthorized }`. Métodos: `register`, `login`, `refresh`, `logout`, `me`,
`changePassword`, `forgotPassword`, `resetPassword`, `requestMagicLink`,
`verifyMagicLink`, `listApiKeys`, `createApiKey`, `deleteApiKey`. Si recibe un
401, intenta refrescar el token y reintenta una vez.

### 3.4 Estilos e i18n

Importa `auth-kit/styles.css` y personaliza con variables `--ak-*` (soporta modo
oscuro automático). Diccionarios `es`/`en` internos; pasa `t` para usar los tuyos.

---

## 4. Tests

```bash
npm test
```

Cubren registro/login/me, rotación de refresh, API keys, magic link y
cambio/reset de contraseña.

## 5. Límites conocidos

- Estrategias OAuth, TOTP/2FA y WebAuthn: pendientes (roadmap en `PLAN.md`).
- El almacén en memoria no persiste ni escala a varias instancias; usa `db` o un
  `store` propio.
- Verificación de email y bloqueo por intentos fallidos: pendientes.
