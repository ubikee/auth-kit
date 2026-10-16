const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createAuth } = require('./index');

function memoryUsers() {
  let nextId = 1;
  const rows = new Map();
  return {
    rows,
    serialize: (user) => ({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      status: user.status,
    }),
    async findByEmail(email) {
      return [...rows.values()].find((row) => row.email === email) || null;
    },
    async findById(id) {
      return rows.get(String(id)) || null;
    },
    async createUser(patch) {
      const user = {
        id: nextId++,
        email: patch.email,
        name: patch.name,
        role: patch.role || 'user',
        status: 'active',
        passwordHash: patch.passwordHash,
      };
      rows.set(String(user.id), user);
      return user;
    },
    async setPasswordHash(id, hash) {
      const user = rows.get(String(id));
      if (user) user.passwordHash = hash;
    },
  };
}

async function startServer(createOptions) {
  const app = express();
  app.use(express.json());
  const captured = { magicLinks: [] };
  const auth = createAuth({
    onMagicLink: (payload) => captured.magicLinks.push(payload),
    ...createOptions,
  });
  app.use('/api/auth', auth.router);
  app.use(auth.errorHandler);
  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = async (method, path, { body, token, apiKey } = {}) => {
    const headers = {};
    if (body) headers['content-type'] = 'application/json';
    if (token) headers.authorization = `Bearer ${token}`;
    if (apiKey) headers['x-api-key'] = apiKey;
    const res = await fetch(`${base}/api/auth${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, body: await res.json() };
  };
  return { request, captured, auth, close: () => new Promise((resolve) => server.close(resolve)) };
}

test('register, login y /me con la estrategia password', async () => {
  const users = memoryUsers();
  const server = await startServer({ users, tokens: { secret: 'test-secret' } });
  try {
    const registered = await server.request('POST', '/register', {
      body: { email: 'ana@example.com', password: 'secret123', name: 'Ana' },
    });
    assert.equal(registered.status, 201);
    assert.ok(registered.body.token);
    assert.equal(registered.body.user.email, 'ana@example.com');
    assert.equal(registered.body.user.passwordHash, undefined);

    const login = await server.request('POST', '/login', {
      body: { email: 'ana@example.com', password: 'secret123' },
    });
    assert.equal(login.status, 200);
    assert.ok(login.body.refreshToken);

    const me = await server.request('GET', '/me', { token: login.body.token });
    assert.equal(me.status, 200);
    assert.equal(me.body.user.name, 'Ana');

    const bad = await server.request('POST', '/login', {
      body: { email: 'ana@example.com', password: 'wrong-password' },
    });
    assert.equal(bad.status, 401);
    assert.equal(bad.body.error.code, 'auth/invalid_credentials');
  } finally {
    await server.close();
  }
});

test('refresh rota el token y /me rechaza tokens inválidos', async () => {
  const users = memoryUsers();
  const server = await startServer({ users, tokens: { secret: 'test-secret' } });
  try {
    const reg = await server.request('POST', '/register', {
      body: { email: 'bob@example.com', password: 'secret123', name: 'Bob' },
    });
    const refreshed = await server.request('POST', '/refresh', {
      body: { refreshToken: reg.body.refreshToken },
    });
    assert.equal(refreshed.status, 200);
    assert.ok(refreshed.body.token);

    const reused = await server.request('POST', '/refresh', {
      body: { refreshToken: reg.body.refreshToken },
    });
    assert.equal(reused.status, 401);

    const me = await server.request('GET', '/me', { token: 'not-a-token' });
    assert.equal(me.status, 401);
  } finally {
    await server.close();
  }
});

test('estrategia api-key crea, autentica y revoca claves', async () => {
  const users = memoryUsers();
  const server = await startServer({
    users,
    strategies: ['password', 'api-key'],
    tokens: { secret: 'test-secret' },
  });
  try {
    const reg = await server.request('POST', '/register', {
      body: { email: 'carol@example.com', password: 'secret123', name: 'Carol' },
    });
    const created = await server.request('POST', '/api-keys', {
      token: reg.body.token,
      body: { label: 'CLI' },
    });
    assert.equal(created.status, 201);
    assert.ok(created.body.key.startsWith('ak_'));

    const { token } = reg.body;
    void token;
    const me = await server.request('GET', '/me', { apiKey: created.body.key });
    assert.equal(me.status, 200);
    assert.equal(me.body.user.email, 'carol@example.com');

    const list = await server.request('GET', '/api-keys', { token: reg.body.token });
    assert.equal(list.body.keys.length, 1);

    const removed = await server.request('DELETE', `/api-keys/${created.body.id}`, { token: reg.body.token });
    assert.equal(removed.status, 200);

    const revoked = await server.request('GET', '/me', { apiKey: created.body.key });
    assert.equal(revoked.status, 401);
  } finally {
    await server.close();
  }
});

test('magic-link emite y verifica enlaces sin contraseña', async () => {
  const users = memoryUsers();
  const server = await startServer({
    users,
    strategies: ['password', 'magic-link'],
    tokens: { secret: 'test-secret' },
    magicLinkUrl: 'https://app.test/login?token={token}',
  });
  try {
    await server.request('POST', '/register', {
      body: { email: 'dave@example.com', password: 'secret123', name: 'Dave' },
    });
    const requested = await server.request('POST', '/magic-link', { body: { email: 'dave@example.com' } });
    assert.equal(requested.status, 200);
    assert.equal(server.captured.magicLinks.length, 1);
    const link = server.captured.magicLinks[0];
    assert.match(link.url, /^https:\/\/app\.test\/login\?token=/);

    const verified = await server.request('POST', '/magic-link/verify', { body: { token: link.token } });
    assert.equal(verified.status, 200);
    assert.ok(verified.body.token);

    const reused = await server.request('POST', '/magic-link/verify', { body: { token: link.token } });
    assert.equal(reused.status, 401);
  } finally {
    await server.close();
  }
});

test('login por identificador username y mensajes personalizados', async () => {
  const rows = new Map();
  let nextId = 1;
  const users = {
    serialize: (u) => ({ id: u.id, username: u.username, name: u.name, role: u.role }),
    async findByLogin(identifier) {
      return rows.get(identifier) || null;
    },
    async findById(id) {
      return [...rows.values()].find((u) => String(u.id) === String(id)) || null;
    },
    async createUser(patch) {
      const user = { id: nextId++, username: patch.username, name: patch.name, role: patch.role, passwordHash: patch.passwordHash };
      rows.set(user.username, user);
      return user;
    },
  };
  const server = await startServer({
    users,
    identifierField: 'username',
    statusField: null,
    tokens: { secret: 'test-secret' },
    messages: { invalid_credentials: 'Credenciales incorrectas' },
  });
  try {
    const reg = await server.request('POST', '/register', {
      body: { username: 'juan', password: 'secret123', name: 'Juan' },
    });
    assert.equal(reg.status, 201);
    assert.equal(reg.body.user.username, 'juan');

    const bad = await server.request('POST', '/login', {
      body: { username: 'juan', password: 'nope' },
    });
    assert.equal(bad.status, 401);
    assert.equal(bad.body.error.message, 'Credenciales incorrectas');

    const ok = await server.request('POST', '/login', {
      body: { username: 'juan', password: 'secret123' },
    });
    assert.equal(ok.status, 200);
    assert.ok(ok.body.token);
  } finally {
    await server.close();
  }
});

test('cambio y reset de contraseña', async () => {
  const users = memoryUsers();
  const server = await startServer({ users, tokens: { secret: 'test-secret' } });
  try {
    const reg = await server.request('POST', '/register', {
      body: { email: 'erin@example.com', password: 'secret123', name: 'Erin' },
    });

    const changed = await server.request('POST', '/password/change', {
      token: reg.body.token,
      body: { currentPassword: 'secret123', newPassword: 'brandnew123' },
    });
    assert.equal(changed.status, 200);

    const loginNew = await server.request('POST', '/login', {
      body: { email: 'erin@example.com', password: 'brandnew123' },
    });
    assert.equal(loginNew.status, 200);

    const forgot = await server.request('POST', '/password/forgot', { body: { email: 'erin@example.com' } });
    assert.equal(forgot.status, 200);
    const reset = server.captured.magicLinks.find((item) => item.purpose === 'reset');
    assert.ok(reset);

    const done = await server.request('POST', '/password/reset', {
      body: { token: reset.token, newPassword: 'resetpass123' },
    });
    assert.equal(done.status, 200);

    const loginReset = await server.request('POST', '/login', {
      body: { email: 'erin@example.com', password: 'resetpass123' },
    });
    assert.equal(loginReset.status, 200);
  } finally {
    await server.close();
  }
});
