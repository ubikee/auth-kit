const express = require('express');
const { AuthError, createErrorHandler } = require('./errors');
const { resolvePasswords } = require('./passwords');
const { createTokens } = require('./tokens');
const { resolveStore } = require('./store');
const { createMiddleware } = require('./middleware');
const { createLimiter } = require('./limiter');
const { parseDuration, defaultSerialize, requireEmail, requireString } = require('./util');
const passwordStrategy = require('./strategies/password');
const magicLinkStrategy = require('./strategies/magic-link');
const apiKeyStrategy = require('./strategies/api-key');

const STRATEGIES = {
  password: passwordStrategy,
  'magic-link': magicLinkStrategy,
  'api-key': apiKeyStrategy,
};

const DEFAULT_MAGIC_LINK_TTL = '15m';

// createAuth({ users, passwords, tokens, store, db, strategies, ... })
//   users       puente obligatorio al modelo de usuario del host.
//   passwords   'scrypt' (defecto) | 'bcryptjs' | { hash, verify }.
//   tokens      { secret, ttl, refreshTtl, refresh, algorithm, issuer }.
//   strategies  ['password', 'magic-link', 'api-key'].
//   store / db  almacén de estado (refresh, magic links, api keys).
//   serialize   (user) => publicUser. Por defecto elimina el hash.
function createAuth(options = {}) {
  const {
    users,
    passwords = 'scrypt',
    tokens: tokenConfig = {},
    store: storeConfig = null,
    db = null,
    strategies = ['password'],
    identifierField = 'email',
    passwordField = 'passwordHash',
    statusField = 'status',
    activeStatus = 'active',
    defaultRole = 'user',
    requireName = false,
    errorPrefix = 'auth/',
    serialize,
    messages = {},
    onEvent = null,
    onMagicLink = null,
    magicLinkUrl = null,
    magicLinkTtl = DEFAULT_MAGIC_LINK_TTL,
    rateLimit = true,
  } = options;

  const findUser = (users && (users.findByLogin || users.findByEmail)) || null;
  if (!users || typeof findUser !== 'function' || typeof users.findById !== 'function') {
    throw new Error('createAuth: `users.findById` y `users.findByLogin` (o `findByEmail`) son obligatorios');
  }

  const emailLogin = identifierField === 'email';
  const readIdentifier = (source) =>
    emailLogin
      ? requireEmail((source || {})[identifierField])
      : requireString((source || {})[identifierField], identifierField, { min: 1, max: 254 });

  const store = resolveStore({ store: storeConfig, db });
  const passwordAdapter = resolvePasswords(passwords);
  const tokenManager = createTokens(tokenConfig, store);
  const limiterConfig = rateLimit === true ? {} : rateLimit === false ? null : rateLimit;

  const ctx = {
    users,
    findUser,
    identifierField,
    readIdentifier,
    passwords: passwordAdapter,
    tokens: tokenManager,
    store,
    passwordField,
    statusField,
    activeStatus,
    defaultRole,
    requireName,
    messages,
    onEvent,
    onMagicLink,
    magicLinkUrl,
    magicLinkTtlSeconds: parseDuration(magicLinkTtl),
    serialize: serialize || ((user) => defaultSerialize(user, passwordField)),
    limiter: limiterConfig ? createLimiter(limiterConfig) : null,
    apiKeysEnabled: strategies.includes('api-key'),
  };

  const middleware = createMiddleware(ctx);
  ctx.middleware = middleware;

  const router = express.Router();
  for (const name of strategies) {
    const factory = STRATEGIES[name];
    if (!factory) throw new Error(`createAuth: estrategia desconocida: ${name}`);
    router.use(factory(ctx));
  }
  const handleError = createErrorHandler(messages, { prefix: errorPrefix });
  router.use(handleError);

  return {
    router,
    requireAuth: middleware.requireAuth,
    optionalAuth: middleware.optionalAuth,
    requireRole: middleware.requireRole,
    tokens: tokenManager,
    hashPassword: passwordAdapter.hash,
    verifyPassword: passwordAdapter.verify,
    strategy: passwordAdapter.name,
    errorHandler: handleError,
    AuthError,
  };
}

module.exports = { createAuth, AuthError };
