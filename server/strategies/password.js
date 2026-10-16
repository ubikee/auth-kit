const express = require('express');
const { badRequest, conflict, forbidden, unauthorized } = require('../errors');
const { requireEmail, requirePassword, requireName, randomToken, sha256 } = require('../util');

module.exports = function passwordStrategy(ctx) {
  const {
    users,
    findUser,
    identifierField,
    readIdentifier,
    passwords,
    tokens,
    store,
    passwordField,
    statusField,
    activeStatus,
    defaultRole,
    requireName: mustRequireName,
    serialize,
    onEvent,
    onMagicLink,
    magicLinkUrl,
    magicLinkTtlSeconds,
    limiter,
  } = ctx;

  const router = express.Router();
  const guard = limiter || ((req, res, next) => next());
  const emit = (type, user) => onEvent && onEvent(type, { user: serialize(user) });

  function buildResetUrl(token) {
    if (typeof magicLinkUrl === 'function') return magicLinkUrl(token);
    const template = typeof magicLinkUrl === 'string' ? magicLinkUrl : '/reset-password?token={token}';
    return template.replace('{token}', encodeURIComponent(token));
  }

  router.post('/register', guard, async (req, res, next) => {
    try {
      if (typeof users.createUser !== 'function') {
        throw forbidden('Registration is not enabled', 'registration_disabled');
      }
      const body = req.body || {};
      const identifier = readIdentifier(body);
      const password = requirePassword(body.password);
      if (!body.name && mustRequireName) throw badRequest('Name is required', 'missing_fields');
      const name = body.name ? requireName(body.name) : identifier;

      if (await findUser(identifier)) throw conflict('That account is already registered', 'email_taken');

      const user = await users.createUser({
        [identifierField]: identifier,
        name,
        role: defaultRole,
        passwordHash: passwords.hash(password),
      });
      const result = await tokens.issuePair(user);
      emit('user.registered', user);
      res.status(201).json({ ...result, user: serialize(user) });
    } catch (err) {
      next(err);
    }
  });

  router.post('/login', guard, async (req, res, next) => {
    try {
      const body = req.body || {};
      const identifier = readIdentifier(body);
      const password = typeof body.password === 'string' ? body.password : '';

      const user = await findUser(identifier);
      const hash = user ? user[passwordField] : null;
      if (!user || !hash || !passwords.verify(password, hash)) {
        throw unauthorized('Invalid credentials', 'invalid_credentials');
      }
      if (statusField && user[statusField] !== activeStatus) {
        throw forbidden('Account disabled', 'account_disabled');
      }

      const result = await tokens.issuePair(user);
      emit('user.login', user);
      res.json({ ...result, user: serialize(user) });
    } catch (err) {
      next(err);
    }
  });

  router.post('/refresh', async (req, res, next) => {
    try {
      const raw = (req.body || {}).refreshToken;
      if (!raw) throw badRequest('refreshToken is required', 'missing_fields');
      const userId = await tokens.rotateRefresh(raw);
      if (!userId) throw unauthorized('Invalid refresh token', 'invalid_refresh');
      const user = await users.findById(userId);
      if (!user) throw unauthorized('Invalid refresh token', 'invalid_refresh');
      if (statusField && user[statusField] !== activeStatus) {
        throw forbidden('Account disabled', 'account_disabled');
      }
      const result = await tokens.issuePair(user);
      res.json({ ...result, user: serialize(user) });
    } catch (err) {
      next(err);
    }
  });

  router.post('/logout', async (req, res, next) => {
    try {
      const raw = (req.body || {}).refreshToken;
      if (raw) await tokens.revokeRefresh(raw);
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  router.get('/me', ctx.middleware.requireAuth, (req, res) => {
    res.json({ user: req.currentUser });
  });

  router.post('/password/change', ctx.middleware.requireAuth, async (req, res, next) => {
    try {
      if (typeof users.setPasswordHash !== 'function') {
        throw forbidden('Password change is not enabled', 'not_supported');
      }
      const body = req.body || {};
      const current = typeof body.currentPassword === 'string' ? body.currentPassword : '';
      const nextPassword = requirePassword(body.newPassword);
      if (!passwords.verify(current, req.user[passwordField])) {
        throw unauthorized('Current password is incorrect', 'invalid_credentials');
      }
      await users.setPasswordHash(req.user.id, passwords.hash(nextPassword));
      emit('user.password_changed', req.user);
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  router.post('/password/forgot', guard, async (req, res, next) => {
    try {
      const email = requireEmail((req.body || {}).email);
      const user = await users.findByEmail(email);
      if (user && (!statusField || user[statusField] === activeStatus)) {
        const raw = randomToken(32);
        await store.set(`reset:${sha256(raw)}`, { userId: String(user.id) }, magicLinkTtlSeconds * 1000);
        const url = buildResetUrl(raw);
        if (onMagicLink) await onMagicLink({ email, token: raw, url, purpose: 'reset', user: serialize(user) });
        onEvent && onEvent('password.reset_requested', { user: serialize(user) });
      }
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  router.post('/password/reset', guard, async (req, res, next) => {
    try {
      if (typeof users.setPasswordHash !== 'function') {
        throw forbidden('Password reset is not enabled', 'not_supported');
      }
      const body = req.body || {};
      const raw = body.token;
      if (!raw) throw badRequest('token is required', 'missing_fields');
      const nextPassword = requirePassword(body.newPassword);
      const key = `reset:${sha256(raw)}`;
      const entry = await store.get(key);
      if (!entry) throw unauthorized('Invalid or expired token', 'invalid_token');
      await store.del(key);

      const user = await users.findById(entry.userId);
      if (!user) throw unauthorized('Invalid or expired token', 'invalid_token');

      await users.setPasswordHash(user.id, passwords.hash(nextPassword));
      emit('user.password_reset', user);
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  return router;
};
