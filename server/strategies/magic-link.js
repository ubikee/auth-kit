const express = require('express');
const { badRequest, forbidden, unauthorized } = require('../errors');
const { requireEmail, randomToken, sha256 } = require('../util');

module.exports = function magicLinkStrategy(ctx) {
  const {
    users,
    tokens,
    store,
    statusField,
    activeStatus,
    serialize,
    onEvent,
    onMagicLink,
    magicLinkUrl,
    magicLinkTtlSeconds,
    limiter,
  } = ctx;

  const router = express.Router();
  const guard = limiter || ((req, res, next) => next());

  function buildUrl(token) {
    if (typeof magicLinkUrl === 'function') return magicLinkUrl(token);
    const template = typeof magicLinkUrl === 'string' ? magicLinkUrl : '/magic-link?token={token}';
    return template.replace('{token}', encodeURIComponent(token));
  }

  router.post('/magic-link', guard, async (req, res, next) => {
    try {
      const email = requireEmail((req.body || {}).email);
      const user = await users.findByEmail(email);
      if (user && (!statusField || user[statusField] === activeStatus)) {
        const raw = randomToken(32);
        await store.set(`magic:${sha256(raw)}`, { userId: String(user.id) }, magicLinkTtlSeconds * 1000);
        const url = buildUrl(raw);
        if (onMagicLink) await onMagicLink({ email, token: raw, url, user: serialize(user) });
        onEvent && onEvent('magic_link.requested', { user: serialize(user) });
      }
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  router.post('/magic-link/verify', async (req, res, next) => {
    try {
      const raw = (req.body || {}).token;
      if (!raw) throw badRequest('token is required', 'missing_fields');
      const key = `magic:${sha256(raw)}`;
      const entry = await store.get(key);
      if (!entry) throw unauthorized('Invalid or expired link', 'invalid_token');
      await store.del(key);

      const user = await users.findById(entry.userId);
      if (!user) throw unauthorized('Invalid or expired link', 'invalid_token');
      if (statusField && user[statusField] !== activeStatus) {
        throw forbidden('Account disabled', 'account_disabled');
      }

      const result = await tokens.issuePair(user);
      onEvent && onEvent('user.login', { user: serialize(user) });
      res.json({ ...result, user: serialize(user) });
    } catch (err) {
      next(err);
    }
  });

  return router;
};
