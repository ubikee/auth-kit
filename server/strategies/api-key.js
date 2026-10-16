const express = require('express');
const { badRequest, notFound } = require('../errors');
const { randomToken, sha256, requireString } = require('../util');

module.exports = function apiKeyStrategy(ctx) {
  const { store, serialize } = ctx;
  const router = express.Router();

  router.use('/api-keys', ctx.middleware.requireAuth);

  router.post('/api-keys', async (req, res, next) => {
    try {
      const label = requireString((req.body || {}).label, 'label', { min: 1, max: 120 });
      const raw = `ak_${randomToken(24)}`;
      const id = sha256(raw);
      await store.set(`apikey:${id}`, {
        userId: String(req.user.id),
        label,
        createdAt: new Date().toISOString(),
      });
      res.status(201).json({ id, key: raw, label, user: serialize(req.user) });
    } catch (err) {
      next(err);
    }
  });

  router.get('/api-keys', async (req, res, next) => {
    try {
      const entries = await store.list('apikey:');
      const keys = entries
        .filter((entry) => entry.value.userId === String(req.user.id))
        .map((entry) => ({
          id: entry.key.slice('apikey:'.length),
          label: entry.value.label,
          createdAt: entry.value.createdAt,
        }));
      res.json({ keys });
    } catch (err) {
      next(err);
    }
  });

  router.delete('/api-keys/:id', async (req, res, next) => {
    try {
      const key = `apikey:${req.params.id}`;
      if (!/^[a-f0-9]{64}$/.test(req.params.id)) throw badRequest('Invalid key id', 'bad_request');
      const entry = await store.get(key);
      if (!entry || entry.userId !== String(req.user.id)) throw notFound('Key not found');
      await store.del(key);
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  return router;
};
