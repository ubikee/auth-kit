const { unauthorized, forbidden } = require('./errors');
const { sha256 } = require('./util');

function extractCredential(req) {
  const header = (req.headers && req.headers.authorization) || '';
  if (header.startsWith('Bearer ')) {
    const value = header.slice(7).trim();
    if (value) return { type: 'bearer', value };
  }
  const queryToken = req.query && req.query.token;
  if (typeof queryToken === 'string' && queryToken) return { type: 'bearer', value: queryToken };
  const apiKey = req.headers && req.headers['x-api-key'];
  if (typeof apiKey === 'string' && apiKey) return { type: 'apikey', value: apiKey };
  return null;
}

function createMiddleware(ctx) {
  const { users, tokens, store, statusField, activeStatus, apiKeysEnabled } = ctx;

  async function resolve(req) {
    const credential = extractCredential(req);
    if (!credential) return null;

    let userId = null;
    if (credential.type === 'bearer') {
      const claims = tokens.verifyAccess(credential.value);
      if (!claims) return null;
      userId = claims.sub;
    } else if (apiKeysEnabled) {
      const entry = await store.get(`apikey:${sha256(credential.value)}`);
      if (!entry) return null;
      userId = entry.userId;
    }
    if (userId == null) return null;

    const user = await users.findById(userId);
    if (!user) return null;
    if (statusField && user[statusField] !== activeStatus) return null;
    return user;
  }

  async function requireAuth(req, res, next) {
    try {
      const user = await resolve(req);
      if (!user) return next(unauthorized());
      req.user = user;
      req.currentUser = ctx.serialize(user);
      req.auth = { type: req.headers.authorization ? 'bearer' : 'token' };
      return next();
    } catch (err) {
      return next(err);
    }
  }

  async function optionalAuth(req, res, next) {
    try {
      const user = await resolve(req);
      if (user) {
        req.user = user;
        req.currentUser = ctx.serialize(user);
      }
      return next();
    } catch (err) {
      return next(err);
    }
  }

  const requireRole =
    (...roles) =>
    (req, res, next) => {
      if (!req.user) return next(unauthorized());
      if (!roles.includes(req.user.role)) return next(forbidden());
      return next();
    };

  return { resolve, requireAuth, optionalAuth, requireRole };
}

module.exports = { createMiddleware };
