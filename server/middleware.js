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
  const { users, tokens, store, statusField, activeStatus, apiKeysEnabled, preciseAuthErrors } = ctx;

  // Returns { status: 'ok', user } | { status: 'none' | 'invalid' | 'disabled' }.
  async function resolve(req) {
    const credential = extractCredential(req);
    if (!credential) return { status: 'none' };

    let userId = null;
    if (credential.type === 'bearer') {
      const claims = tokens.verifyAccess(credential.value);
      if (!claims) return { status: 'invalid' };
      userId = claims.sub;
    } else if (apiKeysEnabled) {
      const entry = await store.get(`apikey:${sha256(credential.value)}`);
      if (!entry) return { status: 'invalid' };
      userId = entry.userId;
    }
    if (userId == null) return { status: 'invalid' };

    const user = await users.findById(userId);
    if (!user) return { status: 'invalid' };
    if (statusField && user[statusField] !== activeStatus) return { status: 'disabled' };
    return { status: 'ok', user };
  }

  async function requireAuth(req, res, next) {
    try {
      const result = await resolve(req);
      if (result.status === 'ok') {
        req.user = result.user;
        req.currentUser = ctx.serialize(result.user);
        req.auth = { type: req.headers.authorization ? 'bearer' : 'token' };
        return next();
      }
      // Precise mode distinguishes a stale/invalid credential from a disabled
      // account; the default keeps the generic `unauthorized` for both.
      if (preciseAuthErrors && result.status === 'disabled') {
        return next(forbidden('Account disabled', 'account_disabled'));
      }
      if (preciseAuthErrors && result.status === 'invalid') {
        return next(unauthorized('Invalid or expired session', 'invalid_token'));
      }
      return next(unauthorized());
    } catch (err) {
      return next(err);
    }
  }

  async function optionalAuth(req, res, next) {
    try {
      const result = await resolve(req);
      if (result.status === 'ok') {
        req.user = result.user;
        req.currentUser = ctx.serialize(result.user);
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
