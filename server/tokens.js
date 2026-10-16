const jwt = require('./jwt');
const { parseDuration, randomToken, sha256 } = require('./util');

function createTokens(config, store) {
  const {
    secret = 'auth-kit-dev-secret-change-me',
    ttl = '1h',
    refreshTtl = '30d',
    refresh = true,
    algorithm = 'HS256',
    issuer,
  } = config || {};

  const ttlSeconds = parseDuration(ttl);
  const refreshTtlSeconds = parseDuration(refreshTtl);
  const refreshKey = (raw) => `refresh:${sha256(raw)}`;

  function issueAccess(user) {
    return jwt.sign({ sub: String(user.id), role: user.role }, secret, { ttlSeconds, algorithm, issuer });
  }

  function verifyAccess(token) {
    return jwt.verify(token, secret, { algorithm, issuer });
  }

  async function issuePair(user) {
    const accessToken = issueAccess(user);
    const result = { token: accessToken, expiresIn: ttlSeconds };
    if (!refresh) return result;
    const raw = randomToken(32);
    await store.set(refreshKey(raw), { userId: String(user.id) }, refreshTtlSeconds * 1000);
    result.refreshToken = raw;
    return result;
  }

  async function rotateRefresh(raw) {
    const entry = await store.get(refreshKey(raw));
    if (!entry) return null;
    await store.del(refreshKey(raw));
    return entry.userId;
  }

  async function revokeRefresh(raw) {
    await store.del(refreshKey(raw));
  }

  return { ttlSeconds, refreshTtlSeconds, issueAccess, verifyAccess, issuePair, rotateRefresh, revokeRefresh };
}

module.exports = { createTokens };
