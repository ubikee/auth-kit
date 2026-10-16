const crypto = require('node:crypto');

const ALGORITHMS = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' };

const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

function sign(payload, secret, { ttlSeconds, algorithm = 'HS256', issuer } = {}) {
  const digest = ALGORITHMS[algorithm];
  if (!digest) throw new Error(`auth-kit: algoritmo JWT no soportado: ${algorithm}`);

  const now = Math.floor(Date.now() / 1000);
  const claims = { ...payload, iat: now };
  if (ttlSeconds != null) claims.exp = now + ttlSeconds;
  if (issuer) claims.iss = issuer;

  const data = `${encode({ alg: algorithm, typ: 'JWT' })}.${encode(claims)}`;
  const signature = crypto.createHmac(digest, secret).update(data).digest('base64url');
  return `${data}.${signature}`;
}

function verify(token, secret, { algorithm = 'HS256', issuer, clockTolerance = 0 } = {}) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerPart, claimsPart, signaturePart] = parts;

  const digest = ALGORITHMS[algorithm];
  if (!digest) return null;

  let header;
  try {
    header = JSON.parse(Buffer.from(headerPart, 'base64url').toString());
  } catch {
    return null;
  }
  if (header.alg !== algorithm) return null;

  const expected = crypto.createHmac(digest, secret).update(`${headerPart}.${claimsPart}`).digest();
  const provided = Buffer.from(signaturePart, 'base64url');
  if (expected.length !== provided.length || !crypto.timingSafeEqual(expected, provided)) return null;

  let claims;
  try {
    claims = JSON.parse(Buffer.from(claimsPart, 'base64url').toString());
  } catch {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp === 'number' && now > claims.exp + clockTolerance) return null;
  if (typeof claims.nbf === 'number' && now + clockTolerance < claims.nbf) return null;
  if (issuer && claims.iss !== issuer) return null;
  return claims;
}

module.exports = { sign, verify, ALGORITHMS };
