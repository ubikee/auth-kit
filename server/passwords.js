const crypto = require('node:crypto');

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

function scryptHash(plain) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(plain, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

function scryptVerify(plain, stored) {
  try {
    const [scheme, N, r, p, saltPart, hashPart] = String(stored).split('$');
    if (scheme !== 'scrypt') return false;
    const salt = Buffer.from(saltPart, 'base64url');
    const expected = Buffer.from(hashPart, 'base64url');
    const actual = crypto.scryptSync(plain, salt, expected.length, { N: Number(N), r: Number(r), p: Number(p) });
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function bcryptProvider() {
  let bcrypt;
  try {
    bcrypt = require('bcryptjs');
  } catch {
    throw new Error('auth-kit: la estrategia `bcryptjs` requiere instalar `bcryptjs`');
  }
  const ROUNDS = 10;
  return {
    hash: (plain) => bcrypt.hashSync(plain, ROUNDS),
    verify: (plain, stored) => bcrypt.compareSync(plain, stored),
  };
}

function resolvePasswords(passwords) {
  if (passwords === 'scrypt' || passwords == null) return { name: 'scrypt', hash: scryptHash, verify: scryptVerify };
  if (passwords === 'bcryptjs' || passwords === 'bcrypt') return { name: 'bcryptjs', ...bcryptProvider() };
  if (typeof passwords === 'object' && typeof passwords.hash === 'function' && typeof passwords.verify === 'function') {
    return { name: 'custom', hash: passwords.hash, verify: passwords.verify };
  }
  throw new Error('auth-kit: `passwords` no válido (usa scrypt, bcryptjs o { hash, verify })');
}

module.exports = { resolvePasswords, scryptHash, scryptVerify };
