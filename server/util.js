const crypto = require('node:crypto');
const { badRequest } = require('./errors');

const UNIT_SECONDS = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };

function parseDuration(value) {
  if (value == null) return null;
  if (typeof value === 'number') return value;
  const match = String(value).trim().match(/^(\d+)\s*(s|m|h|d|w)?$/i);
  if (!match) throw new Error(`auth-kit: duración no válida: ${value}`);
  const amount = Number(match[1]);
  const unit = (match[2] || 's').toLowerCase();
  return amount * UNIT_SECONDS[unit];
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function defaultSerialize(user, passwordField) {
  if (!user) return null;
  const copy = { ...user };
  delete copy[passwordField];
  delete copy.password_hash;
  delete copy.passwordHash;
  return copy;
}

function requireString(value, field, { min = 1, max = 200, code = 'missing_fields' } = {}) {
  const text = typeof value === 'string' ? value.trim() : '';
  if (text.length < min) throw badRequest(`${field} is required`, code);
  if (text.length > max) throw badRequest(`${field} is too long`, 'bad_request');
  return text;
}

function requireEmail(value) {
  const email = requireString(value, 'email', { min: 3, max: 254, code: 'invalid_email' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw badRequest('A valid email is required', 'invalid_email');
  }
  return email.toLowerCase();
}

function requireName(value) {
  return requireString(value, 'name', { min: 1, max: 120 });
}

function requirePassword(value, { min = 8, max = 128 } = {}) {
  if (typeof value !== 'string' || value.length < min) {
    throw badRequest(`Password must be at least ${min} characters`, 'password_too_short');
  }
  if (value.length > max) throw badRequest('Password is too long', 'bad_request');
  return value;
}

module.exports = {
  parseDuration,
  randomToken,
  sha256,
  defaultSerialize,
  requireString,
  requireEmail,
  requireName,
  requirePassword,
};
