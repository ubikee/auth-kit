class AuthError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'AuthError';
    this.status = status;
    this.code = code;
  }
}

const make = (status, fallbackCode, fallbackMessage) => (message, code) =>
  new AuthError(status, code || fallbackCode, message || fallbackMessage);

const badRequest = make(400, 'bad_request', 'Invalid request');
const unauthorized = make(401, 'unauthorized', 'Authentication required');
const forbidden = make(403, 'forbidden', 'Not allowed');
const notFound = make(404, 'not_found', 'Not found');
const conflict = make(409, 'conflict', 'Conflict');

function createErrorHandler(messages = {}, { prefix = 'auth/' } = {}) {
  return function errorHandler(err, req, res, next) {
    if (res.headersSent) return next(err);
    const status = err && err.status ? err.status : 500;
    const bareCode = err && err.code ? err.code : status >= 500 ? 'internal_error' : 'bad_request';
    const code = `${prefix}${bareCode}`;
    const fallback = status >= 500 ? 'Internal server error' : (err && err.message) || 'Error';
    const message = messages[bareCode] || fallback;
    if (status >= 500 && process.env.NODE_ENV !== 'test') {
      console.error('[auth-kit] unhandled error:', err);
    }
    res.status(status).json({ error: { code, message } });
  };
}

module.exports = {
  AuthError,
  badRequest,
  unauthorized,
  forbidden,
  notFound,
  conflict,
  createErrorHandler,
  errorHandler: createErrorHandler(),
};
