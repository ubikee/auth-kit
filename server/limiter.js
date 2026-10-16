function createLimiter({ windowMs = 15 * 60 * 1000, max = 50 } = {}) {
  const hits = new Map();

  return function rateLimit(req, res, next) {
    const key = req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
    const now = Date.now();
    const entry = hits.get(key);

    if (!entry || now > entry.reset) {
      hits.set(key, { count: 1, reset: now + windowMs });
      return next();
    }

    entry.count += 1;
    if (entry.count > max) {
      res
        .status(429)
        .json({ error: { code: 'auth/too_many_requests', message: 'Too many attempts, try again later' } });
      return;
    }
    next();
  };
}

module.exports = { createLimiter };
