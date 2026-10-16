function memoryStore() {
  const entries = new Map();
  const alive = (entry) => entry && (!entry.expiresAt || entry.expiresAt > Date.now());

  return {
    async get(key) {
      const entry = entries.get(key);
      if (!alive(entry)) {
        entries.delete(key);
        return null;
      }
      return JSON.parse(entry.value);
    },
    async set(key, value, ttlMs) {
      entries.set(key, { value: JSON.stringify(value), expiresAt: ttlMs ? Date.now() + ttlMs : null });
    },
    async del(key) {
      entries.delete(key);
    },
    async list(prefix = '') {
      const out = [];
      for (const [key, entry] of entries) {
        if (alive(entry) && key.startsWith(prefix)) out.push({ key, value: JSON.parse(entry.value) });
      }
      return out;
    },
  };
}

function sqliteStore(db) {
  db.exec(
    `CREATE TABLE IF NOT EXISTS ak_kv (
       key TEXT PRIMARY KEY,
       value TEXT NOT NULL,
       expires_at INTEGER
     )`
  );

  return {
    async get(key) {
      const row = db.prepare('SELECT value, expires_at FROM ak_kv WHERE key = ?').get(key);
      if (!row) return null;
      if (row.expires_at && row.expires_at <= Date.now()) {
        db.prepare('DELETE FROM ak_kv WHERE key = ?').run(key);
        return null;
      }
      return JSON.parse(row.value);
    },
    async set(key, value, ttlMs) {
      db.prepare(
        `INSERT INTO ak_kv (key, value, expires_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at`
      ).run(key, JSON.stringify(value), ttlMs ? Date.now() + ttlMs : null);
    },
    async del(key) {
      db.prepare('DELETE FROM ak_kv WHERE key = ?').run(key);
    },
    async list(prefix = '') {
      const rows = db.prepare('SELECT key, value, expires_at FROM ak_kv WHERE key LIKE ?').all(`${prefix}%`);
      return rows
        .filter((row) => !row.expires_at || row.expires_at > Date.now())
        .map((row) => ({ key: row.key, value: JSON.parse(row.value) }));
    },
  };
}

function resolveStore({ store, db }) {
  if (store) return store;
  if (db) return sqliteStore(db);
  return memoryStore();
}

module.exports = { memoryStore, sqliteStore, resolveStore };
