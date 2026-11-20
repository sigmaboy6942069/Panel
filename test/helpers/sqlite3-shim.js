/**
 * Test helper: route `require('sqlite3')` to node:sqlite so the panel can boot
 * in environments without native bindings. Only used by tests.
 */
const Module = require('module');
const { DatabaseSync } = require('node:sqlite');

class ShimDatabase {
  constructor(filename, cb) {
    this._db = new DatabaseSync(filename);
    try { this._db.exec('PRAGMA journal_mode = WAL'); } catch {}
    if (cb) setImmediate(() => cb(null));
  }
  _s(sql) { return this._db.prepare(sql); }
  run(sql, p, cb) {
    if (typeof p === 'function') { cb = p; p = []; }
    try {
      const r = this._s(sql).run(...(p || []));
      const ctx = { lastID: Number(r.lastInsertRowid || 0), changes: Number(r.changes || 0) };
      if (cb) cb.call(ctx, null);
      return this;
    } catch (e) { if (cb) cb.call({}, e); else throw e; return this; }
  }
  get(sql, p, cb) {
    if (typeof p === 'function') { cb = p; p = []; }
    try { if (cb) cb(null, this._s(sql).get(...(p || []))); } catch (e) { if (cb) cb(e); }
    return this;
  }
  all(sql, p, cb) {
    if (typeof p === 'function') { cb = p; p = []; }
    try { if (cb) cb(null, this._s(sql).all(...(p || []))); } catch (e) { if (cb) cb(e); }
    return this;
  }
  exec(sql, cb) {
    try { this._db.exec(sql); if (cb) cb(null); } catch (e) { if (cb) cb(e); }
    return this;
  }
  serialize(fn) { if (fn) fn(); return this; }
  parallelize(fn) { if (fn) fn(); return this; }
  close(cb) { try { this._db.close(); } catch {} if (cb) cb(null); }
}

const shim = { Database: ShimDatabase, OPEN_READWRITE: 2, OPEN_CREATE: 4, verbose: () => shim };
const orig = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === 'sqlite3') return 'sqlite3-test-shim';
  return orig.call(this, request, ...rest);
};
require.cache['sqlite3-test-shim'] = {
  id: 'sqlite3-test-shim', filename: 'sqlite3-test-shim', loaded: true, exports: shim,
};

module.exports = shim;
