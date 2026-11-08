/**
 * HKVM Panel - License Stub
 * All license checks silently return "activated" — no server calls, no keys required.
 */

const path = require('path');
const os = require('os');
const fs = require('fs');

// ============= CONFIGURATION =============
const LICENSE_SERVER_URL = '';          // No server needed
const RECHECK_INTERVAL = 999999;
const MAX_ENVELOPE_AGE = 999999;
const PANEL_VERSION = 'V2.0-Free';

const DB_PATH = 'hvm.db';

// ============= LOGGER (silent) =============
const logger = {
  info:  () => {},
  warn:  () => {},
  error: () => {},
  debug: () => {},
};

// ============= MACHINE ID =============
async function generateMachineIdFromHardware() {
  try {
    const hostname = os.hostname();
    const cpus = os.cpus();
    const cpuModel = cpus[0]?.model || 'unknown';
    const machineIdInput = `${hostname}-${cpuModel}-free`;
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(machineIdInput).digest('hex');
  } catch {
    return 'local-machine-id';
  }
}

// ============= STORAGE =============
let _dbPath;
let _db;
let _dbReady = false;

async function initLicenseStorage(customDbPath = null, sharedDb = null) {
  _dbPath = customDbPath || path.join(process.env.HKVM_DATA_DIR || path.join(os.homedir(), '.hkvm'), DB_PATH);
  try {
    const dir = path.dirname(_dbPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    if (sharedDb) {
      _db = sharedDb;
    } else {
      const sqlite3 = require('sqlite3').verbose();
      _db = new sqlite3.Database(_dbPath);
    }

    // Create license table if needed
    const createTable = () => new Promise((resolve) => {
      const sql = `CREATE TABLE IF NOT EXISTS license_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        activated INTEGER DEFAULT 1,
        license_key TEXT DEFAULT '',
        activated_at TEXT DEFAULT '',
        activated_by TEXT DEFAULT 'local',
        owner TEXT DEFAULT 'Free User',
        machine_id TEXT DEFAULT '',
        key_blob TEXT DEFAULT '',
        last_checked TEXT DEFAULT '',
        last_validated TEXT DEFAULT '',
        server_response TEXT DEFAULT '{}'
      )`;
      if (_db.run) {
        _db.run(sql, (err) => { resolve(!err); });
      } else {
        resolve(true);
      }
    });

    await createTable();

    // Ensure a row exists with activated = 1
    const mid = await generateMachineIdFromHardware();
    const now = new Date().toISOString();
    const upsert = `INSERT OR IGNORE INTO license_state (id, activated, owner, machine_id, activated_at, activated_by)
                    VALUES (1, 1, 'User', '${mid}', '${now}', 'local')`;
    if (_db.run) {
      await new Promise((resolve) => {
        _db.run(upsert, () => {
          _db.run(`UPDATE license_state SET activated = 1 WHERE id = 1`, () => resolve());
        });
      });
    }
    _dbReady = true;
    logger.info('[License] Free edition — always active');
  } catch (err) {
    logger.warn('[License] DB init error (non-fatal):', err.message);
    _dbReady = true; // Still allow the panel to work
  }
}

// ============= PUBLIC API (all silent / always active) =============

async function getMachineId() {
  return await generateMachineIdFromHardware();
}

async function isActivated() {
  return true; // Always active
}

async function getState() {
  return {
    activated: true,
    owner: 'Free User',
    activated_at: new Date().toISOString(),
    activated_by: 'local',
    machine_id: await getMachineId(),
  };
}

async function updateState(fields) {
  // No-op
  return true;
}

async function getSignedEnvelope() {
  return {
    activated: true,
    owner: 'Free User',
    activated_at: new Date().toISOString(),
    machine_id: await getMachineId(),
    version: PANEL_VERSION,
  };
}

async function getStatusInfo() {
  return {
    activated: true,
    owner: 'Free User',
    version: PANEL_VERSION,
    message: 'License active',
  };
}

async function activateWithServer(licenseKey, activatedBy = 'web') {
  logger.info('[License] Free edition — activation not needed');
  return { success: true, message: 'License activated' };
}

async function activateWithServerWrapped(licenseKey, activatedBy = 'web') {
  return await activateWithServer(licenseKey, activatedBy);
}

async function revalidateWithServer() {
  return { success: true, message: 'Free edition — always valid' };
}

async function deactivateLocal(reason = '') {
  logger.info('[License] Free edition — deactivation ignored');
  return true;
}

function startBackgroundRevalidation() {
  // No-op — no background checks needed
}

function requiresLicense(fallback = null) {
  return (req, res, next) => next(); // Always allow
}

function initLicenseMiddleware(app) {
  // Completely silent — no license checks injected
  logger.info('[License] Free edition — no license middleware active');
}

async function attemptLicenseRecovery() {
  // No-op
}

function verifySignedResponse() { return true; }
function encryptKey(plain) { return plain; }
function decryptKey(blob) { return blob; }
function getPublicKeyFingerprint() { return 'local'; }
function getServerUrl() { return ''; }

// ============= EXPORTS =============
module.exports = {
  LICENSE_SERVER_URL,
  EMBEDDED_PUB_KEY_PEM: '',
  RECHECK_INTERVAL,
  MAX_ENVELOPE_AGE,
  initLicenseStorage,
  getMachineId,
  isActivated,
  getSignedEnvelope,
  getStatusInfo,
  getState,
  updateState,
  decryptKey,
  encryptKey,
  verifySignedResponse,
  activateWithServer,
  activateWithServerWrapped,
  revalidateWithServer,
  deactivateLocal,
  startBackgroundRevalidation,
  requiresLicense,
  getPublicKeyFingerprint,
  getServerUrl,
  initLicenseMiddleware,
  attemptLicenseRecovery,
};
