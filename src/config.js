'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULT_CONFIG = {
  botName: 'Sachi AntiCrasher',
  prefix: '.',
  ownerNumbers: [],
  dryRun: false,
  authDir: 'auth',
  logLevel: 'info',
  stateFile: 'data/state.json',
  actions: {
    deleteForMe: true,
    revokeIfAdmin: true,
    blockOnHigh: true,
    kickOnCritical: false,
    autoKickWatchlisted: false,
    notifyOwner: true,
    guardOutgoing: true,
    reportToWhatsApp: true
  },
  report: {
    enabled: true,
    attempts: 3,
    mode: 'untilAccepted',
    delaysMs: [15000, 45000, 120000],
    minSeverity: 'high',
    perSenderDailyCap: 3,
    globalHourlyCap: 20
  },
  addWatchlist: [],
  thresholds: {}
};

function deepMerge(base, override) {
  if (!override || typeof override !== 'object') return { ...base };
  const out = { ...base };
  for (const [k, v] of Object.entries(override)) {
    if (v && typeof v === 'object' && !Array.isArray(v) && base[k] && typeof base[k] === 'object' && !Array.isArray(base[k])) {
      out[k] = deepMerge(base[k], v);
    } else if (v !== undefined) {
      out[k] = v;
    }
  }
  return out;
}

function loadConfig(file) {
  const configPath = file || path.join(process.cwd(), 'config.json');
  let user = {};
  try {
    user = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') {
      // eslint-disable-next-line no-console
      console.warn(`[config] could not read ${configPath}: ${e.message} - using defaults`);
    }
  }
  const cfg = deepMerge(DEFAULT_CONFIG, user);

  // env overrides (handy for hosting panels)
  if (process.env.AC_DRY_RUN === '1' || process.env.AC_DRY_RUN === 'true') cfg.dryRun = true;
  if (process.env.AC_OWNERS) {
    cfg.ownerNumbers = process.env.AC_OWNERS.split(',').map((s) => s.trim()).filter(Boolean);
  }
  if (process.env.AC_PREFIX) cfg.prefix = process.env.AC_PREFIX;
  if (process.env.AC_LOG_LEVEL) cfg.logLevel = process.env.AC_LOG_LEVEL;
  if (process.env.AC_AUTH_DIR) cfg.authDir = process.env.AC_AUTH_DIR;

  cfg.ownerNumbers = (cfg.ownerNumbers || []).map((n) => String(n).replace(/[^0-9]/g, '')).filter(Boolean);
  return cfg;
}

module.exports = { loadConfig, DEFAULT_CONFIG, deepMerge };
