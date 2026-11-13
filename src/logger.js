'use strict';

const fs = require('fs');
const path = require('path');

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };

function createLogger(options = {}) {
  const level = LEVELS[String(options.level || 'info').toLowerCase()] ?? 20;
  const logDir = options.dir || path.join(process.cwd(), 'logs');
  const jsonFile = path.join(logDir, 'anticrash.jsonl');

  try {
    fs.mkdirSync(logDir, { recursive: true });
  } catch {
    /* logging must never take the bot down */
  }

  function write(levelName, msg, meta) {
    if (LEVELS[levelName] < level) return;
    const ts = new Date().toISOString();
    const line = meta ? `${msg} ${safeJson(meta)}` : msg;
    // eslint-disable-next-line no-console
    console.log(`[${ts}] [${levelName.toUpperCase()}] ${line}`);
    if (levelName === 'debug') return;
    try {
      fs.appendFileSync(jsonFile, JSON.stringify({ ts, level: levelName, msg, ...(meta ? { meta } : {}) }) + '\n');
    } catch {
      /* ignore disk errors */
    }
  }

  return {
    debug: (m, meta) => write('debug', m, meta),
    info: (m, meta) => write('info', m, meta),
    warn: (m, meta) => write('warn', m, meta),
    error: (m, meta) => write('error', m, meta),
    file: jsonFile
  };
}

function safeJson(obj) {
  try {
    return JSON.stringify(obj);
  } catch {
    return '[unserializable]';
  }
}

module.exports = { createLogger };
