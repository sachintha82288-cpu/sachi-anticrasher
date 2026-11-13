#!/usr/bin/env node
'use strict';

/**
 * Scan a saved WhatsApp message JSON (for example a stanza you exported from
 * your own bot logs) without touching WhatsApp.
 *
 *   node scripts/scan-json.js sample.json
 *
 * The file may be either:
 *   { "message": { ... } }        -> a full Baileys message object
 *   { ... }                       -> a raw message object
 */

const fs = require('fs');
const { analyzeMessage, summarize } = require('../src/detector');

const file = process.argv[2];
if (!file) {
  console.error('usage: node scripts/scan-json.js <file.json>');
  process.exit(1);
}

let raw;
try {
  raw = JSON.parse(fs.readFileSync(file, 'utf8'));
} catch (e) {
  console.error('could not read/parse json:', e.message);
  process.exit(1);
}

const message = raw && raw.message ? raw.message : raw;
const result = analyzeMessage(message);

console.log('--- Sachi AntiCrasher scan ---');
console.log('verdict :', summarize(result));
console.log('severity:', result.severity, '| score:', result.score, '| action:', result.action);
console.log('stats   :', JSON.stringify(result.stats));
if (result.reasons.length) {
  console.log('reasons :');
  for (const r of result.reasons) {
    console.log(`  - ${r.code} (weight ${r.weight}) ${r.detail}  @ ${r.path}`);
  }
}
process.exitCode = result.flagged ? 2 : 0;
