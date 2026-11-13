'use strict';

/**
 * Sachi AntiCrasher - detection thresholds
 * ----------------------------------------
 * Every number here is a "how much is too much" limit for one crash vector.
 * The values are deliberately conservative: a normal long message, a normal
 * 200-contact vCard or a normal 3-button list message must never be flagged.
 *
 * You can override any of these from config.json -> "thresholds".
 */

const DEFAULT_THRESHOLDS = {
  // ---- generic walk safety (protects the bot itself from hanging) ----
  maxNodes: 6000,          // object/array nodes visited before we stop walking
  maxDepth: 12,            // wrapper nesting (viewOnce > ephemeral > ...)
  maxStringScan: 400000,   // chars inspected per string field
  scanBudgetMs: 250,       // hard time budget per message

  // ---- text / caption ----
  textLengthWarn: 12000,
  textLengthFlag: 30000,
  textLengthCritical: 60000,
  newlineFlag: 200,
  newlineCritical: 600,

  // ---- invisible / bidi / combining character floods ----
  controlCharFlag: 1,        // NUL / C0 / C1 bytes are never legitimate
  controlCharCritical: 5,
  bidiFlag: 40,              // LRO/RLO/LRI/RLI/PDF/LRM/RLM floods
  bidiCritical: 300,
  zeroWidthFlag: 60,         // ZWSP/ZWNJ/ZWJ/WJ/BOM/hangul filler/braille blank
  zeroWidthCritical: 400,
  combiningFlag: 150,        // stacked diacritics -> renderer blow-up
  combiningCritical: 800,
  invisibleRatio: 0.35,      // share of invisible chars in a message
  repeatedCharRun: 4000,     // one char repeated (emoji bomb)

  // ---- mentions ----
  mentionFlag: 40,
  mentionCritical: 120,

  // ---- vCard / contacts ----
  vcardLengthFlag: 2500,
  vcardLengthCritical: 8000,
  vcardCountFlag: 15,        // contacts inside one contactsArrayMessage
  vcardCountCritical: 60,
  vcardFieldLengthFlag: 800, // single FN:/N: value length

  // ---- interactive (buttons / list / carousel / nativeFlow) ----
  buttonCountFlag: 6,
  sectionCountFlag: 12,
  rowCountFlag: 40,
  cardCountFlag: 6,
  buttonParamsJsonFlag: 1500, // buttonParamsJson bytes
  invalidJsonFlag: true,      // malformed buttonParamsJson

  // ---- media / thumbnails ----
  thumbnailFlag: 60000,      // jpegThumbnail base64 length
  fileLengthMismatch: true,  // declared fileLength vs real payload sanity

  // ---- location / poll / other structured types ----
  pollOptionFlag: 12,
  pollOptionCritical: 40,
  latitudeRange: [-90, 90],
  longitudeRange: [-180, 180],

  // ---- protobuf size ----
  protoSizeFlag: 120000,     // estimated encoded Message size (bytes)
  protoSizeCritical: 400000,

  // ---- escalation ----
  burstWindowMs: 60000,
  burstCount: 2,             // same sender, same window -> escalate

  // ---- severity -> score cut-offs ----
  severity: {
    low: 15,
    medium: 35,
    high: 60,
    critical: 85
  },

  // ---- what to do at each severity ----
  action: {
    low: 'log',
    medium: 'delete',
    high: 'delete+block',
    critical: 'delete+block+report'
  }
};

/** deep merge so a partial config override keeps every other default */
function mergeThresholds(base, override) {
  if (!override || typeof override !== 'object') return { ...base };
  const out = { ...base };
  for (const [k, v] of Object.entries(override)) {
    if (v && typeof v === 'object' && !Array.isArray(v) && base[k] && typeof base[k] === 'object' && !Array.isArray(base[k])) {
      out[k] = mergeThresholds(base[k], v);
    } else if (v !== undefined) {
      out[k] = v;
    }
  }
  return out;
}

module.exports = { DEFAULT_THRESHOLDS, mergeThresholds };
