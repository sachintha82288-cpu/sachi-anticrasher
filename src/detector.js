'use strict';

/**
 * Sachi AntiCrasher - detection engine
 * ------------------------------------
 * Pure JavaScript, zero dependencies, no WhatsApp/Baileys import.
 * Input  : a Baileys `message` object (the decoded proto3 Message)
 * Output : { flagged, severity, score, reasons[], stats }
 *
 * Design notes
 *  - The bot process itself never renders a message, so scanning is safe:
 *    we can inspect a poison payload, decide, and delete it before the
 *    phone / WhatsApp Web client ever opens the chat.
 *  - This is a heuristic engine, not a signature list of one specific bug.
 *    It looks at *structure* (size, nesting, invisible characters, array
 *    counts, invalid numbers) which is what every known crash vector abuses.
 *  - Everything is bounded (node budget, depth, time) so a hostile message
 *    cannot turn the scanner into the denial-of-service.
 */

const { DEFAULT_THRESHOLDS, mergeThresholds } = require('./thresholds');

// ---------------------------------------------------------------- patterns

// C0/C1 control bytes. A single NUL in a chat message is already abnormal.
const RE_CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
// Bidi overrides / marks: the classic "black dot" / crash-code ingredient.
const RE_BIDI = /[\u200E\u200F\u202A-\u202E\u2066-\u2069\u061C]/g;
// Zero width, word joiner, BOM, hangul filler, braille blank, soft hyphen.
const RE_ZEROWIDTH = /[\u200B-\u200D\u2060\u2061\u2062\u2063\u2064\uFEFF\u00AD\u180E\u115F\u1160\u3164\uFFA0\u2800]/g;
// Stacked diacritics (zalgo) blow up text shaping.
const RE_COMBINING = /\p{M}/gu;
const RE_NEWLINE = /\n/g;

function count(re, s) {
  const m = s.match(re);
  return m ? m.length : 0;
}

/**
 * Longest run of the *same code point*.
 * Code points, not UTF-16 units, because an emoji bomb repeats a surrogate
 * pair - comparing single units would report a run of 1 and miss it.
 */
function maxCharRun(s) {
  if (s.length < 2) return s.length;
  let best = 1;
  let run = 0;
  let prev = -1;
  for (let i = 0; i < s.length; ) {
    const cp = s.codePointAt(i);
    i += cp > 0xffff ? 2 : 1;
    if (cp === prev) {
      run++;
    } else {
      prev = cp;
      run = 1;
    }
    if (run > best) best = run;
  }
  return best;
}

function byteLength(s) {
  return Buffer.byteLength(s, 'utf8');
}

// ---------------------------------------------------------------- helpers

function sevFromScore(score, T) {
  const s = T.severity;
  if (score >= s.critical) return 'critical';
  if (score >= s.high) return 'high';
  if (score >= s.medium) return 'medium';
  if (score >= s.low) return 'low';
  return 'none';
}

const SEV_RANK = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

function worse(a, b) {
  return SEV_RANK[a] >= SEV_RANK[b] ? a : b;
}

/**
 * Walk the message object graph once, collecting text/structural facts.
 * Bounded by maxNodes / maxDepth / scanBudgetMs.
 */
function collect(message, T) {
  const stats = {
    nodes: 0,
    maxDepth: 0,
    strings: 0,
    totalChars: 0,
    totalBytes: 0,
    maxTextLength: 0,
    maxTextPath: '',
    control: 0,
    bidi: 0,
    zeroWidth: 0,
    combining: 0,
    newlines: 0,
    maxRun: 0,
    maxRunPath: '',
    protoEstimate: 0,
    truncated: false,
    timedOut: false,
    deepestPath: '',
    cycles: 0
  };

  const seen = new WeakSet();
  const stack = [{ node: message, path: 'message', depth: 0 }];
  const deadline = Date.now() + T.scanBudgetMs;

  while (stack.length) {
    if (stats.nodes > T.maxNodes) {
      stats.truncated = true;
      break;
    }
    if ((stats.nodes & 255) === 0 && Date.now() > deadline) {
      stats.timedOut = true;
      break;
    }

    const { node, path, depth } = stack.pop();
    stats.nodes++;

    if (depth > stats.maxDepth) {
      stats.maxDepth = depth;
      stats.deepestPath = path;
    }
    if (depth > T.maxDepth) {
      stats.truncated = true;
      continue;
    }

    if (node === null || node === undefined) continue;

    const t = typeof node;

    if (t === 'string') {
      stats.strings++;
      const len = node.length;
      stats.totalChars += len;
      stats.totalBytes += byteLength(node);
      stats.protoEstimate += len + 8;
      if (len > stats.maxTextLength) {
        stats.maxTextLength = len;
        stats.maxTextPath = path;
      }
      if (len === 0) continue;

      const slice = len > T.maxStringScan ? node.slice(0, T.maxStringScan) : node;
      stats.control += count(RE_CONTROL, slice);
      stats.bidi += count(RE_BIDI, slice);
      stats.zeroWidth += count(RE_ZEROWIDTH, slice);
      stats.combining += count(RE_COMBINING, slice);
      stats.newlines += count(RE_NEWLINE, slice);
      if (slice.length >= 1000) {
        const r = maxCharRun(slice);
        if (r > stats.maxRun) {
          stats.maxRun = r;
          stats.maxRunPath = path;
        }
      }
      continue;
    }

    if (t === 'number') {
      stats.protoEstimate += 9;
      if (!Number.isFinite(node)) {
        // NaN / Infinity must be reported by the caller; keep the path.
        (stats.nonFinite ||= []).push(path);
      }
      continue;
    }

    if (t === 'boolean') {
      stats.protoEstimate += 2;
      continue;
    }

    if (t !== 'object') continue;

    if (seen.has(node)) {
      stats.cycles++;
      continue;
    }
    seen.add(node);

    if (Array.isArray(node)) {
      stats.protoEstimate += node.length * 2;
      for (let i = 0; i < node.length; i++) {
        stack.push({ node: node[i], path: `${path}[${i}]`, depth: depth + 1 });
      }
      continue;
    }

    // Uint8Array / Buffer (thumbnails, media keys, ...)
    if (ArrayBuffer.isView(node)) {
      const n = node.byteLength || node.length || 0;
      stats.protoEstimate += n;
      (stats.binary ||= []).push({ path, size: n });
      continue;
    }

    for (const key of Object.keys(node)) {
      const v = node[key];
      const p = `${path}.${key}`;
      if (v === undefined) continue;
      stats.protoEstimate += key.length + 4;
      stack.push({ node: v, path: p, depth: depth + 1 });
    }
  }

  return stats;
}

// ---------------------------------------------------------------- main

/**
 * @param {object} message   Baileys message object
 * @param {object} [options] { thresholds, extra }
 * @returns {{flagged:boolean, severity:string, score:number, reasons:Array, stats:object, action:string}}
 */
function analyzeMessage(message, options = {}) {
  const T = mergeThresholds(DEFAULT_THRESHOLDS, options.thresholds || {});
  const reasons = [];

  const add = (code, weight, detail, path) => {
    reasons.push({ code, weight, detail, path });
  };

  if (!message || typeof message !== 'object') {
    return {
      flagged: false,
      severity: 'none',
      score: 0,
      reasons: [],
      stats: { empty: true },
      action: 'log'
    };
  }

  const stats = collect(message, T);

  // ---------------- 1. bot-safety walk limits ----------------
  if (stats.truncated && stats.nodes > T.maxNodes) {
    add('STRUCT_TOO_MANY_NODES', 70, `${stats.nodes} nodes (> ${T.maxNodes})`, 'message');
  }
  if (stats.maxDepth > T.maxDepth) {
    add('STRUCT_TOO_DEEP', 45, `nesting depth ${stats.maxDepth} (> ${T.maxDepth}) at ${stats.deepestPath}`, stats.deepestPath);
  }
  if (stats.cycles > 0) {
    add('STRUCT_CYCLE', 60, `${stats.cycles} circular reference(s)`, 'message');
  }
  if (stats.timedOut) {
    add('STRUCT_SCAN_TIMEOUT', 40, 'scan budget exceeded - message too expensive to parse', 'message');
  }

  // ---------------- 2. invisible / bidi / combining floods ----------------
  if (stats.control >= T.controlCharCritical) {
    add('TEXT_CONTROL_BYTES', 85, `${stats.control} control bytes`, stats.maxTextPath);
  } else if (stats.control >= T.controlCharFlag) {
    add('TEXT_CONTROL_BYTES', 55, `${stats.control} control byte(s)`, stats.maxTextPath);
  }

  if (stats.bidi >= T.bidiCritical) {
    add('TEXT_BIDI_FLOOD', 90, `${stats.bidi} bidi control chars`, stats.maxTextPath);
  } else if (stats.bidi >= T.bidiFlag) {
    add('TEXT_BIDI_FLOOD', 55, `${stats.bidi} bidi control chars`, stats.maxTextPath);
  }

  if (stats.zeroWidth >= T.zeroWidthCritical) {
    add('TEXT_ZEROWIDTH_FLOOD', 85, `${stats.zeroWidth} zero-width chars`, stats.maxTextPath);
  } else if (stats.zeroWidth >= T.zeroWidthFlag) {
    add('TEXT_ZEROWIDTH_FLOOD', 50, `${stats.zeroWidth} zero-width chars`, stats.maxTextPath);
  }

  if (stats.combining >= T.combiningCritical) {
    add('TEXT_COMBINING_FLOOD', 80, `${stats.combining} combining marks`, stats.maxTextPath);
  } else if (stats.combining >= T.combiningFlag) {
    add('TEXT_COMBINING_FLOOD', 45, `${stats.combining} combining marks`, stats.maxTextPath);
  }

  const invisibleTotal = stats.control + stats.bidi + stats.zeroWidth + stats.combining;
  if (stats.totalChars > 200 && invisibleTotal / stats.totalChars >= T.invisibleRatio) {
    add(
      'TEXT_INVISIBLE_RATIO',
      45,
      `${(100 * invisibleTotal / stats.totalChars).toFixed(1)}% invisible characters`,
      stats.maxTextPath
    );
  }

  if (stats.maxRun >= T.repeatedCharRun) {
    add('TEXT_REPEAT_RUN', 60, `${stats.maxRun} repeated identical chars at ${stats.maxRunPath}`, stats.maxRunPath);
  }

  // ---------------- 3. raw text size ----------------
  if (stats.maxTextLength >= T.textLengthCritical) {
    add('TEXT_TOO_LARGE', 80, `${stats.maxTextLength} chars at ${stats.maxTextPath}`, stats.maxTextPath);
  } else if (stats.maxTextLength >= T.textLengthFlag) {
    add('TEXT_TOO_LARGE', 45, `${stats.maxTextLength} chars at ${stats.maxTextPath}`, stats.maxTextPath);
  } else if (stats.maxTextLength >= T.textLengthWarn) {
    add('TEXT_LONG', 12, `${stats.maxTextLength} chars at ${stats.maxTextPath}`, stats.maxTextPath);
  }

  if (stats.newlines >= T.newlineCritical) {
    add('TEXT_NEWLINE_FLOOD', 55, `${stats.newlines} newlines`, stats.maxTextPath);
  } else if (stats.newlines >= T.newlineFlag) {
    add('TEXT_NEWLINE_FLOOD', 25, `${stats.newlines} newlines`, stats.maxTextPath);
  }

  // ---------------- 4. non-finite numbers anywhere ----------------
  if (stats.nonFinite && stats.nonFinite.length) {
    add('NUM_NON_FINITE', 55, `NaN/Infinity at ${stats.nonFinite.slice(0, 3).join(', ')}`, stats.nonFinite[0]);
  }

  // ---------------- 5. estimated protobuf size ----------------
  if (stats.protoEstimate >= T.protoSizeCritical) {
    add('PROTO_TOO_LARGE', 85, `~${stats.protoEstimate} bytes encoded`, 'message');
  } else if (stats.protoEstimate >= T.protoSizeFlag) {
    add('PROTO_TOO_LARGE', 50, `~${stats.protoEstimate} bytes encoded`, 'message');
  }

  // ---------------- 6. mentions ----------------
  const mentioned = countMentions(message);
  if (mentioned >= T.mentionCritical) {
    add('MENTION_BOMB', 80, `${mentioned} mentioned JIDs`, 'message');
  } else if (mentioned >= T.mentionFlag) {
    add('MENTION_BOMB', 45, `${mentioned} mentioned JIDs`, 'message');
  }

  // ---------------- 7. vCards / contact bombs ----------------
  checkVCards(message, T, add);

  // ---------------- 8. interactive payloads ----------------
  checkInteractive(message, T, add);

  // ---------------- 9. thumbnails / media ----------------
  checkMedia(message, T, add);

  // ---------------- 10. location / poll ----------------
  checkLocation(message, T, add);
  checkPoll(message, T, add);

  // ---------------- score ----------------
  // Reasons compound: two medium findings are worse than one, but we cap the
  // total so a single big one still dominates the decision.
  let score = 0;
  for (const r of reasons) score += r.weight;
  if (reasons.length > 1) score += (reasons.length - 1) * 6;
  score = Math.min(100, score);

  const severity = sevFromScore(score, T);
  const flagged = severity !== 'none';
  const action = T.action[severity] || 'log';

  return {
    flagged,
    severity,
    score,
    reasons,
    stats: {
      nodes: stats.nodes,
      maxDepth: stats.maxDepth,
      totalChars: stats.totalChars,
      totalBytes: stats.totalBytes,
      maxTextLength: stats.maxTextLength,
      control: stats.control,
      bidi: stats.bidi,
      zeroWidth: stats.zeroWidth,
      combining: stats.combining,
      newlines: stats.newlines,
      mentions: mentioned,
      protoEstimate: stats.protoEstimate,
      truncated: stats.truncated,
      timedOut: stats.timedOut
    },
    action
  };
}

// ---------------------------------------------------------------- sub-checks

function countMentions(message) {
  let n = 0;
  const ctxInfo = message.extendedTextMessage && message.extendedTextMessage.contextInfo;
  if (ctxInfo) {
    if (Array.isArray(ctxInfo.mentionedJid)) n += ctxInfo.mentionedJid.length;
    if (Array.isArray(ctxInfo.groupMentions)) n += ctxInfo.groupMentions.length;
  }
  const anyCtx = [
    message.imageMessage,
    message.videoMessage,
    message.documentMessage,
    message.stickerMessage,
    message.audioMessage
  ];
  for (const m of anyCtx) {
    if (m && m.contextInfo && Array.isArray(m.contextInfo.mentionedJid)) {
      n += m.contextInfo.mentionedJid.length;
    }
  }
  if (Array.isArray(message.mentionedJid)) n += message.mentionedJid.length;
  return n;
}

function checkVCards(message, T, add) {
  const single = message.contactMessage;
  const multi = message.contactsArrayMessage;

  const inspect = (displayName, vcard, path) => {
    if (typeof vcard !== 'string') return;
    const len = vcard.length;
    if (len >= T.vcardLengthCritical) {
      add('VCARD_TOO_LARGE', 80, `${len} chars in vCard at ${path}`, path);
    } else if (len >= T.vcardLengthFlag) {
      add('VCARD_TOO_LARGE', 45, `${len} chars in vCard at ${path}`, path);
    }
    // count embedded contact records + long field values
    const records = (vcard.match(/BEGIN:VCARD/g) || []).length;
    if (records > 1) {
      add('VCARD_EMBEDDED_RECORDS', Math.min(60, 15 * records), `${records} VCARD records inside one vCard`, path);
    }
    for (const line of vcard.split(/\r?\n/)) {
      if (line.length >= T.vcardFieldLengthFlag) {
        add('VCARD_LONG_FIELD', 40, `${line.length}-char field (${line.slice(0, 12)}...)`, path);
        break;
      }
    }
    if (typeof displayName === 'string' && displayName.length >= T.vcardFieldLengthFlag) {
      add('VCARD_LONG_NAME', 40, `${displayName.length}-char display name`, path);
    }
  };

  if (single) inspect(single.displayName, single.vcard, 'message.contactMessage.vcard');

  if (multi && Array.isArray(multi.contacts)) {
    const n = multi.contacts.length;
    if (n >= T.vcardCountCritical) {
      add('VCARD_CONTACT_BOMB', 85, `${n} contacts in one message`, 'message.contactsArrayMessage');
    } else if (n >= T.vcardCountFlag) {
      add('VCARD_CONTACT_BOMB', 45, `${n} contacts in one message`, 'message.contactsArrayMessage');
    }
    // deep-scan the biggest few only (cost control)
    const sorted = [...multi.contacts].sort((a, b) => ((b && b.vcard && b.vcard.length) || 0) - ((a && a.vcard && a.vcard.length) || 0));
    sorted.slice(0, 3).forEach((c, i) => {
      if (!c) return;
      inspect(c.displayName, c.vcard, `message.contactsArrayMessage.contacts[${i}].vcard`);
    });
  }
}

function checkInteractive(message, T, add) {
  const inter = message.interactiveMessage;
  const nativeFlow = message.nativeFlowMessage || (inter && inter.nativeFlowMessage);
  const list = message.listMessage || (inter && inter.interactiveMessage && inter.interactiveMessage.listMessage);
  const buttons = message.buttonsMessage || (inter && inter.interactiveMessage && inter.interactiveMessage.buttonsMessage);
  const carousel = message.carouselMessage || (inter && inter.carouselMessage);

  if (buttons && Array.isArray(buttons.buttons) && buttons.buttons.length >= T.buttonCountFlag) {
    add('INTERACTIVE_BUTTON_BOMB', 45, `${buttons.buttons.length} buttons`, 'message.buttonsMessage');
  }

  if (list) {
    const sections = Array.isArray(list.sections) ? list.sections : [];
    if (sections.length >= T.sectionCountFlag) {
      add('INTERACTIVE_SECTION_BOMB', 50, `${sections.length} list sections`, 'message.listMessage');
    }
    let rows = 0;
    for (const s of sections) rows += Array.isArray(s && s.rows) ? s.rows.length : 0;
    if (rows >= T.rowCountFlag) {
      add('INTERACTIVE_ROW_BOMB', 50, `${rows} list rows`, 'message.listMessage');
    }
  }

  if (carousel) {
    const cards = Array.isArray(carousel.cards) ? carousel.cards.length : 0;
    if (cards >= T.cardCountFlag) {
      add('INTERACTIVE_CARD_BOMB', 50, `${cards} carousel cards`, 'message.carouselMessage');
    }
  }

  if (nativeFlow) {
    const b = Array.isArray(nativeFlow.buttons) ? nativeFlow.buttons : [];
    if (b.length >= T.buttonCountFlag) {
      add('INTERACTIVE_BUTTON_BOMB', 45, `${b.length} nativeFlow buttons`, 'message.nativeFlowMessage');
    }
    for (let i = 0; i < Math.min(b.length, 10); i++) {
      const params = b[i] && b[i].buttonParamsJson;
      if (typeof params !== 'string') continue;
      if (params.length >= T.buttonParamsJsonFlag) {
        add('INTERACTIVE_PARAMS_TOO_LARGE', 55, `${params.length}-byte buttonParamsJson`, `nativeFlow.buttons[${i}]`);
      }
      if (T.invalidJsonFlag) {
        try {
          JSON.parse(params);
        } catch {
          add('INTERACTIVE_PARAMS_INVALID', 40, 'buttonParamsJson is not valid JSON', `nativeFlow.buttons[${i}]`);
        }
      }
    }
  }
}

function checkMedia(message, T, add) {
  const mediaKeys = ['imageMessage', 'videoMessage', 'documentMessage', 'audioMessage', 'stickerMessage'];
  for (const k of mediaKeys) {
    const m = message[k];
    if (!m || typeof m !== 'object') continue;

    if (typeof m.jpegThumbnail === 'string' && m.jpegThumbnail.length >= T.thumbnailFlag) {
      add('MEDIA_THUMBNAIL_TOO_LARGE', 55, `${m.jpegThumbnail.length}-char thumbnail in ${k}`, `message.${k}.jpegThumbnail`);
    }
    if (m.jpegThumbnail && ArrayBuffer.isView(m.jpegThumbnail) && m.jpegThumbnail.byteLength >= T.thumbnailFlag) {
      add('MEDIA_THUMBNAIL_TOO_LARGE', 55, `${m.jpegThumbnail.byteLength}-byte thumbnail in ${k}`, `message.${k}.jpegThumbnail`);
    }

    // declared fileLength that is absurdly large for a chat payload
    const declared = Number(m.fileLength);
    if (Number.isFinite(declared) && declared > 0) {
      const payload = typeof m.fileSha256 === 'string' ? m.fileSha256.length : 0;
      if (payload && declared > 512 * 1024 * 1024) {
        add('MEDIA_FILE_LENGTH_ABSURD', 30, `fileLength ${declared} in ${k}`, `message.${k}.fileLength`);
      }
    }
    // caption inherits the same text limits (already covered by the walk)
  }
}

function checkLocation(message, T, add) {
  for (const k of ['locationMessage', 'liveLocationMessage']) {
    const m = message[k];
    if (!m || typeof m !== 'object') continue;
    const lat = Number(m.degreesLatitude);
    const lng = Number(m.degreesLongitude);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
      add('LOCATION_INVALID', 55, `non-numeric coordinates in ${k}`, `message.${k}`);
      continue;
    }
    const [latMin, latMax] = T.latitudeRange;
    const [lngMin, lngMax] = T.longitudeRange;
    if (lat < latMin || lat > latMax || lng < lngMin || lng > lngMax) {
      add('LOCATION_OUT_OF_RANGE', 60, `lat=${lat} lng=${lng} in ${k}`, `message.${k}`);
    }
  }
}

function checkPoll(message, T, add) {
  const m = message.pollCreationMessage || message.pollCreationMessageV2 || message.pollCreationMessageV3;
  if (!m || !Array.isArray(m.options)) return;
  const n = m.options.length;
  if (n >= T.pollOptionCritical) {
    add('POLL_OPTION_BOMB', 70, `${n} poll options`, 'message.pollCreationMessage');
  } else if (n >= T.pollOptionFlag) {
    add('POLL_OPTION_BOMB', 40, `${n} poll options`, 'message.pollCreationMessage');
  }
}

/** short human readable summary for logs */
function summarize(result) {
  if (!result.flagged) return 'clean';
  return `${result.severity.toUpperCase()}(${result.score}) ${result.reasons.map((r) => r.code).join('+')}`;
}

module.exports = {
  analyzeMessage,
  summarize,
  sevFromScore,
  worse,
  DEFAULT_THRESHOLDS,
  mergeThresholds
};
