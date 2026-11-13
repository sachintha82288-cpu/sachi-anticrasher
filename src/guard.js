'use strict';

const { analyzeMessage, summarize, worse, mergeThresholds, DEFAULT_THRESHOLDS } = require('./detector');
const A = require('./actions');
const { TokenStore, attachTokenCapture } = require('./report/token-store');
const { Reporter } = require('./report/reporter');

const SEV_RANK = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

function jidToNumber(jid) {
  return String(jid || '').split('@')[0].split(':')[0];
}

function isGroup(jid) {
  return typeof jid === 'string' && jid.endsWith('@g.us');
}

function extractText(message) {
  if (!message) return '';
  return (
    message.conversation ||
    (message.extendedTextMessage && message.extendedTextMessage.text) ||
    (message.imageMessage && message.imageMessage.caption) ||
    (message.videoMessage && message.videoMessage.caption) ||
    (message.documentMessage && message.documentMessage.caption) ||
    ''
  );
}

/**
 * createGuard(sock, deps)
 * deps = { config, logger, store, onDetection? }
 */
function createGuard(sock, deps) {
  const { config, logger, store } = deps;
  const T = mergeThresholds(DEFAULT_THRESHOLDS, config.thresholds || {});
  const act = config.actions || {};
  const dryRun = !!config.dryRun;
  const getGroupMeta = A.createGroupMetaCache(sock, logger);
  const notifyCooldown = new Map();
  const ownJid = (sock.user && sock.user.id) || '';
  const prefix = config.prefix || '.';

  const stats = { scanned: 0, flagged: 0, deleted: 0, blocked: 0, kicked: 0, reported: 0, errors: 0 };

  // reporting: capture the reporting token off the raw stanza, then report
  const tokenStore = new TokenStore(logger);
  let detachTokenCapture = () => {};
  const lastPoison = new Map(); // sender jid -> { message, key, timestampSec, chatJid }

  const reporter = new Reporter({
    sock,
    config,
    logger,
    store,
    tokenStore,
    notify: (lines) => notifyOwner(lines)
  });

  // ---------------------------------------------------------------- notify

  async function notifyOwner(lines) {
    if (!act.notifyOwner) return;
    const owners = (config.ownerNumbers || []).map((n) => String(n).replace(/[^0-9]/g, '')).filter(Boolean);
    if (!owners.length) return;
    const body = `${lines.join('\n')}`;
    for (const n of owners) {
      const jid = `${n}@s.whatsapp.net`;
      if (jid === ownJid) continue;
      const last = notifyCooldown.get(jid) || 0;
      if (Date.now() - last < 8000) continue;
      notifyCooldown.set(jid, Date.now());
      await A.safe(() => sock.sendMessage(jid, { text: body }), 'notifyOwner', logger);
    }
  }

  // ---------------------------------------------------------------- respond

  async function respondTo(msg, chatJid, result, sender) {
    const sev = result.severity;
    const group = isGroup(chatJid);
    const reasons = result.reasons.map((r) => `• ${r.code} — ${r.detail}`).join('\n');
    const logLine = `[${sev.toUpperCase()}] ${jidToNumber(sender)} in ${chatJid} :: ${summarize(result)}`;

    logger.warn(logLine);
    stats.flagged++;
    store.bump('flagged');

    if (dryRun) {
      logger.info('[dry-run] no action taken');
      await notifyOwner([
        `🧪 *${config.botName || 'Sachi AntiCrasher'}* (DRY RUN)`,
        `Severity: ${sev.toUpperCase()}  score: ${result.score}`,
        `Chat: ${chatJid}`,
        `Sender: ${jidToNumber(sender)}`,
        reasons
      ]);
      return;
    }

    const key = msg.key;
    const fromMe = !!key.fromMe;
    let meta = null;
    if (group) meta = await getGroupMeta(chatJid);
    const botAdmin = group ? A.isBotAdminIn(sock, meta) : false;

    // 1) ALWAYS remove the poison message from our own view first.
    //    This is the step that protects the phone / WhatsApp Web client.
    if (act.deleteForMe !== false) {
      const r = await A.safe(() => A.deleteForMe(sock, chatJid, key, msg.messageTimestamp), 'deleteForMe', logger);
      if (r !== null) {
        stats.deleted++;
        store.bump('deleted');
      }
    }

    // 2) If we can revoke for everyone (own message, or group admin) do it.
    if (act.revokeIfAdmin && (fromMe || botAdmin) && SEV_RANK[sev] >= SEV_RANK.high) {
      await A.safe(() => A.revokeForEveryone(sock, chatJid, key), 'revoke', logger);
    }

    // 3) Block the sender.
    if (!fromMe && act.blockOnHigh && SEV_RANK[sev] >= SEV_RANK.high && sender) {
      if (!store.isWhitelisted(sender)) {
        const r = await A.safe(() => A.blockSender(sock, sender), 'blockSender', logger);
        if (r !== null) {
          stats.blocked++;
          store.bump('blocked');
          store.markBlocked(sender);
        }
      }
    }

    // 4) Optional: kick from the group (needs admin rights).
    if (!fromMe && act.kickOnCritical && sev === 'critical' && group && botAdmin) {
      const r = await A.safe(() => A.kickFromGroup(sock, chatJid, sender), 'kick', logger);
      if (r !== null) {
        stats.kicked++;
        store.bump('kicked');
      }
    }

    // 5) Report the sender to WhatsApp (up to N attempts, in the background).
    if (!fromMe && reporter.enabled) {
      lastPoison.set(sender, {
        message: msg.message,
        key: { ...msg.key },
        timestampSec: msg.messageTimestamp,
        chatJid,
        severity: sev,
        at: Date.now()
      });
      if (lastPoison.size > 200) lastPoison.delete(lastPoison.keys().next().value);

      const queued = reporter.queue({
        message: msg.message,
        key: { ...msg.key },
        timestampSec: msg.messageTimestamp,
        senderJid: sender,
        chatJid,
        groupSubject: meta && meta.subject,
        severity: sev
      });
      if (queued.started) stats.reported++;
      else logger.info('report not queued', { why: queued.why });
    }

    await notifyOwner([
      `🚨 *${config.botName || 'Sachi AntiCrasher'}*`,
      `Severity: *${sev.toUpperCase()}*  score: ${result.score}`,
      `Chat: ${group ? 'group' : 'direct'} ${chatJid}`,
      `Sender: ${jidToNumber(sender)}${fromMe ? ' (you)' : ''}`,
      `Deleted for me: ${act.deleteForMe !== false ? 'yes' : 'no'}`,
      `Blocked: ${!fromMe && SEV_RANK[sev] >= SEV_RANK.high ? 'yes' : 'no'}`,
      `Report to WhatsApp: ${!fromMe && reporter.enabled ? 'queued' : 'off'}`,
      `Bot is group admin: ${botAdmin ? 'yes' : 'no'}`,
      'Reasons:',
      reasons
    ]);

    if (typeof deps.onDetection === 'function') {
      try {
        deps.onDetection({ chatJid, sender, result });
      } catch (e) {
        logger.debug('onDetection callback error', { error: String(e) });
      }
    }
  }

  // ---------------------------------------------------------------- core

  async function inspectMessage(msg, source = 'incoming') {
    if (!store.data.enabled) return null;
    if (!msg || !msg.key || !msg.message) return null;

    const chatJid = msg.key.remoteJid;
    if (!chatJid) return null;
    if (msg.messageStubType) return null; // system/notification message
    if (msg.message.protocolMessage) return null; // revokes, keys, ephemeral setup

    const sender = msg.key.participant || msg.key.remoteJid;
    const fromMe = !!msg.key.fromMe;

    // never fight with our own control commands
    const text = extractText(msg.message);
    if (text && text.trim().startsWith(prefix)) return null;

    if (store.isWhitelisted(chatJid) || store.isWhitelisted(sender)) return null;
    if (fromMe && act.guardOutgoing === false) return null;

    stats.scanned++;
    store.bump('scanned');

    const result = analyzeMessage(msg.message, { thresholds: T });

    if (!result.flagged) {
      logger.debug('clean message', { chatJid, severity: result.severity, score: result.score });
      return result;
    }

    // burst escalation: repeat offenders get treated harder
    const burst = store.hitSender(sender, T.burstWindowMs);
    if (burst.windowHits >= T.burstCount) result.severity = worse(result.severity, 'high');
    if (burst.total >= 5) result.severity = worse(result.severity, 'critical');
    if (result.severity !== 'none') result.flagged = true;

    await respondTo(msg, chatJid, result, sender);
    return result;
  }

  // ---------------------------------------------------------------- hooks

  async function onUpsert(upsert) {
    try {
      const type = upsert && upsert.type;
      if (type && type !== 'notify' && type !== 'append') return;
      const messages = (upsert && upsert.messages) || [];
      for (const msg of messages) {
        // one message must never break the batch
        try {
          await inspectMessage(msg);
        } catch (e) {
          stats.errors++;
          logger.error('inspect failed', { error: String(e && e.message ? e.message : e) });
        }
      }
    } catch (e) {
      stats.errors++;
      logger.error('upsert handler failed', { error: String(e && e.message ? e.message : e) });
    }
  }

  async function onGroupsUpdate(updates) {
    try {
      for (const u of updates || []) {
        const fields = ['subject', 'desc'];
        for (const f of fields) {
          const v = u[f];
          if (typeof v !== 'string' || !v) continue;
          const res = analyzeMessage({ conversation: v }, { thresholds: T });
          if (res.flagged && SEV_RANK[res.severity] >= SEV_RANK.medium) {
            logger.warn('poison group metadata', { groupJid: u.id, field: f, result: summarize(res) });
            await notifyOwner([
              `⚠️ *${config.botName || 'Sachi AntiCrasher'}*`,
              `Group ${f} looks like a crash payload.`,
              `Group: ${u.id}`,
              `Severity: ${res.severity.toUpperCase()}`,
              res.reasons.map((r) => `• ${r.code} — ${r.detail}`).join('\n')
            ]);
          }
        }
      }
    } catch (e) {
      logger.error('groups.update handler failed', { error: String(e) });
    }
  }

  async function onParticipantsUpdate(update) {
    try {
      if (!act.autoKickWatchlisted) return;
      if (!update || update.action !== 'add') return;
      const groupJid = update.id;
      const meta = await getGroupMeta(groupJid);
      if (!A.isBotAdminIn(sock, meta)) return;
      for (const p of update.participants || []) {
        if (config.addWatchlist && config.addWatchlist.includes(jidToNumber(p))) {
          await A.safe(() => A.kickFromGroup(sock, groupJid, p), 'kickWatchlisted', logger);
          logger.warn('kicked watchlisted number on add', { groupJid, participant: jidToNumber(p) });
        }
      }
    } catch (e) {
      logger.error('participants.update handler failed', { error: String(e) });
    }
  }

  // ---------------------------------------------------------------- outgoing

  let originalSend = null;
  function wrapOutgoing() {
    if (act.guardOutgoing === false || originalSend) return;
    originalSend = sock.sendMessage.bind(sock);
    sock.sendMessage = async (jid, content, options) => {
      try {
        if (content && typeof content === 'object' && !content.delete) {
          const res = analyzeMessage(content, { thresholds: T });
          if (res.flagged && SEV_RANK[res.severity] >= SEV_RANK.high) {
            logger.error('blocked outgoing poison payload', { jid, result: summarize(res) });
            throw new Error(`Sachi AntiCrasher: outgoing message looks like a crash payload (${res.severity})`);
          }
        }
      } catch (e) {
        if (String(e && e.message).includes('Sachi AntiCrasher')) throw e;
        // scanner failure must not stop normal sending
      }
      return originalSend(jid, content, options);
    };
  }

  function unwrapOutgoing() {
    if (originalSend) {
      sock.sendMessage = originalSend;
      originalSend = null;
    }
  }

  // ---------------------------------------------------------------- api

  function attach() {
    sock.ev.on('messages.upsert', onUpsert);
    sock.ev.on('groups.update', onGroupsUpdate);
    sock.ev.on('group-participants.update', onParticipantsUpdate);
    detachTokenCapture = attachTokenCapture(sock, tokenStore, logger);
    wrapOutgoing();
    logger.info(`${config.botName || 'Sachi AntiCrasher'} guard attached`, {
      dryRun,
      thresholds: { high: T.severity.high, critical: T.severity.critical }
    });
  }

  function detach() {
    try {
      sock.ev.off('messages.upsert', onUpsert);
      sock.ev.off('groups.update', onGroupsUpdate);
      sock.ev.off('group-participants.update', onParticipantsUpdate);
    } catch {
      /* ignore */
    }
    try {
      detachTokenCapture();
    } catch {
      /* ignore */
    }
    unwrapOutgoing();
  }

  /** manual report for the last poison message from a sender (owner command) */
  function reportLast(senderJid, severity) {
    const hit = lastPoison.get(senderJid);
    if (!hit) return { started: false, why: 'no poison message stored for this sender' };
    return reporter.queue({
      message: hit.message,
      key: hit.key,
      timestampSec: hit.timestampSec,
      senderJid,
      chatJid: hit.chatJid,
      severity: severity || hit.severity
    });
  }

  return {
    attach,
    detach,
    inspectMessage,
    analyze: (message) => analyzeMessage(message, { thresholds: T }),
    reportLast,
    reporter,
    tokenStore,
    stats: () => ({ ...stats, dryRun, thresholds: T, report: reporter.status() }),
    get thresholds() {
      return T;
    }
  };
}

module.exports = { createGuard, extractText, isGroup, jidToNumber };
