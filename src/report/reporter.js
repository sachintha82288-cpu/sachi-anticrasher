'use strict';

/**
 * Report policy + retry orchestration.
 *
 * Reality check (why this is "attempts", not "guaranteed"):
 *   WhatsApp has no public report API. A report is a `spam` IQ that the server
 *   only honours when it carries a valid reporting token for the message, and
 *   WhatsApp de-duplicates repeated reports of the same sender. So:
 *     - we try up to `attempts` times (default 3), spaced out
 *     - we stop early as soon as the server returns a report id
 *       (mode: 'untilAccepted'), because hammering an accepted report is
 *       exactly the "abuse reporting tools" pattern that gets an account
 *       limited. Set mode: 'always' if you really want all 3 sent.
 *     - every attempt is logged with the server's answer, so you can see what
 *       actually happened instead of assuming it worked.
 */

const { sendSpamReport, getProto } = require('./report');

function jidToNumber(jid) {
  return String(jid || '').split('@')[0].split(':')[0];
}

const DEFAULT_REPORT_CONFIG = {
  enabled: true,
  attempts: 3,
  mode: 'untilAccepted', // 'untilAccepted' | 'always'
  delaysMs: [15000, 45000, 120000],
  minSeverity: 'high',
  perSenderDailyCap: 3,
  globalHourlyCap: 20,
  flows: null // optional override: { user: 'MessageMenu', group: 'GroupInfoReport' }
};

const SEV_RANK = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

function sleep(ms) {
  // deliberately NOT unref'd: a pending report attempt should keep the
  // process alive until it has run (the WhatsApp socket normally does anyway)
  return new Promise((r) => setTimeout(r, ms));
}

class Reporter {
  constructor({ sock, config, logger, store, tokenStore, notify }) {
    this.sock = sock;
    this.config = config;
    this.logger = logger;
    this.store = store;
    this.tokenStore = tokenStore;
    this.notify = notify || (async () => {});
    this.cfg = { ...DEFAULT_REPORT_CONFIG, ...(config.report || {}) };
    this.stats = { queued: 0, attempts: 0, accepted: 0, failed: 0, skipped: 0 };
    this.inFlight = new Set();
    this.proto = null;
    try {
      this.proto = getProto();
    } catch {
      this.proto = null;
    }
  }

  get enabled() {
    return this.cfg.enabled !== false && this.config.actions?.reportToWhatsApp !== false;
  }

  /** Gate before we spend an attempt. */
  canReport({ senderJid, severity }) {
    if (!this.enabled) return { ok: false, why: 'reporting disabled' };
    if (!senderJid) return { ok: false, why: 'no sender jid' };
    if (SEV_RANK[severity] < SEV_RANK[this.cfg.minSeverity]) {
      return { ok: false, why: `severity ${severity} below ${this.cfg.minSeverity}` };
    }
    if (this.inFlight.has(senderJid)) return { ok: false, why: 'report already running for this sender' };
    if (this.store.reportCount(senderJid, 24 * 3600 * 1000) >= this.cfg.perSenderDailyCap) {
      return { ok: false, why: 'daily cap reached for this sender' };
    }
    if (this.store.globalReportCount(3600 * 1000) >= this.cfg.globalHourlyCap) {
      return { ok: false, why: 'hourly global cap reached' };
    }
    return { ok: true };
  }

  /**
   * Queue a report for a detected message. Returns immediately; attempts run
   * in the background so the guard never blocks on a 2-minute retry chain.
   */
  queue(job) {
    const gate = this.canReport({ senderJid: job.senderJid, severity: job.severity });
    if (!gate.ok) {
      this.stats.skipped++;
      this.logger.info('report skipped', { sender: jidToNumber(job.senderJid), why: gate.why });
      return { started: false, why: gate.why };
    }
    this.stats.queued++;
    this.inFlight.add(job.senderJid);
    this.run(job)
      .catch((e) => this.logger.error('report chain failed', { error: String(e && e.message ? e.message : e) }))
      .finally(() => this.inFlight.delete(job.senderJid));
    return { started: true };
  }

  async run(job) {
    const number = jidToNumber(job.senderJid);
    const attempts = Math.max(1, Number(this.cfg.attempts) || 3);
    const delays = Array.isArray(this.cfg.delaysMs) ? this.cfg.delaysMs : DEFAULT_REPORT_CONFIG.delaysMs;
    const results = [];

    this.logger.info(`reporting ${number} (up to ${attempts}x)`, {
      severity: job.severity,
      messageId: job.key && job.key.id,
      hasToken: !!(this.tokenStore && this.tokenStore.has(job.key && job.key.id))
    });

    for (let i = 0; i < attempts; i++) {
      if (i > 0) {
        const wait = Number(delays[Math.min(i - 1, delays.length - 1)]) || 30000;
        await sleep(wait);
      }

      const capturedToken = this.tokenStore ? this.tokenStore.get(job.key.id) : null;

      let res;
      try {
        this.stats.attempts++;
        res = await sendSpamReport(this.sock, {
          message: job.message,
          key: job.key,
          timestampSec: job.timestampSec,
          senderJid: job.senderJid,
          chatJid: job.chatJid,
          groupSubject: job.groupSubject,
          flow: job.flow || (this.cfg.flows && (job.chatJid || '').endsWith('@g.us') ? this.cfg.flows.group : this.cfg.flows && this.cfg.flows.user),
          capturedToken,
          proto: this.proto
        });
      } catch (e) {
        res = { ok: false, reason: String(e && e.message ? e.message : e) };
      }

      const entry = {
        at: new Date().toISOString(),
        attempt: i + 1,
        ok: !!res.ok,
        reportId: res.reportId || null,
        errorCode: res.errorCode || null,
        errorText: res.errorText || res.reason || null
      };
      results.push(entry);
      this.store.recordReport(job.senderJid, entry);

      if (res.ok) {
        this.stats.accepted++;
        this.store.bump('reports');
        this.logger.info(`report accepted (${entry.attempt}/${attempts})`, {
          sender: number,
          reportId: entry.reportId
        });
      } else {
        this.stats.failed++;
        this.logger.warn(`report attempt ${entry.attempt}/${attempts} failed`, {
          sender: number,
          reason: entry.errorText,
          code: entry.errorCode
        });
      }

      if (res.ok && this.cfg.mode === 'untilAccepted') break;
    }

    const accepted = results.filter((r) => r.ok).length;
    const last = results[results.length - 1] || {};

    await this.notify([
      accepted ? '✅ *Report sent to WhatsApp*' : '⚠️ *Report could not be confirmed*',
      `Number: ${number}`,
      `Attempts: ${results.length}/${attempts}  accepted: ${accepted}`,
      accepted ? `Report ID: ${results.find((r) => r.ok).reportId}` : `Last error: ${last.errorText || 'unknown'}`,
      accepted
        ? 'WhatsApp has the report. Keep the number blocked.'
        : 'WhatsApp did not confirm. Report manually from the chat menu as a backup.'
    ]);

    return results;
  }

  status() {
    return {
      ...this.stats,
      enabled: this.enabled,
      attempts: this.cfg.attempts,
      mode: this.cfg.mode,
      tokens: this.tokenStore ? this.tokenStore.stats() : null
    };
  }
}

module.exports = { Reporter, DEFAULT_REPORT_CONFIG };
