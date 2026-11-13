'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Tiny JSON state store.
 * Keeps: enabled flag, whitelist, block list (numbers the bot blocked),
 * counters and per-sender burst counters. Writes are debounced so a spam
 * burst cannot hammer the disk.
 */
class Store {
  constructor(file, logger) {
    this.file = file;
    this.logger = logger;
    this.data = {
      enabled: true,
      whitelistJids: [],
      whitelistNumbers: [],
      blockedByBot: [],
      stats: {
        scanned: 0,
        flagged: 0,
        deleted: 0,
        blocked: 0,
        kicked: 0,
        since: new Date().toISOString()
      },
      senders: {},
      reports: {},
      reportLog: []
    };
    this._dirty = false;
    this._timer = null;
    this.load();
  }

  load() {
    try {
      const raw = fs.readFileSync(this.file, 'utf8');
      const parsed = JSON.parse(raw);
      this.data = { ...this.data, ...parsed, stats: { ...this.data.stats, ...(parsed.stats || {}) } };
    } catch {
      /* first run */
    }
  }

  save(force = false) {
    this._dirty = true;
    if (force) return this._flush();
    if (this._timer) return;
    this._timer = setTimeout(() => {
      this._timer = null;
      this._flush();
    }, 3000);
    if (this._timer.unref) this._timer.unref();
  }

  _flush() {
    if (!this._dirty) return;
    this._dirty = false;
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      const tmp = `${this.file}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2));
      fs.renameSync(tmp, this.file);
    } catch (e) {
      this.logger && this.logger.warn('store save failed', { error: String(e) });
    }
  }

  // ---- whitelist ----
  isWhitelisted(jid) {
    if (!jid) return false;
    const num = String(jid).split('@')[0].split(':')[0];
    return (
      this.data.whitelistJids.includes(jid) ||
      this.data.whitelistNumbers.includes(num)
    );
  }

  addWhitelist(value) {
    const v = String(value).trim();
    if (!v) return false;
    if (v.includes('@')) {
      if (this.data.whitelistJids.includes(v)) return false;
      this.data.whitelistJids.push(v);
    } else {
      const num = v.replace(/[^0-9]/g, '');
      if (!num || this.data.whitelistNumbers.includes(num)) return false;
      this.data.whitelistNumbers.push(num);
    }
    this.save(true);
    return true;
  }

  removeWhitelist(value) {
    const v = String(value).trim();
    const num = v.replace(/[^0-9]/g, '');
    const beforeJ = this.data.whitelistJids.length;
    const beforeN = this.data.whitelistNumbers.length;
    this.data.whitelistJids = this.data.whitelistJids.filter((j) => j !== v);
    this.data.whitelistNumbers = this.data.whitelistNumbers.filter((n) => n !== num);
    const changed = beforeJ !== this.data.whitelistJids.length || beforeN !== this.data.whitelistNumbers.length;
    if (changed) this.save(true);
    return changed;
  }

  // ---- block list ----
  markBlocked(jid) {
    if (!this.data.blockedByBot.includes(jid)) {
      this.data.blockedByBot.push(jid);
      if (this.data.blockedByBot.length > 500) this.data.blockedByBot.shift();
      this.save();
    }
  }

  // ---- counters ----
  bump(key, n = 1) {
    this.data.stats[key] = (this.data.stats[key] || 0) + n;
    this.save();
  }

  /** record a detection for a sender and return how many in the window */
  hitSender(jid, windowMs) {
    const now = Date.now();
    const rec = this.data.senders[jid] || { hits: [], total: 0 };
    rec.hits = rec.hits.filter((t) => now - t < windowMs);
    rec.hits.push(now);
    rec.total = (rec.total || 0) + 1;
    this.data.senders[jid] = rec;
    // prune old senders
    const keys = Object.keys(this.data.senders);
    if (keys.length > 1000) {
      for (const k of keys.slice(0, 200)) delete this.data.senders[k];
    }
    this.save();
    return { windowHits: rec.hits.length, total: rec.total };
  }

  senderTotal(jid) {
    const rec = this.data.senders[jid];
    return rec ? rec.total || 0 : 0;
  }

  // ---- reporting ----
  /** how many report attempts we made for this sender inside the window */
  reportCount(jid, windowMs) {
    const rec = this.data.reports[jid];
    if (!rec || !Array.isArray(rec.history)) return 0;
    const cutoff = Date.now() - windowMs;
    return rec.history.filter((h) => new Date(h.at).getTime() >= cutoff).length;
  }

  /** attempts across all senders inside the window (abuse guard) */
  globalReportCount(windowMs) {
    const cutoff = Date.now() - windowMs;
    return (this.data.reportLog || []).filter((t) => t >= cutoff).length;
  }

  recordReport(jid, entry) {
    const rec = this.data.reports[jid] || { history: [], accepted: 0, lastAt: null };
    rec.history.push(entry);
    if (rec.history.length > 20) rec.history.shift();
    rec.lastAt = entry.at;
    if (entry.ok) rec.accepted = (rec.accepted || 0) + 1;
    rec.lastReportId = entry.reportId || rec.lastReportId || null;
    this.data.reports[jid] = rec;

    this.data.reportLog = (this.data.reportLog || []).concat(Date.now()).slice(-200);
    this.save();
  }

  getReport(jid) {
    return this.data.reports[jid] || null;
  }

  reportSummary(limit = 10) {
    return Object.entries(this.data.reports || {})
      .sort((a, b) => new Date(b[1].lastAt || 0) - new Date(a[1].lastAt || 0))
      .slice(0, limit)
      .map(([jid, rec]) => ({
        jid,
        attempts: rec.history.length,
        accepted: rec.accepted || 0,
        lastAt: rec.lastAt,
        reportId: rec.lastReportId || null
      }));
  }

  snapshot() {
    return {
      enabled: this.data.enabled,
      stats: { ...this.data.stats },
      blockedByBot: [...this.data.blockedByBot],
      whitelistJids: [...this.data.whitelistJids],
      whitelistNumbers: [...this.data.whitelistNumbers],
      reports: this.reportSummary(10)
    };
  }
}

module.exports = { Store };
