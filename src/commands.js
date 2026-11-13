'use strict';

const { summarize } = require('./detector');
const A = require('./actions');
const { jidToNumber } = require('./guard');

const HELP = `🛡️ *Sachi AntiCrasher* — උදව්

*පොදු*
• \`{p}ac status\` — bot එකේ තත්වය
• \`{p}ac stats\` — සංඛ්‍යා ලේඛන
• \`{p}ac on\` / \`{p}ac off\` — ආරක්ෂාව on/off
• \`{p}ac dryrun on|off\` — block නොකර test mode

*පරීක්ෂාව*
• \`{p}ac scan\` — මැසේජ් එකකට reply කරලා යවන්න (scan කරලා පෙන්නනවා)
• \`{p}ac thresholds\` — දැන් පාවිච්චි වෙන limits

*Whitelist (කවදාවත් block නොකරන අය)*
• \`{p}ac wl add 94771234567\`
• \`{p}ac wl del 94771234567\`
• \`{p}ac wl list\`

*Report (WhatsApp ට report කිරීම)*
• \`{p}ac report on|off\` — auto report on/off
• \`{p}ac report now\` — අන්තිම bug එක එවපු number එක report
• \`{p}ac reports\` — report ඉතිහාසය

*Block list*
• \`{p}ac blocklist\` — bot block කරපු numbers
• \`{p}ac unblock 94771234567\`

*අතින්*
• \`{p}ac block 94771234567\`
• \`{p}ac block @user\` (reply කරලා)`;

function createCommands(ctx) {
  const { config, store, guard, logger } = ctx;
  const p = config.prefix || '.';

  function isOwner(sender) {
    const owners = config.ownerNumbers || [];
    if (!owners.length) return true; // nobody configured -> the linked number is the owner
    return owners.includes(jidToNumber(sender));
  }

  async function reply(msg, text) {
    const jid = msg.key.remoteJid;
    await A.safe(() => ctx.sock.sendMessage(jid, { text }, { quoted: msg }), 'commandReply', logger);
  }

  function parse(body) {
    return body.trim().slice(p.length).split(/\s+/);
  }

  async function handle(msg) {
    const text = ctx.extractText(msg.message);
    if (!text || !text.trim().startsWith(p)) return false;
    const body = text.trim();
    if (!/^[a-zA-Z]/.test(body.slice(p.length))) return false;

    const args = parse(body);
    const cmd = (args[0] || '').toLowerCase();
    if (cmd !== 'ac' && cmd !== 'anticrash') return false;

    const sender = msg.key.participant || msg.key.remoteJid;
    if (!isOwner(sender)) {
      await reply(msg, '⛔ මේ command එක owner ට විතරයි.');
      return true;
    }

    const sub = (args[1] || 'help').toLowerCase();

    switch (sub) {
      case 'help':
      case 'menu': {
        await reply(msg, HELP.replace(/\{p\}/g, p));
        return true;
      }
      case 'status': {
        const s = guard.stats();
        await reply(
          msg,
          [
            `🛡️ *${config.botName}*`,
            `ආරක්ෂාව: ${store.data.enabled ? '✅ ON' : '❌ OFF'}`,
            `Test mode (dry run): ${s.dryRun ? '✅ ON — block කරන්නේ නෑ' : '❌ OFF'}`,
            `Scan කරපු: ${s.scanned}`,
            `හඳුනාගත්තු: ${s.flagged}`,
            `Delete කරපු: ${s.deleted}`,
            `Block කරපු: ${s.blocked}`,
            `Report (auto): ${s.report && s.report.enabled ? '✅ ON' : '❌ OFF'} — ${s.report ? `${s.report.attempts}x / ${s.report.mode}` : ''}`,
            `Report accepted: ${s.report ? s.report.accepted : 0} | failed: ${s.report ? s.report.failed : 0}`,
            `Tokens captured: ${s.report && s.report.tokens ? s.report.tokens.captured : 0}`,
            `High limit: ${s.thresholds.severity.high} | Critical: ${s.thresholds.severity.critical}`
          ].join('\n')
        );
        return true;
      }
      case 'stats': {
        const st = store.data.stats;
        const top = Object.entries(store.data.senders || {})
          .sort((a, b) => (b[1].total || 0) - (a[1].total || 0))
          .slice(0, 5)
          .map(([jid, r], i) => `${i + 1}. ${jidToNumber(jid)} — ${r.total}`)
          .join('\n');
        await reply(
          msg,
          [
            `📊 *සංඛ්‍යා* (${st.since || '-'} සිට)`,
            `Scan: ${st.scanned || 0}`,
            `Flagged: ${st.flagged || 0}`,
            `Deleted: ${st.deleted || 0}`,
            `Blocked: ${st.blocked || 0}`,
            `Kicked: ${st.kicked || 0}`,
            top ? `\n*වැඩිපුර යවපු අය:*\n${top}` : ''
          ].filter(Boolean).join('\n')
        );
        return true;
      }
      case 'on':
      case 'off': {
        store.data.enabled = sub === 'on';
        store.save(true);
        await reply(msg, `ආරක්ෂාව ${sub === 'on' ? '✅ ON' : '❌ OFF'}`);
        return true;
      }
      case 'dryrun': {
        const v = (args[2] || '').toLowerCase();
        const on = v === 'on' || v === 'true' || v === '1';
        const off = v === 'off' || v === 'false' || v === '0';
        if (!on && !off) {
          await reply(msg, `දැන්: ${config.dryRun ? 'ON' : 'OFF'}\nභාවිතය: ${p}ac dryrun on|off`);
          return true;
        }
        config.dryRun = on;
        await reply(msg, `Test mode ${on ? '✅ ON (block කරන්නේ නෑ)' : '❌ OFF (සැබෑ actions)'}`);
        return true;
      }
      case 'scan': {
        const quoted = msg.message.extendedTextMessage && msg.message.extendedTextMessage.contextInfo
          ? msg.message.extendedTextMessage.contextInfo.quotedMessage
          : null;
        if (!quoted) {
          await reply(msg, `මැසේජ් එකකට *reply* කරලා \`${p}ac scan\` යවන්න.`);
          return true;
        }
        const res = guard.analyze(quoted);
        const lines = [
          res.flagged ? `🚨 *FLAGGED* — ${res.severity.toUpperCase()}` : '✅ *CLEAN*',
          `Score: ${res.score}`,
          `Text: ${res.stats.maxTextLength || 0} chars`,
          `Control: ${res.stats.control || 0} | Bidi: ${res.stats.bidi || 0} | Zero-width: ${res.stats.zeroWidth || 0} | Combining: ${res.stats.combining || 0}`,
          `Mentions: ${res.stats.mentions || 0} | ~proto: ${res.stats.protoEstimate || 0} bytes`,
          res.reasons.length ? '\n*Reasons:*\n' + res.reasons.map((r) => `• ${r.code} (${r.weight}) — ${r.detail}`).join('\n') : ''
        ];
        await reply(msg, lines.filter(Boolean).join('\n'));
        return true;
      }
      case 'thresholds': {
        const t = guard.thresholds;
        await reply(
          msg,
          [
            '⚙️ *Limits*',
            `Text flag/critical: ${t.textLengthFlag} / ${t.textLengthCritical}`,
            `Bidi: ${t.bidiFlag} / ${t.bidiCritical}`,
            `Zero-width: ${t.zeroWidthFlag} / ${t.zeroWidthCritical}`,
            `Combining: ${t.combiningFlag} / ${t.combiningCritical}`,
            `Mentions: ${t.mentionFlag} / ${t.mentionCritical}`,
            `vCard chars: ${t.vcardLengthFlag} / ${t.vcardLengthCritical}`,
            `vCard contacts: ${t.vcardCountFlag} / ${t.vcardCountCritical}`,
            `List rows: ${t.rowCountFlag} | Carousel cards: ${t.cardCountFlag}`,
            `proto bytes: ${t.protoSizeFlag} / ${t.protoSizeCritical}`,
            `Depth: ${t.maxDepth} | Nodes: ${t.maxNodes}`
          ].join('\n')
        );
        return true;
      }
      case 'wl':
      case 'whitelist': {
        const op = (args[2] || 'list').toLowerCase();
        const val = args[3];
        if (op === 'add') {
          if (!val) return (await reply(msg, `භාවිතය: ${p}ac wl add 94771234567`)), true;
          const ok = store.addWhitelist(val);
          await reply(msg, ok ? `✅ Whitelist එකට එකතු කළා: ${val}` : '⚠️ දැනටමත් ඒකේ ඉන්නවා.');
          return true;
        }
        if (op === 'del' || op === 'remove') {
          if (!val) return (await reply(msg, `භාවිතය: ${p}ac wl del 94771234567`)), true;
          const ok = store.removeWhitelist(val);
          await reply(msg, ok ? `🗑️ අයින් කළා: ${val}` : '⚠️ හම්බුණේ නෑ.');
          return true;
        }
        const snap = store.snapshot();
        await reply(
          msg,
          `📋 *Whitelist*\n${[...snap.whitelistNumbers, ...snap.whitelistJids].map((x) => `• ${x}`).join('\n') || '(හිස්)'}`
        );
        return true;
      }
      case 'report': {
        const op = (args[2] || 'status').toLowerCase();

        if (op === 'on' || op === 'off') {
          config.report = config.report || {};
          config.report.enabled = op === 'on';
          if (guard.reporter) guard.reporter.cfg.enabled = op === 'on';
          await reply(msg, `Report to WhatsApp ${op === 'on' ? '✅ ON' : '❌ OFF'}`);
          return true;
        }

        if (op === 'now' || op === 'manual') {
          let target = (args[3] || '').replace(/[^0-9]/g, '');
          const quotedParticipant =
            msg.message.extendedTextMessage &&
            msg.message.extendedTextMessage.contextInfo &&
            msg.message.extendedTextMessage.contextInfo.participant;
          if (!target && quotedParticipant) target = jidToNumber(quotedParticipant);
          if (!target) {
            await reply(msg, `භාවිතය: ${p}ac report now 94771234567 (හෝ bug මැසේජ් එකට reply කරන්න)`);
            return true;
          }
          const jid = `${target}@s.whatsapp.net`;
          const r = guard.reportLast(jid, 'critical');
          await reply(
            msg,
            r.started
              ? `📤 Report queue කළා: ${target}\nප්‍රතිඵලය විනාඩියක් ඇතුලත alert එකක් විදිහට එයි.`
              : `⚠️ Report කරන්න බැරි වුණා: ${r.why}`
          );
          return true;
        }

        if (op === 'list' || op === 'history' || op === 'reports') {
          const rows = store.reportSummary(10);
          await reply(
            msg,
            `📋 *Reports*\n${
              rows
                .map(
                  (r) =>
                    `• ${jidToNumber(r.jid)} — ${r.attempts} attempts, ${r.accepted} accepted${r.reportId ? `\n  id: ${r.reportId}` : ''}`
                )
                .join('\n') || '(හිස්)'
            }`
          );
          return true;
        }

        const s = guard.reporter ? guard.reporter.status() : null;
        await reply(
          msg,
          [
            '📤 *Report settings*',
            `Auto report: ${s && s.enabled ? '✅ ON' : '❌ OFF'}`,
            `Attempts: ${s ? s.attempts : '-'} (mode: ${s ? s.mode : '-'})`,
            `Accepted: ${s ? s.accepted : 0} | Failed: ${s ? s.failed : 0} | Skipped: ${s ? s.skipped : 0}`,
            `Tokens captured: ${s && s.tokens ? s.tokens.captured : 0}`,
            '',
            `භාවිතය: ${p}ac report on|off|now|list`
          ].join('\n')
        );
        return true;
      }
      case 'blocklist': {
        const snap = store.snapshot();
        await reply(
          msg,
          `🚫 *Bot block කරපු numbers* (${snap.blockedByBot.length})\n${snap.blockedByBot.slice(-30).map((x) => `• ${jidToNumber(x)}`).join('\n') || '(හිස්)'}`
        );
        return true;
      }
      case 'block':
      case 'unblock': {
        let target = (args[2] || '').replace(/[^0-9]/g, '');
        const quotedParticipant =
          msg.message.extendedTextMessage &&
          msg.message.extendedTextMessage.contextInfo &&
          msg.message.extendedTextMessage.contextInfo.participant;
        if (!target && quotedParticipant) target = jidToNumber(quotedParticipant);
        if (!target) {
          await reply(msg, `භාවිතය: ${p}ac ${sub} 94771234567 (හෝ reply කරන්න)`);
          return true;
        }
        const jid = `${target}@s.whatsapp.net`;
        const r = await A.safe(
          () => (sub === 'block' ? A.blockSender(ctx.sock, jid) : A.unblockSender(ctx.sock, jid)),
          sub,
          logger
        );
        await reply(msg, r === null ? '⚠️ කරන්න බැරි වුණා.' : `${sub === 'block' ? '🚫 Block කළා' : '✅ Unblock කළා'}: ${target}`);
        return true;
      }
      case 'test': {
        // local self-test, no WhatsApp traffic
        const sample = { conversation: 'a'.repeat(50) };
        const res = guard.analyze(sample);
        await reply(msg, `Self-test OK. clean sample => ${summarize(res)}`);
        return true;
      }
      default:
        await reply(msg, `හඳුනාගත්තේ නෑ: ${sub}\n\n${p}ac help`);
        return true;
    }
  }

  return { handle, isOwner, HELP };
}

module.exports = { createCommands };
