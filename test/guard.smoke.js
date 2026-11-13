'use strict';

/**
 * Integration smoke test - no WhatsApp connection.
 * A fake Baileys socket records what the guard does with a poison message.
 *
 *   node test/guard.smoke.js
 */

const os = require('os');
const path = require('path');
const fs = require('fs');

const { createGuard } = require('../src/guard');
const { Store } = require('../src/store');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ac-'));
const logger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
  file: path.join(tmp, 'x.log')
};

let pass = 0;
let fail = 0;
function check(name, cond, extra) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}${extra ? ' :: ' + extra : ''}`);
  }
}

function fakeSock() {
  const calls = { chatModify: [], sendMessage: [], block: [], kick: [], groupMetadata: 0, query: [] };
  const handlers = {};
  const sock = {
    user: { id: '94770000000:1@s.whatsapp.net' },
    ev: {
      on: (ev, fn) => {
        (handlers[ev] ||= []).push(fn);
      },
      off: () => {}
    },
    chatModify: async (mod, jid) => {
      calls.chatModify.push({ mod, jid });
      return {};
    },
    sendMessage: async (jid, content) => {
      calls.sendMessage.push({ jid, content });
      return {};
    },
    updateBlockStatus: async (jid, action) => {
      calls.block.push({ jid, action });
      return {};
    },
    groupParticipantsUpdate: async (jid, participants, action) => {
      calls.kick.push({ jid, participants, action });
      return {};
    },
    query: async (node) => {
      calls.query.push(node);
      return { tag: 'iq', attrs: { type: 'result' }, content: [{ tag: 'report_id', content: 'RID-SMOKE' }] };
    },
    groupMetadata: async (jid) => {
      calls.groupMetadata++;
      return {
        id: jid,
        participants: [
          { id: '94770000000@s.whatsapp.net', admin: 'admin' },
          { id: '94711111111@s.whatsapp.net', admin: null }
        ]
      };
    }
  };
  return { sock, calls, handlers };
}

const config = {
  botName: 'Sachi AntiCrasher',
  prefix: '.',
  ownerNumbers: ['94770000000'],
  dryRun: false,
  actions: {
    deleteForMe: true,
    revokeIfAdmin: true,
    blockOnHigh: true,
    kickOnCritical: false,
    notifyOwner: false,
    guardOutgoing: true
  },
  report: { enabled: true, attempts: 1, delaysMs: [1], mode: 'untilAccepted', minSeverity: 'high' },
  thresholds: {}
};

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

function msg(text, opts = {}) {
  return {
    key: {
      remoteJid: opts.chat || '94711111111@s.whatsapp.net',
      fromMe: !!opts.fromMe,
      id: 'TESTID' + Math.random().toString(36).slice(2, 8),
      participant: opts.participant
    },
    messageTimestamp: Math.floor(Date.now() / 1000),
    message: typeof text === 'string' ? { conversation: text } : text
  };
}

async function main() {
  console.log('guard smoke test');

  // ---- 1. poison in a DM ----
  {
    const { sock, calls, handlers } = fakeSock();
    const store = new Store(path.join(tmp, 'state1.json'), logger);
    const guard = createGuard(sock, { config, logger, store });
    guard.attach();

    await handlers['messages.upsert'][0]({
      type: 'notify',
      messages: [
        msg({
          conversation: '\u200B'.repeat(5000),
          messageContextInfo: { messageSecret: require('crypto').randomBytes(32) }
        })
      ]
    });
    await wait(80);

    check('poison message deleted for me', calls.chatModify.length === 1);
    check('delete used chatModify clear', !!(calls.chatModify[0] && calls.chatModify[0].mod.clear));
    check('sender blocked', calls.block.length === 1 && calls.block[0].action === 'block');
    check('blocked jid is the sender', calls.block[0] && calls.block[0].jid === '94711111111@s.whatsapp.net');
    check('block list recorded', store.data.blockedByBot.includes('94711111111@s.whatsapp.net'));
    check('flagged counter', guard.stats().flagged === 1);
    check('report iq sent to WhatsApp', calls.query.length === 1);
    check('report recorded in store', !!store.getReport('94711111111@s.whatsapp.net'));
    check('report accepted', guard.stats().report.accepted === 1);
  }

  // ---- 2. clean message untouched ----
  {
    const { sock, calls, handlers } = fakeSock();
    const store = new Store(path.join(tmp, 'state2.json'), logger);
    const guard = createGuard(sock, { config, logger, store });
    guard.attach();

    await handlers['messages.upsert'][0]({ type: 'notify', messages: [msg('hello, kohomada?')] });
    check('clean message: no delete', calls.chatModify.length === 0);
    check('clean message: no block', calls.block.length === 0);
    check('clean message: scanned counter', guard.stats().scanned === 1);
  }

  // ---- 3. whitelisted sender is never touched ----
  {
    const { sock, calls, handlers } = fakeSock();
    const store = new Store(path.join(tmp, 'state3.json'), logger);
    store.addWhitelist('94711111111');
    const guard = createGuard(sock, { config, logger, store });
    guard.attach();

    await handlers['messages.upsert'][0]({ type: 'notify', messages: [msg('\u0000'.repeat(50))] });
    check('whitelisted sender skipped', calls.chatModify.length === 0 && calls.block.length === 0);
  }

  // ---- 4. group: revoke when bot is admin ----
  {
    const { sock, calls, handlers } = fakeSock();
    const store = new Store(path.join(tmp, 'state4.json'), logger);
    const guard = createGuard(sock, { config, logger, store });
    guard.attach();

    await handlers['messages.upsert'][0]({
      type: 'notify',
      messages: [
        msg('\u202E'.repeat(3000), {
          chat: '120363000000000000@g.us',
          participant: '94722222222@s.whatsapp.net'
        })
      ]
    });

    check('group poison deleted for me', calls.chatModify.length === 1);
    check('group poison revoked for everyone', calls.sendMessage.some((c) => c.content && c.content.delete));
    check('group poison sender blocked', calls.block.length === 1);
  }

  // ---- 5. dry run takes no action ----
  {
    const { sock, calls, handlers } = fakeSock();
    const store = new Store(path.join(tmp, 'state5.json'), logger);
    const guard = createGuard(sock, { config: { ...config, dryRun: true }, logger, store });
    guard.attach();

    await handlers['messages.upsert'][0]({ type: 'notify', messages: [msg('\u200B'.repeat(5000))] });
    check('dry run: no delete', calls.chatModify.length === 0);
    check('dry run: no block', calls.block.length === 0);
    check('dry run: still counted as flagged', guard.stats().flagged === 1);
  }

  // ---- 6. outgoing guard ----
  {
    const { sock } = fakeSock();
    const store = new Store(path.join(tmp, 'state6.json'), logger);
    const guard = createGuard(sock, { config, logger, store });
    guard.attach();

    let threw = false;
    try {
      await sock.sendMessage('94733333333@s.whatsapp.net', { text: '\u0000'.repeat(80) });
    } catch (e) {
      threw = true;
    }
    check('outgoing poison payload rejected', threw);

    const ok = await sock.sendMessage('94733333333@s.whatsapp.net', { text: 'normal reply' });
    check('outgoing clean payload allowed', ok !== null);
  }

  // ---- 7. protocol / system messages ignored ----
  {
    const { sock, calls, handlers } = fakeSock();
    const store = new Store(path.join(tmp, 'state7.json'), logger);
    const guard = createGuard(sock, { config, logger, store });
    guard.attach();

    const revoke = msg({ protocolMessage: { type: 0, key: { id: 'X' } } });
    await handlers['messages.upsert'][0]({ type: 'notify', messages: [revoke] });
    check('revoke protocol message ignored', calls.chatModify.length === 0);

    const sys = msg('x');
    sys.messageStubType = 1;
    await handlers['messages.upsert'][0]({ type: 'notify', messages: [sys] });
    check('system stub message ignored', calls.chatModify.length === 0);
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail) process.exitCode = 1;
  try {
    fs.rmSync(tmp, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
