'use strict';

/**
 * Reporting module tests - no network, no WhatsApp.
 *
 *   node test/report.test.js
 */

const os = require('os');
const path = require('path');
const fs = require('fs');
const { randomBytes } = require('crypto');

const token = require('../src/report/token');
const { buildSpamReportNode, extractReportResult, sendSpamReport } = require('../src/report/report');
const { TokenStore } = require('../src/report/token-store');
const { Reporter } = require('../src/report/reporter');
const { Store } = require('../src/store');

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

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ac-report-'));
const logger = { debug() {}, info() {}, warn() {}, error() {}, file: path.join(tmp, 'x.log') };

// ---------------------------------------------------------------- fixtures

function makeMessage(text = 'hello') {
  return {
    conversation: text,
    messageContextInfo: { messageSecret: randomBytes(32) }
  };
}

function makeKey(overrides = {}) {
  return {
    remoteJid: '94711111111@s.whatsapp.net',
    fromMe: false,
    id: '3EB0ABCDEF1234567890',
    ...overrides
  };
}

// ---------------------------------------------------------------- 1. token

async function testToken() {
  console.log('\nreporting key derivation');

  const messageSecret = randomBytes(32);
  const messageId = '3EB0ABCDEF1234567890';
  const from = '94711111111@s.whatsapp.net';
  const to = '94770000000@s.whatsapp.net';

  const mine = token.deriveReportingKey({ messageId, from, to, messageSecret });

  // Baileys' own hkdf must produce the same 32 bytes
  const baileys = require('@whiskeysockets/baileys');
  const useCaseSecret = Buffer.concat([
    Buffer.from(messageId, 'utf8'),
    Buffer.from(from, 'utf8'),
    Buffer.from(to, 'utf8'),
    Buffer.from('Report Token', 'utf8')
  ]);
  const theirs = await baileys.hkdf(messageSecret, 32, { info: useCaseSecret.toString('latin1') });

  check('derived key is 32 bytes', mine.length === 32, `got ${mine.length}`);
  check('matches Baileys hkdf output', Buffer.compare(mine, Buffer.from(theirs)) === 0);

  check('missing messageSecret -> null', token.deriveReportingKey({ messageId, from, to }) === null);
  check('missing id -> null', token.deriveReportingKey({ from, to, messageSecret }) === null);

  // endpoints: incoming message, fromMe=false
  const e1 = token.tokenEndpoints({ remoteJid: to, participant: from, fromMe: false });
  check('incoming endpoints from=sender to=us', e1.from === from && e1.to === to, JSON.stringify(e1));

  // our own outgoing message
  const e2 = token.tokenEndpoints({ remoteJid: to, fromMe: true });
  check('outgoing endpoints from=us to=them', e2.from === to && e2.to === to, JSON.stringify(e2));

  // token over a real encoded protobuf is 16 bytes and deterministic
  const baileysProto = baileys.proto;
  const message = makeMessage('crash test');
  const raw = Buffer.from(baileysProto.Message.encode(message).finish());
  const t1 = token.computeReportingToken(mine, raw);
  const t2 = token.computeReportingToken(mine, raw);
  check('token is 16 bytes', t1 && t1.length === 16, t1 ? String(t1.length) : 'null');
  check('token is deterministic', Buffer.compare(t1, t2) === 0);
  check('different key -> different token', Buffer.compare(t1, token.computeReportingToken(randomBytes(32), raw)) !== 0);
}

// ---------------------------------------------------------------- 2. node

function testNode() {
  console.log('\nreport stanza');

  const proto = require('@whiskeysockets/baileys').proto;
  const message = makeMessage('poison');
  const key = makeKey();
  const capturedToken = randomBytes(16);

  const built = buildSpamReportNode({
    message,
    key,
    timestampSec: 1700000000,
    senderJid: key.remoteJid,
    chatJid: key.remoteJid,
    capturedToken,
    proto,
    iqId: 'TESTIQ'
  });

  check('node built', !!built.node, built.reason);
  const iq = built.node;
  check('iq is type set to s.whatsapp.net', iq.tag === 'iq' && iq.attrs.type === 'set' && iq.attrs.to === 's.whatsapp.net');
  check('iq namespace is spam', iq.attrs.xmlns === 'spam');
  check('iq id used', iq.attrs.id === 'TESTIQ');

  const list = iq.content[0];
  check('spam_list jid is the reported number', list.tag === 'spam_list' && list.attrs.jid === '94711111111@s.whatsapp.net');
  check('spam_flow present', list.attrs.spam_flow === 'MessageMenu', list.attrs.spam_flow);

  const mnode = list.content[0];
  check('message node carries id + timestamp', mnode.attrs.id === key.id && mnode.attrs.t === '1700000000');

  const raw = mnode.content.find((c) => c.tag === 'raw');
  check('raw node has protobuf bytes', raw && Buffer.isBuffer(raw.content) && raw.content.length > 0);

  const cv = mnode.content.find((c) => c.tag === 'content_validation');
  const tok = cv && cv.content.find((c) => c.tag === 'reporting_token');
  const keyNode = cv && cv.content.find((c) => c.tag === 'reporting_token_key');
  check('captured token is used as-is', tok && Buffer.compare(Buffer.from(tok.content), capturedToken) === 0);
  check('reporting key attached', keyNode && Buffer.from(keyNode.content).length === 32);

  // group variant
  const g = buildSpamReportNode({
    message,
    key: makeKey({ remoteJid: '120363000000000000@g.us', participant: '94722222222@s.whatsapp.net' }),
    timestampSec: 1700000000,
    senderJid: '94722222222@s.whatsapp.net',
    chatJid: '120363000000000000@g.us',
    groupSubject: 'Bad Group',
    capturedToken,
    proto
  });
  const glist = g.node && g.node.content[0];
  check('group report targets the group', glist && glist.attrs.jid === '120363000000000000@g.us');
  check('group report keeps subject', glist && glist.attrs.subject === 'Bad Group');
  check('group flow is GroupInfoReport', glist && glist.attrs.spam_flow === 'GroupInfoReport');

  // no secret -> refuse instead of sending garbage
  const noSecret = buildSpamReportNode({
    message: { conversation: 'x' },
    key,
    timestampSec: 1,
    senderJid: key.remoteJid,
    chatJid: key.remoteJid,
    capturedToken,
    proto
  });
  check('no messageSecret -> no node', noSecret.node === null && /messageSecret/.test(noSecret.reason), noSecret.reason);
}

// ---------------------------------------------------------------- 3. result

function testResultParsing() {
  console.log('\nserver response parsing');

  const ok = extractReportResult({ tag: 'iq', attrs: { type: 'result' }, content: [{ tag: 'report_id', attrs: {}, content: 'RID123' }] });
  check('report id from child node', ok.reportId === 'RID123');

  const attr = extractReportResult({ tag: 'iq', attrs: { report_id: 'RID999' } });
  check('report id from attribute', attr.reportId === 'RID999');

  const err = extractReportResult({ tag: 'iq', attrs: { type: 'error', code: '400', text: 'bad-request' } });
  check('error code/text parsed', err.errorCode === 400 && err.errorText === 'bad-request');

  const empty = extractReportResult(null);
  check('null response safe', empty.reportId === null);
}

// ---------------------------------------------------------------- 4. send

async function testSend() {
  console.log('\nsending');

  const proto = require('@whiskeysockets/baileys').proto;
  const message = makeMessage('poison');
  const key = makeKey();

  const calls = [];
  const sock = {
    query: async (node) => {
      calls.push(node);
      return { tag: 'iq', attrs: { type: 'result' }, content: [{ tag: 'report_id', content: 'RID-OK' }] };
    }
  };

  const res = await sendSpamReport(sock, {
    message,
    key,
    timestampSec: 1700000000,
    senderJid: key.remoteJid,
    chatJid: key.remoteJid,
    capturedToken: randomBytes(16),
    proto
  });

  check('iq was sent', calls.length === 1);
  check('accepted with report id', res.ok === true && res.reportId === 'RID-OK');

  const failing = { query: async () => { throw new Error('boom'); } };
  const bad = await sendSpamReport(failing, {
    message,
    key,
    timestampSec: 1700000000,
    senderJid: key.remoteJid,
    chatJid: key.remoteJid,
    capturedToken: randomBytes(16),
    proto
  });
  check('iq error -> not ok', bad.ok === false && /boom/.test(bad.errorText));
}

// ---------------------------------------------------------------- 5. policy

async function testReporter() {
  console.log('\nreporter policy');

  const makeStore = (n) => new Store(path.join(tmp, `s${n}.json`), logger);
  const proto = require('@whiskeysockets/baileys').proto;

  const job = () => ({
    message: makeMessage('poison'),
    key: makeKey(),
    timestampSec: 1700000000,
    senderJid: '94711111111@s.whatsapp.net',
    chatJid: '94711111111@s.whatsapp.net',
    severity: 'critical'
  });

  // --- accepted on first attempt: stops early (untilAccepted) ---
  {
    let count = 0;
    const sock = { query: async () => { count++; return { tag: 'iq', attrs: {}, content: [{ tag: 'report_id', content: 'RID1' }] }; } };
    const notes = [];
    const r = new Reporter({
      sock,
      config: { actions: {}, report: { attempts: 3, delaysMs: [5, 5], mode: 'untilAccepted' } },
      logger,
      store: makeStore(1),
      tokenStore: new TokenStore(logger),
      notify: async (lines) => notes.push(lines)
    });
    const results = await r.run(job());
    check('untilAccepted: one attempt only', count === 1, `sent ${count}`);
    check('accepted counted', r.status().accepted === 1);
    check('owner notified success', notes.length === 1 && /Report sent/.test(notes[0][0]), notes[0] && notes[0][0]);
  }

  // --- always mode: all 3 attempts ---
  {
    let count = 0;
    const sock = { query: async () => { count++; return { tag: 'iq', attrs: {}, content: [{ tag: 'report_id', content: 'RID' }] }; } };
    const store = makeStore(2);
    const r = new Reporter({
      sock,
      config: { actions: {}, report: { attempts: 3, delaysMs: [5, 5, 5], mode: 'always', perSenderDailyCap: 10 } },
      logger,
      store,
      tokenStore: new TokenStore(logger),
      notify: async () => {}
    });
    await r.run(job());
    check('always mode: 3 attempts', count === 3, `sent ${count}`);
    check('all 3 recorded in store', store.getReport('94711111111@s.whatsapp.net').history.length === 3);
  }

  // --- all attempts fail ---
  {
    let count = 0;
    const sock = { query: async () => { count++; return { tag: 'iq', attrs: { type: 'error', code: '400', text: 'not-acceptable' } }; } };
    const notes = [];
    const r = new Reporter({
      sock,
      config: { actions: {}, report: { attempts: 3, delaysMs: [5, 5, 5] } },
      logger,
      store: makeStore(3),
      tokenStore: new TokenStore(logger),
      notify: async (lines) => notes.push(lines)
    });
    await r.run(job());
    check('3 attempts on failure', count === 3, `sent ${count}`);
    check('failure counted', r.status().failed === 3);
    check('owner told it failed', notes.length === 1 && /could not be confirmed/.test(notes[0][0]), notes[0] && notes[0][0]);
  }

  // --- gating ---
  {
    const store = makeStore(4);
    const r = new Reporter({
      sock: { query: async () => ({}) },
      config: { actions: {}, report: { attempts: 3, minSeverity: 'high', perSenderDailyCap: 3, globalHourlyCap: 20 } },
      logger,
      store,
      tokenStore: new TokenStore(logger)
    });

    check('low severity blocked', r.canReport({ senderJid: '9471@s.whatsapp.net', severity: 'medium' }).ok === false);
    check('high severity allowed', r.canReport({ senderJid: '9471@s.whatsapp.net', severity: 'high' }).ok === true);
    check('no jid blocked', r.canReport({ senderJid: null, severity: 'high' }).ok === false);

    r.cfg.enabled = false;
    check('disabled blocks everything', r.canReport({ senderJid: '9471@s.whatsapp.net', severity: 'critical' }).ok === false);
    r.cfg.enabled = true;

    // daily cap
    for (let i = 0; i < 3; i++) {
      store.recordReport('9471@s.whatsapp.net', { at: new Date().toISOString(), attempt: i + 1, ok: false });
    }
    check('daily cap enforced', r.canReport({ senderJid: '9471@s.whatsapp.net', severity: 'critical' }).ok === false);

    // global cap
    const store2 = makeStore(5);
    const r2 = new Reporter({
      sock: { query: async () => ({}) },
      config: { actions: {}, report: { globalHourlyCap: 2, perSenderDailyCap: 99 } },
      logger,
      store: store2,
      tokenStore: new TokenStore(logger)
    });
    store2.recordReport('a@s.whatsapp.net', { at: new Date().toISOString(), attempt: 1, ok: false });
    store2.recordReport('b@s.whatsapp.net', { at: new Date().toISOString(), attempt: 1, ok: false });
    check('global hourly cap enforced', r2.canReport({ senderJid: 'c@s.whatsapp.net', severity: 'critical' }).ok === false);
  }
}

// ---------------------------------------------------------------- 6. token store

function testTokenStore() {
  console.log('\ntoken capture');

  const ts = new TokenStore(logger);
  const stanza = {
    tag: 'message',
    attrs: { id: 'MSG1', from: '94711111111@s.whatsapp.net' },
    content: [
      { tag: 'enc', attrs: { v: '2', type: 'msg' }, content: Buffer.from('ciphertext') },
      { tag: 'reporting', attrs: {}, content: [{ tag: 'reporting_token', attrs: { v: '2' }, content: Buffer.from('0123456789abcdef') }] }
    ]
  };

  ts.ingest(stanza);
  check('token captured by message id', !!ts.get('MSG1'));
  check('token bytes preserved', ts.get('MSG1').toString() === '0123456789abcdef');

  ts.ingest({ tag: 'message', attrs: { id: 'MSG2' }, content: [{ tag: 'enc', attrs: {}, content: Buffer.from('x') }] });
  check('stanza without reporting ignored', ts.get('MSG2') === null);

  ts.ingest(null);
  ts.ingest({ tag: 'receipt', attrs: { id: 'MSG3' } });
  check('non-message stanzas ignored', ts.get('MSG3') === null);

  // bounded memory
  const small = new TokenStore(logger, 2);
  for (let i = 0; i < 5; i++) {
    small.ingest({
      tag: 'message',
      attrs: { id: 'M' + i },
      content: [{ tag: 'reporting', content: [{ tag: 'reporting_token', content: Buffer.from('abcdefgh') }] }]
    });
  }
  check('store is bounded', small.stats().stored === 2, String(small.stats().stored));
}

// ---------------------------------------------------------------- run

(async () => {
  try {
    await testToken();
    testNode();
    testResultParsing();
    await testSend();
    await testReporter();
    testTokenStore();
  } catch (e) {
    fail++;
    console.log('  ✗ threw: ' + (e && e.stack));
  }

  console.log(`\n${'='.repeat(46)}`);
  console.log(`  ${pass} passed, ${fail} failed`);
  if (fail) process.exitCode = 1;
  try {
    fs.rmSync(tmp, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
})();
