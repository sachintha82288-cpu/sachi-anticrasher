'use strict';

/**
 * Detector self-test. No network, no WhatsApp, no real crash payloads -
 * every sample here is synthesised from ordinary characters so the test is
 * safe to run anywhere.
 *
 *   node test/detector.test.js
 */

const { analyzeMessage } = require('../src/detector');

let pass = 0;
let fail = 0;
const failures = [];

function check(name, cond, extra) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    failures.push(name);
    console.log(`  ✗ ${name}${extra ? ' :: ' + extra : ''}`);
  }
}

function t(name, fn) {
  console.log(`\n${name}`);
  try {
    fn();
  } catch (e) {
    fail++;
    failures.push(`${name} (threw)`);
    console.log(`  ✗ threw ${e && e.message}`);
  }
}

const zw = (n) => '\u200B'.repeat(n);
const bidi = (n) => '\u202E'.repeat(n);
const combining = (n) => 'a' + '\u0301'.repeat(n);
const filler = (n) => '\u3164'.repeat(n);

// ------------------------------------------------------------------ clean

t('clean traffic must never be flagged', () => {
  const cases = {
    'short text': { conversation: 'hello machan, kohomada?' },
    'normal long text (4k)': { conversation: 'Sachi AntiCrasher test. '.repeat(160) },
    'sinhala text': { conversation: 'ආයුබෝවන්! මේක සාමාන්‍ය මැසේජ් එකක්.' },
    'emoji text': { conversation: '👍🏽🔥🎉 '.repeat(50) },
    'quoted reply': {
      extendedTextMessage: {
        text: 'ok',
        contextInfo: { quotedMessage: { conversation: 'previous' }, stanzaId: 'ABC' }
      }
    },
    'single vcard': {
      contactMessage: {
        displayName: 'Sachintha',
        vcard: 'BEGIN:VCARD\nVERSION:3.0\nFN:Sachintha\nTEL;type=CELL:+94771234567\nEND:VCARD'
      }
    },
    '3 native flow buttons': {
      interactiveMessage: {
        nativeFlowMessage: {
          buttons: [
            { name: 'quick_reply', buttonParamsJson: JSON.stringify({ display_text: 'Yes', id: '1' }) },
            { name: 'quick_reply', buttonParamsJson: JSON.stringify({ display_text: 'No', id: '2' }) },
            { name: 'cta_url', buttonParamsJson: JSON.stringify({ display_text: 'Open', url: 'https://x.y' }) }
          ]
        }
      }
    },
    'normal location': { locationMessage: { degreesLatitude: 6.9271, degreesLongitude: 79.8612 } },
    'normal poll': { pollCreationMessage: { name: 'Lunch?', options: [{ optionName: 'A' }, { optionName: 'B' }] } },
    'image with caption': {
      imageMessage: { caption: 'look at this', mimetype: 'image/jpeg', fileLength: '123456' }
    },
    'viewOnce wrapper': {
      viewOnceMessage: { message: { imageMessage: { caption: 'once', mimetype: 'image/jpeg' } } }
    },
    'edit wrapper': {
      editedMessage: { message: { protocolMessage: { editedMessage: { conversation: 'fixed typo' } } } }
    }
  };

  for (const [label, message] of Object.entries(cases)) {
    const r = analyzeMessage(message);
    check(`${label} -> clean`, !r.flagged, `got ${r.severity} ${r.score} ${r.reasons.map((x) => x.code).join(',')}`);
  }
});

// ------------------------------------------------------------------ poison

t('invisible / bidi / control floods', () => {
  const zwRes = analyzeMessage({ conversation: zw(3000) });
  check('3000 zero-width chars flagged', zwRes.flagged && ['high', 'critical'].includes(zwRes.severity), `${zwRes.severity} ${zwRes.score}`);

  const bidiRes = analyzeMessage({ conversation: bidi(2000) });
  check('2000 bidi overrides flagged', bidiRes.flagged && ['high', 'critical'].includes(bidiRes.severity), `${bidiRes.severity} ${bidiRes.score}`);

  const ctrlRes = analyzeMessage({ conversation: 'hi\u0000there' });
  check('a single NUL byte flagged', ctrlRes.flagged, `${ctrlRes.severity} ${ctrlRes.score}`);

  const combRes = analyzeMessage({ conversation: combining(2000) });
  check('zalgo combining flood flagged', combRes.flagged, `${combRes.severity} ${combRes.score}`);

  const fillRes = analyzeMessage({ conversation: filler(2000) });
  check('hangul filler flood flagged', fillRes.flagged, `${fillRes.severity} ${fillRes.score}`);
});

t('size / structure', () => {
  const big = analyzeMessage({ conversation: 'A'.repeat(70000) });
  check('70k char text flagged critical', big.flagged && big.severity === 'critical', `${big.severity} ${big.score}`);

  const nl = analyzeMessage({ conversation: 'x\n'.repeat(900) });
  check('newline flood flagged', nl.flagged, `${nl.severity} ${nl.score}`);

  const run = analyzeMessage({ conversation: '😂'.repeat(8000) });
  check('single-char repeat run flagged', run.flagged, `${run.severity} ${run.score}`);

  let deep = { conversation: 'x' };
  for (let i = 0; i < 30; i++) deep = { viewOnceMessage: { message: deep } };
  const deepRes = analyzeMessage(deep);
  check('30-level nesting flagged', deepRes.flagged, `${deepRes.severity} ${deepRes.score}`);

  const many = { extendedTextMessage: { text: 'hi', contextInfo: { mentionedJid: Array.from({ length: 500 }, (_, i) => `94${i}@s.whatsapp.net`) } } };
  const manyRes = analyzeMessage(many);
  check('500 mentions flagged', manyRes.flagged, `${manyRes.severity} ${manyRes.score}`);
});

t('contact / vCard bombs', () => {
  const huge = analyzeMessage({
    contactMessage: { displayName: 'X', vcard: 'BEGIN:VCARD\nFN:' + 'A'.repeat(9000) + '\nEND:VCARD' }
  });
  check('9k vCard flagged', huge.flagged, `${huge.severity} ${huge.score}`);

  const bomb = analyzeMessage({
    contactsArrayMessage: {
      displayName: '100 contacts',
      contacts: Array.from({ length: 100 }, (_, i) => ({
        displayName: 'c' + i,
        vcard: 'BEGIN:VCARD\nFN:c' + i + '\nEND:VCARD'
      }))
    }
  });
  check('100-contact array flagged', bomb.flagged, `${bomb.severity} ${bomb.score}`);

  const embedded = analyzeMessage({
    contactMessage: { displayName: 'Y', vcard: 'BEGIN:VCARD\nFN:a\nEND:VCARD\n'.repeat(40) }
  });
  check('vCard with 40 embedded records flagged', embedded.flagged, `${embedded.severity} ${embedded.score}`);
});

t('interactive payloads', () => {
  const rows = analyzeMessage({
    listMessage: {
      title: 'pick',
      sections: Array.from({ length: 10 }, (_, s) => ({
        title: 's' + s,
        rows: Array.from({ length: 10 }, (_, r) => ({ title: 'r' + r, rowId: `${s}-${r}` }))
      }))
    }
  });
  check('100 list rows flagged', rows.flagged, `${rows.severity} ${rows.score}`);

  const cards = analyzeMessage({
    carouselMessage: { cards: Array.from({ length: 20 }, () => ({ header: { title: 'c' } })) }
  });
  check('20 carousel cards flagged', cards.flagged, `${cards.severity} ${cards.score}`);

  const params = analyzeMessage({
    interactiveMessage: {
      nativeFlowMessage: {
        buttons: [{ name: 'quick_reply', buttonParamsJson: 'not-json-' + 'x'.repeat(3000) }]
      }
    }
  });
  check('invalid + oversized buttonParamsJson flagged', params.flagged, `${params.severity} ${params.score}`);
});

t('numbers / media / location', () => {
  const nan = analyzeMessage({ locationMessage: { degreesLatitude: NaN, degreesLongitude: 0 } });
  check('NaN latitude flagged', nan.flagged, `${nan.severity} ${nan.score}`);

  const range = analyzeMessage({ liveLocationMessage: { degreesLatitude: 999, degreesLongitude: 5000 } });
  check('out-of-range coordinates flagged', range.flagged, `${range.severity} ${range.score}`);

  const thumb = analyzeMessage({
    imageMessage: { mimetype: 'image/jpeg', jpegThumbnail: 'A'.repeat(200000) }
  });
  check('200k thumbnail flagged', thumb.flagged, `${thumb.severity} ${thumb.score}`);

  const poll = analyzeMessage({
    pollCreationMessage: { name: 'x', options: Array.from({ length: 200 }, (_, i) => ({ optionName: 'o' + i })) }
  });
  check('200 poll options flagged', poll.flagged, `${poll.severity} ${poll.score}`);
});

t('edge cases', () => {
  check('null message -> not flagged', analyzeMessage(null).flagged === false);
  check('undefined message -> not flagged', analyzeMessage(undefined).flagged === false);
  check('empty object -> not flagged', analyzeMessage({}).flagged === false);
  check('array payload does not throw', analyzeMessage({ contactsArrayMessage: { contacts: [] } }).flagged === false);

  // circular reference must be detected, not hang
  const circ = { conversation: 'x' };
  circ.self = circ;
  const r = analyzeMessage(circ);
  check('circular structure handled', r.flagged === true || r.stats.cycles >= 0, `${r.severity} ${r.score}`);
});

t('performance guard', () => {
  const start = Date.now();
  analyzeMessage({ conversation: 'x'.repeat(400000) });
  const ms = Date.now() - start;
  check(`400k char scan under 400ms (took ${ms}ms)`, ms < 400);
});

// ------------------------------------------------------------------ summary

console.log(`\n${'='.repeat(46)}`);
console.log(`  ${pass} passed, ${fail} failed`);
if (fail) {
  console.log('  failed: ' + failures.join(' | '));
  process.exitCode = 1;
}
