# 🛡️ Sachi AntiCrasher

[![tests](https://github.com/sachintha82288-cpu/sachi-anticrasher/actions/workflows/test.yml/badge.svg)](https://github.com/sachintha82288-cpu/sachi-anticrasher/actions/workflows/test.yml)
[![release](https://img.shields.io/github/v/release/sachintha82288-cpu/sachi-anticrasher?color=blue)](https://github.com/sachintha82288-cpu/sachi-anticrasher/releases)
[![license](https://img.shields.io/github/license/sachintha82288-cpu/sachi-anticrasher)](LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](package.json)

WhatsApp **crash / bug payload** වලින් ඔයාගේ number එක ආරක්ෂා කරන Bot එකක්. Baileys (Multi-Device) වලින් හදලා තියෙනවා.

පණිවිඩයක් ආව ගමන් ඒකේ **protobuf structure** එක scan කරනවා. Crash payload එකක ලක්ෂණ තියෙනවා නම් —

1. ඒ මැසේජ් එක **Delete for me** කරනවා (ඔයාගේ chat එකෙන් අයින් වෙනවා)
2. ඒ **number එක Block** කරනවා
3. ඒ number එක **WhatsApp ට Report** කරනවා (උපරිම උත්සාහ 3ක්)
4. Group එකක් නම්, bot admin වුණොත් **Delete for everyone** (revoke) කරනවා
5. ඔයාට **alert** එකක් එවනවා — මොකක්ද හඳුනාගත්තේ කියලා

---

## ⚙️ කොහොමද වැඩ කරන්නේ

```
Incoming message
      │
      ▼
[ detector.js ]  ── structure walk ──►  reasons + score (0-100)
      │                                    │
      │  clean                             │  flagged
      ▼                                    ▼
   ignore                          [ severity? ]
                                    low      → log only
                                    medium   → delete for me
                                    high     → delete + block + report
                                    critical → delete + block + report + (kick if admin)
```

Report කරන කොටස වෙනම module එකක්: `src/report/` — ඒක ගැන හැම දෙයක්ම [`docs/REPORTING.md`](docs/REPORTING.md) එකේ.

වැදගත්ම කරුණ: **bot එක message එක render කරන්නේ නෑ.** Baileys කියන්නේ protobuf data එකක් විතරයි — UI එකක් නෑ. ඒ නිසා poison payload එක bot එකට අවුලක් නෑ, ඒත් ඔයාගේ phone එකේ WhatsApp එකට ඒක open කළොත් crash වෙනවා. Bot එක ඒක **ඔයාට කලින්** අල්ලගෙන delete කරනවා.

---

## 🔬 මොනවද හඳුනාගන්නේ

ප්‍රසිද්ධ (public) crash payload families ගැන research කරලා, ඒවා හැමෝම භාවිතා කරන **structure patterns** වලට map කරලා තියෙනවා. සම්පූර්ණ විස්තර + sources: [`docs/RESEARCH.md`](docs/RESEARCH.md)

| Vector family | උදාහරණය | Detection |
|---|---|---|
| Invisible / bidi floods | "black dot", crash codes, LRO/RLO floods | bidi + zero-width + invisible-ratio limits |
| Control bytes | NUL / C0 / C1 bytes | 1ක් ආවත් flag |
| Combining marks (zalgo) | stacked diacritics | combining count limit |
| Size bombs | 60k+ char text, newline floods, emoji runs | length / newline / repeat-run limits |
| vCard / contact bombs | 100+ contacts, 8k-char names | vCard length, record count, field length |
| Interactive bombs | list rows, carousel cards, buttonParamsJson | per-type structural caps |
| Mention bombs | 500 mentioned JIDs | mention count |
| Media / thumbnail | huge base64 thumbnails | thumbnail size |
| Invalid numbers | NaN / Infinity / out-of-range coords | finite + range checks |
| Deep nesting / huge protobuf | viewOnce-in-viewOnce chains | depth, node, proto-size budgets |
| Repeat offenders | same number, many attempts | burst escalation |

Detect වුණාට පස්සේ bot එක **WhatsApp ට report** කරනවා (default 3 attempts, accept වුණාම නවත්තනවා). කොහොමද ඒක වැඩ කරන්නේ, ඇයි "3 වතාවක්" කියන එකේ අවුලක් තියෙනවා කියලා — [`docs/REPORTING.md`](docs/REPORTING.md)

මේක **antivirus එකක් වගේ** — දන්නා patterns + heuristics. අලුත් bug එකක් ආවොත් `src/thresholds.js` එකේ limit එකක් වෙනස් කරලා අල්ලගන්න පුළුවන්.

---

## 🚀 Install

**අවශ්‍ය:** Node.js 20 හෝ ඊට උඩ

```bash
cd sachi-anticrasher
npm install
cp .env.example .env      # optional
node index.js
```

Terminal එකේ QR code එකක් එනවා. ඒක **WhatsApp → Linked devices → Link a device** එකෙන් scan කරන්න.

Phone number එකෙන් link කරන්න ඕන නම් `config.json` එකේ:

```json
"pairingNumber": "94771234567"
```

එතකොට terminal එකේ 8 digit pairing code එකක් එනවා.

> **පළමු වතාවට test mode එකේ යවන්න:**
> ```bash
> node index.js --dry-run
> ```
> මේකෙන් හඳුනාගන්නවා විතරයි, delete/block කරන්නේ නෑ. Logs බලලා limit ටික හරි කියලා පේනවා නම්, normal mode එකට යන්න.

---

## 🧾 config.json

```json
{
  "botName": "Sachi AntiCrasher",
  "prefix": ".",
  "ownerNumbers": [],          // හිස් නම්, link කරපු number එකම owner
  "pairingNumber": "",
  "dryRun": false,
  "authDir": "auth",
  "logLevel": "info",
  "stateFile": "data/state.json",
  "actions": {
    "deleteForMe": true,       // අනිවාර්යයි — මේක තමයි ප්‍රධාන ආරක්ෂාව
    "revokeIfAdmin": true,     // group admin නම් delete for everyone
    "blockOnHigh": true,       // high/critical වලදී block
    "kickOnCritical": false,   // critical වලදී group එකෙන් kick (admin ඕන)
    "autoKickWatchlisted": false,
    "notifyOwner": true,
    "guardOutgoing": true,     // ඔයා forward කරන poison payload block කරනවා
    "reportToWhatsApp": true   // WhatsApp ට report කරනවා
  },
  "report": {
    "enabled": true,
    "attempts": 3,             // උපරිම උත්සාහ 3
    "mode": "untilAccepted",   // accept වුණාම නවත්තනවා ("always" = 3ම යවනවා)
    "delaysMs": [15000, 45000, 120000],
    "minSeverity": "high",     // මේකට අඩු severity වලට report යන්නේ නෑ
    "perSenderDailyCap": 3,
    "globalHourlyCap": 20
  },
  "addWatchlist": [],
  "thresholds": {}             // මෙතනින් default limits override කරන්න
}
```

---

## 💬 Commands (owner only)

| Command | කරන්නේ |
|---|---|
| `.ac help` | උදව් menu |
| `.ac status` | ON/OFF, scan/flag/delete/block counts |
| `.ac stats` | සම්පූර්ණ සංඛ්‍යා + වැඩිපුර යවපු අය |
| `.ac on` / `.ac off` | ආරක්ෂාව on/off |
| `.ac dryrun on\|off` | එකවරම test mode toggle |
| `.ac scan` | මැසේජ් එකකට **reply** කරලා — ඒක scan කරලා report දෙනවා |
| `.ac thresholds` | දැන් වැඩ කරන limits |
| `.ac wl add 94771234567` | whitelist (කවදාවත් block නොකරන අය) |
| `.ac wl list` / `.ac wl del …` | whitelist බලනවා / අයින් කරනවා |
| `.ac report` | report තත්වය (accepted / failed / tokens) |
| `.ac report on\|off` | auto report on/off |
| `.ac report now 9477…` | අන්තිම bug message එක report කරන්න |
| `.ac reports` | report ඉතිහාසය |
| `.ac blocklist` | bot block කරපු numbers |
| `.ac block 9477…` / `.ac unblock …` | අතින් block / unblock |
| `.ac test` | local self-test |

---

## 🧪 Tests

```bash
npm test                      # everything: detector 38 + report 49 + guard 23 assertions
node test/detector.test.js    # detection engine only
node test/report.test.js      # report token derivation + stanza + policy
node test/guard.smoke.js      # end-to-end guard behaviour with a fake socket
node scripts/scan-json.js msg.json   # ඔයා save කරපු message එකක් scan කරන්න
```

---

## 🖥️ 24/7 Run

**pm2:**
```bash
npm i -g pm2
pm2 start index.js --name sachi-anticrasher
pm2 logs sachi-anticrasher
pm2 save
```

**systemd:**
```ini
[Unit]
Description=Sachi AntiCrasher
After=network.target

[Service]
WorkingDirectory=/opt/sachi-anticrasher
ExecStart=/usr/bin/node index.js
Restart=always
RestartSec=5
User=sachi

[Install]
WantedBy=multi-user.target
```

`auth/` folder එක backup කරගන්න — ඒකේ තමයි session එක. Logout වුණොත් `auth/` delete කරලා ආයේ link කරන්න.

---

## ⚠️ සීමා (හරි විදිහට තේරුම් ගන්න)

- **100% නෑ.** මේක heuristic එකක්. අලුත් crash bug එකක් ආවොත් detection update කරන්න වෙනවා.
- **"Delete for me" = revoke නෙවෙයි.** අනුන්ගේ මැසේජ් එකක් WhatsApp අපිට delete-for-everyone කරන්න දෙන්නේ නෑ (group admin නම් ඇරෙන්න). ඒ නිසා group එකේ අනිත් අයට ඒ payload එක තියෙනවා — ඒ අයත් ආරක්ෂා කරන්න ඕන නම් bot ට admin දෙන්න, එතකොට revoke + kick කරනවා.
- **Block කරාම group messages නවතින්නේ නෑ.** Group එකක attack එකක් නම් kick ඕන (bot admin නම්).
- **Report එක guarantee එකක් නෑ.** WhatsApp ට public report API එකක් නෑ; ඒක reverse-engineered stanza එකක්. Report එක accept වුණා කියලා ඒ number එක ban වෙනවා කියන එක නෑ — WhatsApp තමයි තීරණය කරන්නේ. Bot offline වෙලාවක ආපු message එකකට report කරන්නත් බෑ (token එක capture වෙන්නේ නෑ).
- **එකම number එක දිගට report කරන්න එපා.** WhatsApp report de-duplicate කරනවා, ඒ වගේම "abuse reporting tools" කියන එක ඒගොල්ලන්ගේ guidelines වල violation එකක් — ඔයාගේම account එකට limit වෙන්න පුළුවන්. ඒ නිසා default එක `untilAccepted` (accept වුණාම නවත්තනවා).
- **Backup තියාගන්න.** Bot වැඩ කළේ නැති වෙලාවක poison message එකක් open වුණොත් phone එකේ chat history නැති වෙන්න පුළුවන්.
- **False positive:** සාමාන්‍ය මැසේජ් එකක් flag වුණොත් `.ac scan` එකෙන් බලලා `config.json → thresholds` එකේ limit එක වැඩි කරන්න.

## ⚖️ භාවිතය

මේ tool එක **ආරක්ෂාවට** විතරයි — crash payload හදන්න, යවන්න, අනිත් අයට හිරිහැර කරන්න පාවිච්චි කරන්න එපා. ඒ වගේ දේවල් WhatsApp Terms of Service කඩනවා, රටවල් ගොඩක නීතිමය ප්‍රශ්න එනවා (Sri Lanka: Computer Crimes Act). Bot එක ඔයාගේම number එකට link කරන නිසා ඔයාගේ account එකට තමයි වගකීම.

MIT License — `LICENSE` බලන්න.
