# Research notes — WhatsApp crash / bug payloads

මේ document එකේ අරමුණ: **ප්‍රසිද්ධ crash payload families ගැන දැනගෙන, ඒවා හඳුනාගන්න structural heuristics හදන එක.** මෙතන payload එකක් හදන විදිහක් නෑ — patterns, ඒවා ඇයි වැඩ කරන්නේ, සහ ඒවා අල්ලගන්නේ කොහොමද කියන එක විතරයි.

---

## 1. Crash වෙන්නේ කොහොමද (mechanism)

WhatsApp client එකක් message එකක් process කරද්දී අවුල් වෙන්න පුළුවන් තැන් 4ක් තියෙනවා:

| # | Layer | ඇයි crash වෙන්නේ | ප්‍රතිඵලය |
|---|---|---|---|
| 1 | **Text renderer** (bidi, shaping) | දහස් ගාණක් RTL/LTR override, zero-width, combining marks — Unicode bidi algorithm එකට exponential වගේ වැඩ | app freeze → ANR → force close |
| 2 | **Parser / protobuf** | decode කරන්න බැරි හෝ limit එකට වඩා ලොකු structure, control bytes | exception → crash |
| 3 | **Resource exhaustion** | ලොකු text / vCard / thumbnails / mention arrays — RAM + CPU | OOM kill, freeze |
| 4 | **State persistence** | crash කරන data එක disk එකේ (chat DB, draft, saved state) save වෙනවා | **persistent crash loop** — app එක open කරන හැම වෙලාවෙම crash |

4 වෙනි එක තමයි භයානකම: එක වරක් ආපු message එකකින් app එක නැවත නැවත crash වෙනවා, chat එක delete කරන්න / app data clear කරන්න / reinstall කරන්න වෙනවා.

---

## 2. ප්‍රසිද්ධ cases (documented)

| අවුරුද්ද | Case | Vector | Note |
|---|---|---|---|
| 2014 | iOS 2.11.7 crash | non-printable characters | 2.11.8 වල fix |
| 2014–15 | 2KB "text bomb" | special character set, ~2000 words | 7MB message එකකට වඩා පොඩි payload එකකින් crash |
| 2015 | Emoji overflow | ~4200+ emoji / 65k char limit | Web + Android crash |
| 2017 | Oversized contact name (.vcf) | contact field length | iOS crash loop, 10.3.3 fix |
| 2018 | "Black dot" | ~2000 LTR/RTL marks | tap කරාම freeze |
| 2019 | Group chat crash (Check Point) | edited message parameters from Web | whole group crash loop, 2.19.58 fix |
| 2020 | "Scary messages" / vCard bombs (Brazil: *travar*, *binario*, *contato bomba*) | long weird strings + vCards with 100 contacts | patch rolled out |
| 2020 | Pakistan NTISB advisory #16 | "crash codes" + vCards | national CERT advisory |
| 2025–26 | Baileys-side DoS | rate-overlimit loops, groupMetadata cache miss | bot server CPU/RAM exhaustion |
| 2026 | Oversized draft → `TransactionTooLargeException` | 80KB draft in SavedState → Binder limit | persistent crash loop on Android 15 |

Sources (bottom).

---

## 3. Vector families → detection mapping

### 3.1 Invisible / bidi floods
**ඇයි:** text renderer එකට direction එක resolve කරන්න ලොකු වැඩක්. එකම character එක දහස් ගාණක් ආවම rendering cost එක explode වෙනවා.
**Detect:** `bidiFlag/bidiCritical` (U+200E/200F, U+202A–202E, U+2066–2069, U+061C), `zeroWidthFlag/Critical` (U+200B–200D, U+2060, U+FEFF, U+180E, U+3164, U+FFA0, U+2800, U+00AD), `invisibleRatio` (මුළු text එකෙන් 35%+ invisible නම්).

### 3.2 Control bytes
**ඇයි:** NUL / C0 / C1 bytes කිසිම සාමාන්‍ය chat message එකක නෑ. Parser/renderer එකට invalid.
**Detect:** `controlCharFlag: 1` — එකක් ආවත් flag. `controlCharCritical: 5`.

### 3.3 Combining marks (zalgo)
**ඇයි:** එකක් උඩ තව එක stacking → shaping engine එකට quadratic වැඩ.
**Detect:** `combiningFlag: 150`, `combiningCritical: 800` (`\p{M}`).

### 3.4 Size bombs
**ඇයි:** RAM/CPU. WhatsApp text limit ~65536 chars; 60k+ එකක් + newline flood + emoji repeat run.
**Detect:** `textLengthWarn/Flag/Critical`, `newlineFlag/Critical`, `repeatedCharRun` (code-point based — emoji bomb එක surrogate pair එකක් නිසා code-unit count එකෙන් අහුවෙන්නේ නෑ).

### 3.5 vCard / contact bombs
**ඇයි:** vCard එකක් ඇතුලේ 100ක් contacts, හැම එකකම 8k char name. Open කරාම render + import.
**Detect:** `vcardLengthFlag/Critical`, `vcardCountFlag/Critical`, `vcardFieldLengthFlag`, embedded `BEGIN:VCARD` record count.

### 3.6 Interactive payload bombs
**ඇයි:** `listMessage` sections/rows, `carouselMessage` cards, `nativeFlowMessage` buttons + `buttonParamsJson` — client එකේ UI builder එකට cap එකක් නැත්නම් blow up.
**Detect:** `buttonCountFlag`, `sectionCountFlag`, `rowCountFlag`, `cardCountFlag`, `buttonParamsJsonFlag`, invalid JSON check.

### 3.7 Mention bombs
**ඇයි:** `mentionedJid` / `groupMentions` දහස් ගාණක් → notification + render loop.
**Detect:** `mentionFlag: 40`, `mentionCritical: 120`.

### 3.8 Media / thumbnails
**ඇයි:** `jpegThumbnail` base64 එකේ limit එකට වඩා ලොකු, හෝ `fileLength` වැරදි.
**Detect:** `thumbnailFlag`, `fileLength` sanity.

### 3.9 Invalid numbers / coordinates
**ඇයි:** `NaN` / `Infinity` / range එකෙන් පිට location — client math එකේ exception.
**Detect:** walk එකේදී හැම number එකක්ම `Number.isFinite` check; lat ±90, lng ±180.

### 3.10 Deep nesting / huge protobuf
**ඇයි:** `viewOnce` → `ephemeral` → `deviceSent` → `edited` chains; parser recursion limit / stack overflow.
**Detect:** `maxDepth`, `maxNodes`, `protoSizeFlag/Critical`, cycle detection.

### 3.11 Repeat offenders / bursts
**ඇයි:** එකම number එකෙන් එක දිගට payload එවනවා (හෝ bot එකට rate-overlimit loop එකක් හදනවා).
**Detect:** per-sender hit counter, `burstWindowMs` / `burstCount` → severity escalate → block.

---

## 4. ඇයි මේ approach එක වැඩ කරන්නේ

Bot එක **Baileys** වලින් වැඩ කරන නිසා message එකක් කියන්නේ protobuf object එකක් විතරයි — renderer එකක් නෑ, UI thread එකක් නෑ. ඒ නිසා:

1. poison payload එක bot එකට කිසිම හානියක් නෑ (scan කරන්න පුළුවන්),
2. scan එකෙන් පස්සේ `chatModify({ clear: ... })` (= **Delete for me**) එකෙන් ඒක ඔයාගේ chat එකෙන් අයින් කරනවා,
3. ඊට පස්සේ ඔයා phone එකෙන් chat එක open කරද්දී payload එක නෑ → crash නෑ.

මේක **timing** එකක්: phone එකට sync වෙන්න කලින් delete වෙන්න ඕන. ඒ නිසා bot එක 24/7 online තියෙන්න ඕන (linked device එකක් විදිහට).

**අවවාදය:** `Delete for me` කියන්නේ revoke නෙවෙයි. අනුන්ගේ message එකක් delete-for-everyone කරන්න බෑ — group admin නම් විතරයි (bot ට admin දෙන්න).

---

## 5. Gaps (මේකෙන් අල්ලන්නේ නැති දේ)

- 100% නෑ — heuristics. Brand-new bug එකක් (අලුත් field එකක්, අලුත් rendering path එකක්) miss වෙන්න පුළුවන්.
- Phone එක offline / bot offline වෙලාවක ආව message — protection නෑ.
- Encrypted media payload එකක් ඇතුලේ තියෙන දේවල් (bot decrypt කරන්නේ නෑ) — ඒවා detect කරන්නේ metadata වලින් විතරයි.
- Status (`status@broadcast`) messages default එකේ scan කරන්නේ නෑ — ඕන නම් extend කරන්න පුළුවන්.

---

## 6. Sources

- WABetaInfo — "Scary messages and vcards freeze WhatsApp" (2020): https://wabetainfo.com/scary-messages-and-vcards-freeze-whatsapp/
- NTISB Pakistan Advisory No. 16 (2020) — WhatsApp crash codes: https://download1.fbr.gov.pk/Docs/20209291091551192AdvisoryNo16of2020.pdf
- The Hindu — "Long weird messages can freeze your WhatsApp account indefinitely" (2020): https://www.thehindu.com/sci-tech/technology/long-weird-messages-can-freeze-your-whatapp-account-indefinitely/article61709034.ece
- TechRadar — WhatsApp "crash code" messages (2020): https://www.techradar.com/news/whatsapp-users-need-to-watch-out-for-dangerous-crash-code-messages
- Check Point Research — WhatsApp group chat crash fix (2019): https://www.checkpoint.com/press-releases/check-point-research-leads-to-whatsapp-group-chat-crash-issue-fix/
- Android StackExchange — why the "black dot" character crashes WhatsApp: https://android.stackexchange.com/questions/195485/why-does-this-character-crash-whatsapp
- Medium (Pritom Gogoi) — black dot bug and bidi characters: https://medium.com/rustyelectron/whatsapp-black-dot-bugs-connection-with-arabic-and-hebrew-text-674e6e5bac83
- Hackatrick — WhatsApp crash v2 (emoji / character limit, 2015): https://hackatrick.com/whatsapp-crash-v2-crashing-pc-browser-and-mobile-app/
- Shashank's security blog — oversized contact / .vcf crash on iOS (2017): https://blog.shashank.co/2017/10/crashing-anyones-whatsapp-on-ios.html
- lostmon — large draft → persistent crash loop, Android 15 (2026): https://lostmon.blogspot.com/2026/08/whatsapp-when-large-draft-becomes.html
- Baileys issue #1973 — bot CPU/RAM exhaustion from a single sender: https://github.com/WhiskeySockets/Baileys/issues/1973
- Baileys issue #1627 — timeout → unhandled rejection → process crash (fixed upstream): https://github.com/WhiskeySockets/Baileys/issues/1627
- mautrix/whatsapp capabilities — `MaxTextLength = 65536` reference: https://github.com/mautrix/whatsapp/blob/bf96ce9f/pkg/connector/capabilities.go
- wppconnect `MSG_TYPE` enum — `OVERSIZED`, `MULTI_VCARD` message types: https://wppconnect.io/wa-js/enums/whatsapp.enums.MSG_TYPE.html

---

## 7. Update කරන්නේ කොහොමද

අලුත් crash bug එකක් ආවොත්:

1. ඒකෙන් ආපු message එකේ JSON එකක් ගන්න (ඔයාගේම bot log එකෙන්),
2. `node scripts/scan-json.js that-message.json` — දැන් අල්ලගන්නවද බලන්න,
3. නැත්නම් `src/thresholds.js` එකේ අදාළ limit එක අඩු කරන්න / `src/detector.js` එකේ අලුත් check එකක් එකතු කරන්න,
4. `npm test` + `node test/guard.smoke.js` දුවන්න — clean messages තාම pass වෙනවද බලන්න.
