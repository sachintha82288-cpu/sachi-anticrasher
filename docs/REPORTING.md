# WhatsApp Report — කොහොමද වැඩ කරන්නේ (සහ අපේ bot එකේ report logic එක)

මේ document එකෙන් කියන්නේ WhatsApp එකේ "report" කියන දේ ඇත්තටම මොකක්ද, ඒක technical විදිහට කොහොමද සිද්ධ වෙන්නේ, සහ Sachi AntiCrasher ඒක කරන්නේ කොහොමද කියලා.

---

## 1. පළවෙනි කරුණ: public API එකක් නෑ

WhatsApp ට report එවන්න **කිසිම official API එකක් නෑ**. Cloud API එකේ (business messaging) report endpoint එකක් නෑ. ඒ නිසා:

- Phone එකේ / WhatsApp Web එකේ **UI එකෙන්** report කරන එක තමයි පිළිගත්තු ක්‍රමය.
- Unofficial libraries (Baileys, whatsapp-web.js, wppconnect) වලට report කරන්න පුළුවන් **එකම නිසා** ඒවා WhatsApp Web client එකේ internal function එකක් හෝ internal stanza එකක් පාවිච්චි කරන නිසා. ඒක reverse-engineered — WhatsApp ඕන වෙලාවක වෙනස් කරන්න පුළුවන්.

---

## 2. UI එකෙන් report කරද්දී ඇත්තටම වෙන්නේ මොකක්ද

WhatsApp Help Center එකේ කියන විදිහට, ඔයා කෙනෙක්ව report කරාම WhatsApp ට ලැබෙන්නේ:

- ඒ කෙනා ඔයාට එවපු **අන්තිම messages 5**
- ඒ කෙනාගේ WhatsApp ID, message එවපු වෙලාව, message type (text/image/video…)
- calls තිබුණා නම් අන්තිම calls 5ක basic info (කවුද ගත්තේ, කොච්චර වෙලාද)

සහ වැදගත් දේවල්:
- **report කරපු කෙනාට දැනගන්නේ නෑ** (notification එකක් යන්නේ නෑ)
- Block කිරීම report එකෙන් **වෙනම** දෙයක් (එකට එකතු කරන්න පුළුවන්, ඒත් වෙන වෙනම stanzas)
- WhatsApp server එකෙන් **report id** එකක් එවනවා. හිස් id එකක් ආවා නම් ඒක "discard" කළා කියන එක (duplicate, synthetic evidence, ආදිය)

---

## 3. Technical flow (reverse-engineered)

Report එක කියන්නේ **එක IQ stanza එකක්**:

```
<iq type="set" id="…" to="s.whatsapp.net" xmlns="spam">
  <spam_list jid="<report කරන number එක>" spam_flow="MessageMenu">
    <message from="<එවපු කෙනා>" t="<unix time>" id="<message id>">
      <raw v="2" local_message_type="0" mediatype="0"><protobuf bytes/></raw>
      <content_validation type="plaintext_v3">
        <reporting_token v="2"><16 bytes/></reporting_token>
        <reporting_token_key><32 bytes/></reporting_token_key>
      </content_validation>
    </message>
  </spam_list>
</iq>
```

මේකේ තියෙන කෑලි:

| කෑල්ල | මොකක්ද |
|---|---|
| `xmlns="spam"`, `to="s.whatsapp.net"` | report server endpoint එක |
| `spam_list jid` | කාවද report කරන්නේ (user / group / channel) |
| `spam_flow` | කොහෙන් report කළාද කියන entry point එක (`MessageMenu`, `ChatInfoReport`, `GroupInfoReport`, `ContactInfo`, …) |
| `<message>` | report කරන message එකේ id, time, sender |
| `<raw>` | message එකේ **protobuf bytes** (plaintext, encrypt කරලා නෑ) |
| `reporting_token` | ඒ message එකට අදාළ **HMAC token** එක |
| `reporting_token_key` | ඒ token එක verify කරන්න ඕන **key** එක |

### Token එක හැදෙන විදිහ

1. Message එක යවන කෙනාගේ client එක `messageContextInfo.messageSecret` (32 random bytes) එකක් හදනවා — ඒක E2E encrypt වෙච්ච message එක ඇතුලේ යනවා.
2. ඒ secret එකෙන් HKDF-SHA256 වලින් **reporting key** එකක් අදුරනවා:
   `key = HKDF(secret, info = messageId ‖ fromJid ‖ toJid ‖ "Report Token")`
3. Message protobuf එකේ **නිශ්චිත field set එකක්** විතරක් අරගෙන (`reportingFields` — text, media metadata, context info වගේ) HMAC-SHA256 ගහලා පළවෙනි 16 bytes ගන්නවා = **token**
4. Token එක message එකේ stanza එකට **plaintext child එකක්** විදිහට attach කරනවා (`<reporting><reporting_token v="2">…`)

ඒ නිසා report එක valid වෙන්න නම් reporter ට **token + key දෙකම** තියෙන්න ඕන. ඒකෙන් තමයි "මේ message එක මට ඇත්තටම ආවා" කියලා server එකට ඔප්පු වෙන්නේ (වෙන කෙනෙක් ගැන බොරු report එකක් හදන්න බැරි වෙන්න).

---

## 4. Baileys වල ප්‍රශ්නය (සහ අපේ විසඳුම)

Baileys v6 message එකක් decrypt කරලා `messages.upsert` event එකට දෙනවා — ඒත් **stanza එකේ අනිත් children (`<reporting>`) ඉවත් කරනවා**. ඒ නිසා:

- `sock.sendMessage()` වලින් report එකක් "හදන්න" බෑ — token එක නෑ
- Token එක නැතුව යැව්වොත් server එක **548** error එකක් දෙනවා, නැත්නම් **හිස් report id** එකක් එවලා discard කරනවා (silent no-op)

**අපේ විසඳුම** (`src/report/`):

1. `token-store.js` — raw websocket එකේ `CB:message` event එකට hook වෙලා, හැම message stanza එකකම `<reporting><reporting_token>` එක කියවලා message id එකෙන් store කරනවා (bounded LRU, 800 entries).
2. `token.js` — Baileys v7 එකේ `reporting-utils` logic එකේ port එකක්: HKDF key එක + protobuf field filter එක + HMAC. (Baileys' own `hkdf()` එකට byte-for-byte match වෙනවා කියලා test එකක් තියෙනවා.)
3. `report.js` — ඒකෙන් `spam` IQ එක හදලා `sock.query()` එකෙන් යවනවා, server එකේ response එකෙන් `report_id` / error code එක කියවනවා.
4. `reporter.js` — policy: කීප වතාවක් උත්සාහ කරන්නද, කොච්චර වෙලාවක් අතර, කවදා නවත්තන්නද.

---

## 5. "3 වතාවක් report" — ඇත්ත කතාව

ඔයා කිව්වා number එක **3 වතාවක්** report කරන්න ඕන කියලා. ඒක implement කරලා තියෙනවා (`report.attempts: 3`), ඒත් මේක හරියට තේරුම් ගන්න:

**හොඳ පැත්ත:** unofficial ක්‍රමයෙන් report එක නිතරම confirm වෙන්නේ නෑ (token mismatch, network, rate limit). ඒ නිසා **3 attempts** එකක් තියෙන එක වැදගත් — එකක් fail වුණොත් ඊළඟ එක යනවා.

**අවුල:** WhatsApp එකම (reporter → reported) pair එකක් **de-duplicate** කරනවා. ඒ නිසා "accepted" වුණාට පස්සේ ආයේ 3 වතාවක් යැව්වොත්:
- වැඩි ප්‍රයෝජනයක් නෑ (server එක discard කරනවා)
- ඒත් **ඔයාගේම account එකට අවදානමක්** — WhatsApp Messaging Guidelines එකේ "abuse reporting tools" කියන එක violation එකක් විදිහට තියෙනවා. එක දිගට report කරන account එකකට report tool එක limit වෙන්න පුළුවන්.

ඒ නිසා default එක තියෙන්නේ:

```json
"report": {
  "attempts": 3,            // උපරිම උත්සාහ 3
  "mode": "untilAccepted",  // ✅ accept වුණාම නවත්තනවා
  "delaysMs": [15000, 45000, 120000]
}
```

හැබැයි ඇත්තටම 3ම යවන්න ඕන නම්:

```json
"mode": "always"
```

එතකොට accept වුණත් 3ම යනවා (15s, 45s, 120s පරතරයෙන්). මගේ උපදෙස: `untilAccepted` තියන්න. WhatsApp එකෙන් confirm එකක් ආවා නම් report එක ගිහින් — ආයේ යවන එකෙන් වෙන්නේ ඔයාගේ account එක risk කරන එක විතරයි.

**Hard caps** (abuse guard) — මේවා හැම වෙලාවෙම වැඩ කරනවා:
- එකම number එකකට දවසකට උපරිම attempts 3 (`perSenderDailyCap`)
- පැයකට reports 20ට වඩා නෑ (`globalHourlyCap`)
- `minSeverity: "high"` — medium/low detection වලට report යන්නේ නෑ (false positive වලින් අනිත් අයට හානි නොවෙන්න)
- dry-run mode එකේ report යන්නේ නෑ

---

## 6. ඇත්තටම සිද්ධ වෙන්නේ මොකක්ද (බලාගන්නේ කොහොමද)

හැම attempt එකක්ම log වෙනවා:

```
logs/anticrash.jsonl
[info] reporting 94771234567 (up to 3x) { severity: 'critical', hasToken: true }
[info] report accepted (1/3) { sender: '94771234567', reportId: '...' }
```

නැත්නම්:

```
[warn] report attempt 1/3 failed { sender: '94771234567', reason: 'server returned no report id (discarded)', code: null }
```

Owner ට WhatsApp alert එකකුත් එනවා — accepted ද, attempts කීයද, report id එක මොකක්ද කියලා.

Commands:
- `.ac report` — තත්වය + accepted/failed counts + captured tokens
- `.ac report on|off`
- `.ac report now 94771234567` — අන්තිම bug message එක report කරන්න
- `.ac reports` — ඉතිහාසය

---

## 7. සීමා (හරියට දැනගෙන ඉන්න)

| සීමාව | තේරුම |
|---|---|
| Token capture එක `CB:message` එකට යැපෙනවා | Baileys version එකක් ඒක නොදුන්නොත් report එක හැදෙන්නේ නෑ (`hasToken: false` log එකෙන් පේනවා) |
| Bot offline වෙලාවක ආපු message | token capture වෙන්නේ නෑ → report කරන්න බෑ (delete/block විතරයි) |
| TC token / privacy-restricted accounts | WhatsApp Web ඒවට අමතර TC token එකක් එකතු කරනවා; අපි ඒක නොදාන නිසා සමහර numbers වලට report reject වෙන්න පුළුවන් |
| Reverse-engineered | WhatsApp ඕන වෙලාවක stanza shape එක වෙනස් කරන්න පුළුවන් — එතකොට update කරන්න වෙනවා |
| Report ≠ block | Report කළාම ඒ number එක නවතින්නේ නෑ. Block එක වෙනම කරන්න ඕන (bot ඒක auto කරනවා) |
| Report ≠ guarantee | WhatsApp තමයි තීරණය කරන්නේ ඒ number එක ban කරන්නද කියලා. එක report එකකින් ban වෙන්නේ නෑ |

**Backup ක්‍රමය (හැම වෙලාවෙම වැඩ කරන එක):** ඒ chat එක open කරලා → contact/group info → **Report** → "Block" එකත් tick කරන්න. මේකෙන් WhatsApp ට අන්තිම messages 5ම යනවා, bot එකේ token එක අවශ්‍ය නෑ.

---

## 8. Sources

- WhatsApp Help Center — How to block and report someone (report එකේදී යන data): https://faq.whatsapp.com/1142481766359885/
- WhatsApp Help Center — About detecting violations: https://faq.whatsapp.com/1805617343145907
- WhatsApp Messaging Guidelines (abuse reporting tools / unofficial clients): https://www.whatsapp.com/legal/messaging-guidelines
- WhatsApp reporting — full reverse-engineering report (`spam` IQ, `spam_list`, tokens, flows): https://docs.baron0.com/WA_REPORTING/
- Baileys v7 `Utils/reporting-utils.ts` (reporting token derivation, MIT): https://github.com/WhiskeySockets/Baileys
- Baileys DeepWiki — Spam reporting and tokens: https://deepwiki.com/WhiskeySockets/Baileys/11.7-analytics-and-reporting
- WPPConnect wa-js — `reportContact` / `reportSpam` (WhatsApp Web's own report job): https://wppconnect.io/wa-js/functions/contact.reportContact.html
- whatsapp-rust — spam reporting API (`SpamFlow`, `SpamReportRequest`): https://whatsapp-rust.jlucaso.com/api/spam-report
