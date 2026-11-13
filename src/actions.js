'use strict';

/**
 * Actions the guard can take on WhatsApp.
 * Every call is wrapped: one failing action must never abort the others,
 * and nothing here is allowed to throw into the socket event handler.
 */

const TIMEOUT_MS = 12000;

function withTimeout(promise, ms = TIMEOUT_MS) {
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      const t = setTimeout(() => reject(new Error('action timeout')), ms);
      if (t.unref) t.unref();
    })
  ]);
}

async function safe(fn, name, logger) {
  try {
    return await withTimeout(Promise.resolve().then(fn));
  } catch (e) {
    logger && logger.warn(`action failed: ${name}`, { error: String(e && e.message ? e.message : e) });
    return null;
  }
}

/** "Delete for me" - removes the message from our own chat only. */
async function deleteForMe(sock, chatJid, key, timestampSec) {
  return sock.chatModify(
    {
      clear: {
        messages: [
          {
            id: key.id,
            fromMe: !!key.fromMe,
            timestamp: Number(timestampSec) || Math.floor(Date.now() / 1000)
          }
        ]
      }
    },
    chatJid
  );
}

/** "Delete for everyone" - only valid for our own messages or as group admin. */
async function revokeForEveryone(sock, chatJid, key) {
  return sock.sendMessage(chatJid, { delete: key });
}

async function blockSender(sock, jid) {
  return sock.updateBlockStatus(jid, 'block');
}

async function unblockSender(sock, jid) {
  return sock.updateBlockStatus(jid, 'unblock');
}

async function kickFromGroup(sock, groupJid, participantJid) {
  return sock.groupParticipantsUpdate(groupJid, [participantJid], 'remove');
}

function botId(sock) {
  const id = sock && sock.user && sock.user.id;
  return id ? id.split(':')[0].split('@')[0] : null;
}

/** group metadata with a short cache (avoids rate-overlimit on busy groups) */
function createGroupMetaCache(sock, logger, ttlMs = 60000) {
  const cache = new Map();
  return async function getGroupMeta(groupJid) {
    const now = Date.now();
    const hit = cache.get(groupJid);
    if (hit && now - hit.at < ttlMs) return hit.meta;
    try {
      const meta = await withTimeout(sock.groupMetadata(groupJid), 8000);
      cache.set(groupJid, { at: now, meta });
      if (cache.size > 200) cache.delete(cache.keys().next().value);
      return meta;
    } catch (e) {
      logger && logger.debug('groupMetadata failed', { groupJid, error: String(e) });
      return hit ? hit.meta : null;
    }
  };
}

function isBotAdminIn(sock, metadata) {
  if (!metadata) return false;
  const me = botId(sock);
  if (!me) return false;
  return metadata.participants.some((p) => {
    const pid = (p.id || '').split('@')[0].split(':')[0];
    return pid === me && (p.admin === 'admin' || p.admin === 'superadmin');
  });
}

module.exports = {
  safe,
  withTimeout,
  deleteForMe,
  revokeForEveryone,
  blockSender,
  unblockSender,
  kickFromGroup,
  isBotAdminIn,
  botId,
  createGroupMetaCache
};
