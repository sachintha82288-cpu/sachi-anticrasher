'use strict';

/**
 * Captures the `<reporting>` stanza child that arrives with every incoming
 * message and keeps it by message id.
 *
 * Baileys v6 decodes only `<enc>` / `<plaintext>` and throws the rest of the
 * stanza away, so without this hook a report cannot be verified by the server.
 * We listen on the raw websocket ('CB:message') which fires for every stanza.
 */

const MAX_ENTRIES = 800;

function findChild(node, tag) {
  if (!node || !Array.isArray(node.content)) return null;
  for (const c of node.content) {
    if (c && c.tag === tag) return c;
  }
  return null;
}

function toBuffer(content) {
  if (Buffer.isBuffer(content)) return content;
  if (content instanceof Uint8Array) return Buffer.from(content);
  if (typeof content === 'string') return Buffer.from(content, 'binary');
  return null;
}

class TokenStore {
  constructor(logger, max = MAX_ENTRIES) {
    this.logger = logger;
    this.max = max;
    this.map = new Map(); // id -> { token, capturedAt }
    this.captured = 0;
  }

  /** Parse one raw <message> stanza; safe to call for every stanza. */
  ingest(stanza) {
    try {
      if (!stanza || stanza.tag !== 'message') return;
      const reporting = findChild(stanza, 'reporting');
      if (!reporting) return;
      const tokenNode = findChild(reporting, 'reporting_token');
      if (!tokenNode) return;
      const token = toBuffer(tokenNode.content);
      if (!token || token.length < 6) return;

      const id = stanza.attrs && stanza.attrs.id;
      if (!id) return;

      this.map.set(id, { token, capturedAt: Date.now() });
      this.captured++;
      if (this.map.size > this.max) {
        const oldest = this.map.keys().next().value;
        this.map.delete(oldest);
      }
    } catch (e) {
      this.logger && this.logger.debug('token ingest failed', { error: String(e) });
    }
  }

  get(id) {
    const hit = this.map.get(id);
    return hit ? hit.token : null;
  }

  has(id) {
    return this.map.has(id);
  }

  stats() {
    return { captured: this.captured, stored: this.map.size };
  }

  clear() {
    this.map.clear();
  }
}

/** Attach to a Baileys socket. Returns a detach function. */
function attachTokenCapture(sock, tokenStore, logger) {
  const ws = sock && sock.ws;
  if (!ws || typeof ws.on !== 'function') {
    logger && logger.warn('raw socket not available - reporting tokens cannot be captured');
    return () => {};
  }
  const handler = (node) => tokenStore.ingest(node);
  ws.on('CB:message', handler);
  logger && logger.debug('reporting-token capture attached');
  return () => {
    if (typeof ws.off === 'function') ws.off('CB:message', handler);
  };
}

module.exports = { TokenStore, attachTokenCapture, findChild };
