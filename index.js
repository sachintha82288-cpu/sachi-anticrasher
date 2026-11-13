#!/usr/bin/env node
'use strict';

/**
 * Sachi AntiCrasher
 * WhatsApp crash/bug message guard - Baileys MD
 *
 * What it does
 *   1. watches every incoming message
 *   2. analyses the decoded protobuf for known crash-payload *shapes*
 *   3. deletes the message for you (and revokes it if it can)
 *   4. blocks the sender
 *   5. tells you what happened and why
 */

const path = require('path');
const fs = require('fs');

const baileys = require('@whiskeysockets/baileys');
const makeWASocket = baileys.default || baileys.makeWASocket;
const {
  useMultiFileAuthState,
  DisconnectReason,
  fetchLatestBaileysVersion,
  makeCacheableSignalKeyStore,
  Browsers
} = baileys;

const pino = require('pino');
const qrcode = require('qrcode-terminal');

const { loadConfig } = require('./src/config');
const { createLogger } = require('./src/logger');
const { Store } = require('./src/store');
const { createGuard, extractText } = require('./src/guard');
const { createCommands } = require('./src/commands');

const ROOT = __dirname;
const argv = process.argv.slice(2);
const cliDryRun = argv.includes('--dry-run');

const config = loadConfig(path.join(ROOT, 'config.json'));
if (cliDryRun) config.dryRun = true;

const logger = createLogger({ level: config.logLevel, dir: path.join(ROOT, 'logs') });
const store = new Store(path.join(ROOT, config.stateFile), logger);

// The bot must survive anything: a poison message, a socket error, a bad key.
process.on('uncaughtException', (e) => {
  logger.error('uncaughtException', { error: e && e.stack ? e.stack.split('\n')[0] : String(e) });
});
process.on('unhandledRejection', (e) => {
  logger.error('unhandledRejection', { error: e && e.message ? e.message : String(e) });
});
process.on('SIGINT', () => {
  logger.info('shutting down (SIGINT)');
  store.save(true);
  process.exit(0);
});
process.on('SIGTERM', () => {
  store.save(true);
  process.exit(0);
});

let currentGuard = null;
let currentCommands = null;
let reconnectAttempts = 0;
let pairingRequested = false;

function banner() {
  logger.info(
    [
      '',
      '  ███████╗ █████╗  ██████╗██╗  ██╗██╗',
      '  ██╔════╝██╔══██╗██╔════╝██║  ██║██║',
      '  ███████╗███████║██║     ███████║██║',
      '  ╚════██║██╔══██║██║     ██╔══██║██║',
      '  ███████║██║  ██║╚██████╗██║  ██║██║',
      '  ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  AntiCrasher',
      ''
    ].join('\n')
  );
}

async function start() {
  const authDir = path.join(ROOT, config.authDir);
  fs.mkdirSync(authDir, { recursive: true });

  const { state, saveCreds } = await useMultiFileAuthState(authDir);

  let version = [2, 3000, 1023223821];
  try {
    const latest = await fetchLatestBaileysVersion();
    if (latest && latest.version) version = latest.version;
  } catch {
    logger.warn('could not fetch latest WA version, using fallback');
  }

  const sock = makeWASocket({
    version,
    logger: pino({ level: 'silent' }),
    printQRInTerminal: false,
    auth: {
      creds: state.creds,
      keys: makeCacheableSignalKeyStore(state.keys, pino({ level: 'silent' }))
    },
    browser: Browsers.ubuntu('Chrome'),
    syncFullHistory: false,
    markOnlineOnConnect: false,
    generateHighQualityLinkPreview: false,
    getMessage: async () => undefined
  });

  sock.ev.on('creds.update', saveCreds);

  sock.ev.on('connection.update', async (update) => {
    const { connection, lastDisconnect, qr } = update || {};

    if (qr) {
      logger.info('QR code — WhatsApp > Linked devices > Link a device');
      qrcode.generate(qr, { small: true });
    }

    if (connection === 'open') {
      reconnectAttempts = 0;
      const me = (sock.user && sock.user.id) || '';
      logger.info(`connected as ${me.split(':')[0]}`);

      if (!config.ownerNumbers.length) {
        const self = me.split(':')[0].split('@')[0];
        if (self) {
          config.ownerNumbers = [self];
          logger.info(`owner set to the linked number: ${self}`);
        }
      }

      currentGuard = createGuard(sock, { config, logger, store });
      currentGuard.attach();

      currentCommands = createCommands({
        sock,
        config,
        store,
        logger,
        guard: currentGuard,
        extractText
      });

      sock.ev.on('messages.upsert', async (upsert) => {
        try {
          if (!currentCommands) return;
          for (const msg of (upsert && upsert.messages) || []) {
            if (!msg || !msg.message) continue;
            await currentCommands.handle(msg);
          }
        } catch (e) {
          logger.error('command handler failed', { error: String(e && e.message ? e.message : e) });
        }
      });
    }

    if (connection === 'close') {
      const code = lastDisconnect && lastDisconnect.error && lastDisconnect.error.output
        ? lastDisconnect.error.output.statusCode
        : 0;
      const loggedOut = code === DisconnectReason.loggedOut;

      if (currentGuard) {
        currentGuard.detach();
        currentGuard = null;
      }
      currentCommands = null;

      if (loggedOut) {
        logger.error(`logged out (${code}) — delete the ${config.authDir}/ folder and link again`);
        return;
      }

      reconnectAttempts++;
      const delay = Math.min(15000, 1500 * reconnectAttempts);
      logger.warn(`connection closed (${code}) — reconnecting in ${delay}ms`);
      setTimeout(() => {
        start().catch((e) => logger.error('restart failed', { error: String(e) }));
      }, delay);
    }
  });

  // pairing code flow (optional): config.pairingNumber = "94771234567"
  if (config.pairingNumber && !state.creds.registered && !pairingRequested) {
    pairingRequested = true;
    try {
      await new Promise((r) => setTimeout(r, 3000));
      const code = await sock.requestPairingCode(String(config.pairingNumber).replace(/[^0-9]/g, ''));
      logger.info(`PAIRING CODE: ${code}  (WhatsApp > Linked devices > Link with phone number)`);
    } catch (e) {
      logger.error('pairing code failed', { error: String(e && e.message ? e.message : e) });
    }
  }

  return sock;
}

banner();
logger.info(`starting ${config.botName}`, { dryRun: config.dryRun, prefix: config.prefix });
start().catch((e) => {
  logger.error('startup failed', { error: String(e && e.stack ? e.stack : e) });
  process.exitCode = 1;
});
