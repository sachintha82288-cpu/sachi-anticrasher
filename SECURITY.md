# Security policy

## What this project is

Sachi AntiCrasher is a **defensive** tool. It detects WhatsApp crash/bug
payloads ("crash codes", contact bombs, invisible-character floods) on the
messages you receive, deletes them before your phone's client can open them,
blocks the sender and reports them to WhatsApp.

It deliberately does **not** contain crash payloads, payload generators, or
anything that could be used to attack another account. Bug reports that ask for
those will be closed.

## Reporting a vulnerability in this project

If you find a flaw in the detection engine, a bypass, or a way this bot could
be abused, please **do not open a public issue**. Instead:

1. Open a private security advisory on this repository
   (Security → Advisories → Report a vulnerability), or
2. Contact the maintainer through the profile linked on the repository page.

Please include: affected version, what you expected, what happened, and the
smallest message shape that reproduces it. **Never send a live crash payload**
- describe the structure instead, or send a JSON where the dangerous bytes are
replaced with a placeholder.

We aim to acknowledge within 7 days.

## Scope

In scope:

- false negatives (a known crash vector that is not flagged)
- false positives (a legitimate message that is flagged, blocked or reported)
- ways the reporting module could be tricked into reporting an innocent number
- anything that lets a remote message crash the bot process itself

Out of scope:

- "make it send crash payloads" - that is not a feature
- WhatsApp account bans caused by using an unofficial client
- bugs in WhatsApp itself (report those to Meta's bug bounty programme)
