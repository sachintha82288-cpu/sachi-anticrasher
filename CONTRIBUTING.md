# Contributing

Thanks for helping make WhatsApp a bit less hostile. A few rules keep this
project useful.

## The one hard rule

**No crash payloads.** Never submit real bug/crash payloads, generators, or
"here is the exact bytes that crash client X" content - not in issues, not in
pull requests, not in test fixtures. If you need to show a shape, replace the
dangerous bytes with a placeholder (`"\\u200B".repeat(3000)`, `<PAYLOAD>`) so the
file stays inert.

This project exists to *stop* these messages, and a repository full of working
payloads would just move the problem.

## Good contributions

- a crash vector that is currently missed, described structurally (which field,
  which kind of abuse, roughly what size)
- a false positive: a legitimate message the bot deleted/blocked, with the
  message JSON sanitised
- threshold tuning backed by examples
- portability fixes (Windows, Termux, Docker, Pterodactyl), docs, translations

## Workflow

```bash
git clone https://github.com/<you>/sachi-anticrasher
cd sachi-anticrasher
npm install
npm test          # 110 assertions, must stay green
node index.js --dry-run
```

1. Fork, branch from `main` (`feat/...`, `fix/...`).
2. Keep the detection engine dependency-free (`src/detector.js` must stay pure
   JS - it is what makes the tests instant).
3. Add a test for anything you change. Tests are the only thing standing
   between a heuristic and a false positive that blocks an innocent number.
4. Update `README.md` / `docs/` if behaviour or config changes.
5. Open the PR with: what vector/FP you hit, what you changed, test output.

## Style

- CommonJS, Node 20+, no build step.
- Small pure functions in `src/`, WhatsApp side effects in `src/actions.js`.
- Comment *why*, not *what*. Threshold numbers need a one-line reason.
- Log via the `logger` passed in, never `console.log` inside `src/`.

## Reporting security issues

See [SECURITY.md](SECURITY.md) - private advisory, not a public issue.
