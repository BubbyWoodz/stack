# Stack — encrypted supplement tracker

A self-hosted, mobile-friendly web dashboard for tracking daily vitamin and
supplement intake. **Everything is end-to-end encrypted**: the server stores
one opaque ciphertext blob and can never read your data. Your 12-word
recovery code is the only key — the account *is* the phrase.

## Quick start

```bash
docker compose up -d --build
# open http://<host>:8096
```

Data persists in `./data/stack.db` (mounted volume). No accounts, no cloud,
no telemetry.

## Features (v1)

- **Groups** — Morning / Afternoon / Evening by default; add unlimited custom
  groups (e.g. "Pre-workout", "Before bed")
- **Supplements** — name, dose, brand, notes, group assignment; archive
  instead of delete so history is preserved
- **Daily logging** — tap to log/un-log, "Log all" per group, day navigation
- **Calendar** — month view with full / partial / missed days; tap any day for
  the taken/missed breakdown
- **History** — per-supplement stats: days taken, current streak, best streak,
  first logged date (archived supplements included)
- **Reminders** — per-group reminder times via the browser Notification API
  (works while the page is open)
- **Dark mode default** with light-mode toggle; liquid-glass UI, phone-first

## Encryption model (mirrors Mneme)

- **Recovery code**: BIP39, 128-bit entropy, 12 words. Lose it = data is gone.
  No recovery, no reset, no backdoor.
- **Seed → keys**: BIP39 PBKDF2-HMAC-SHA512 → 64-byte seed →
  HKDF-SHA256(salt `"stack-v1"`, info `"data"` → 32-byte data key;
  info `"identity"` → owner ID = `base64url(sha256(identity_key))`).
- **Vault encryption**: XChaCha20-Poly1305, random 24-byte nonce per write.
  Envelope is version-prefixed from day one: `[0x01][nonce][ciphertext+tag]`.
- **Server** stores only `{version, iv, ciphertext}` — never decrypts.
  Wrong code/password → AEAD tag failure → "won't decrypt".
- **Device password (opt-in)**: seals the 64-byte seed with
  XChaCha20-Poly1305 under Argon2id(password, 128 MiB, t=2, p=1), stored in
  `localStorage`. Quick unlock on that browser only. Caveat shown in the UI:
  a stolen device is offline-brute-forceable — password strength + KDF cost
  are the only protection. Skip it and use the 12 words every time instead.
- **Clearing browser data** wipes the seal → you re-enter the 12 words.
  Expected behavior, not a bug.
- **Auto-lock** after 15 minutes idle wipes keys from memory.
- Record IDs are random 128-bit hex so the server can't infer chronology.

Primitives: `@noble/hashes` + `@noble/ciphers` (audited, sync, no WASM),
vendored under `static/vendor/`.

## Project layout

```
app.py               # dumb vault-blob server (Flask + SQLite)
static/
  index.html         # app shell
  css/style.css      # liquid-glass design system
  js/
    app.js           # UI, vault logic, sync
    crypto.js        # key hierarchy, AEAD, seals, BIP39
    wordlist.js      # BIP39 English wordlist (2048)
  vendor/
    noble-hashes/    # @noble/hashes 2.4.0
    noble-ciphers/   # @noble/ciphers 2.4.0
Dockerfile
docker-compose.yml   # host port 8096
```

## API (server)

| Method | Path        | Body                                        | Notes                              |
| ------ | ----------- | ------------------------------------------- | ---------------------------------- |
| GET    | `/`         | —                                           | web app                            |
| GET    | `/healthz`  | —                                           | `{"ok": true}`                     |
| GET    | `/api/vault`| —                                           | blob or 404 `{"exists": false}`    |
| PUT    | `/api/vault`| `{iv, ciphertext, base_version}` (b64)      | 409 on version conflict            |

## Dev notes

- `STACK_DB` env var overrides the SQLite path (default `/data/stack.db`).
- `PORT` env var overrides the listen port (default `8096`).
- Crypto unit + headless UI-flow tests live in `/tmp` on the build machine
  (`crypto-test.mjs`, `harness.mjs`) — 40/40 passing at build time.
