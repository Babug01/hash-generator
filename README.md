# Hash Generator

**Live demo:** https://hash-generator-three-eta.vercel.app (Vercel) · [GitHub Pages mirror](https://babug01.github.io/hash-generator/)

Compute MD5, SHA-1, SHA-256, SHA-384, SHA-512, and HMAC digests of text or an uploaded file,
entirely client-side via the Web Crypto API. Runs entirely in the browser; nothing you type or
upload ever leaves your machine.

## Features

- **SHA-1 / SHA-256 / SHA-384 / SHA-512** via the browser's native `crypto.subtle.digest` — no
  external hashing library needed for any of these
- **MD5** via a small vendored pure-JS implementation (Web Crypto deliberately doesn't support
  MD5) — shown for legacy checksum comparison only, clearly labeled as not security-sensitive
- **File upload** (via `FileReader`/`File.arrayBuffer()`) as an alternative to pasted text, so you
  can check a downloaded artifact against a published checksum
- **HMAC mode** — secret key + message + SHA-256/SHA-512, via
  `crypto.subtle.importKey`/`crypto.subtle.sign`
- Per-hash copy buttons

## Why I built this

A quick "does this match the published checksum" or "give me an HMAC for this webhook payload"
comes up often enough that I wanted it without opening a terminal. This is also one piece of a
larger internal DevOps tool I built at work consolidating the utility pages a platform engineer
reaches for daily into one place — this repo is the hash generator piece, cleaned up and
open-sourced on its own.

## Tech Stack

- [React](https://react.dev/) + [Vite](https://vitejs.dev/)
- Native [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) for
  SHA-*/HMAC; a vendored ~60-line MD5 implementation for the one algorithm Web Crypto omits

## Running locally

```bash
git clone https://github.com/Babug01/hash-generator.git
cd hash-generator
npm install
npm run dev
```

## License

MIT — see [LICENSE](LICENSE).
