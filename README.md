# ctf-toolkit

> A swiss-army CLI for CTF challenges and offensive-security warm-ups. Classical ciphers, encoders, hash identification, and quick recon helpers — one binary, no dependencies.

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg)]() [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What it does

CTF beginners spend half their time switching between online tools — base64 decoders, ROT calculators, hash identifiers, "what cipher is this" guides. `ctf-toolkit` puts the most common ones in one offline CLI so you can keep your hands on the keyboard.

```bash
ctf encode b64 "hello world"
# → aGVsbG8gd29ybGQ=

ctf decode b64 aGVsbG8gd29ybGQ=
# → hello world

ctf cipher caesar --shift 13 "Uryyb, Jbeyq!"
# → Hello, World!

ctf cipher caesar-brute "Uryyb"
# → Tried 26 shifts; best by English frequency: shift=13 → Hello

ctf cipher xor --key "secret" 1f0b1c1f0a06
# → hidden

ctf hash id "5d41402abc4b2a76b9719d911017c592"
# → Likely: MD5 (32 hex chars)

ctf hash crack --algo md5 --wordlist rockyou.txt 5f4dcc3b5aa765d61d8327deb882cf99
# → password
```

---

## Subcommands

### `encode` / `decode` — multi-format converters

| Format | Description |
|---|---|
| `b64` | Base64 (RFC 4648) |
| `b32` | Base32 |
| `hex` | Hexadecimal |
| `url` | URL percent-encoding |
| `rot13` | ROT13 letter substitution |
| `morse` | International Morse code |
| `binary` | 8-bit binary (space-separated bytes) |

### `cipher` — classical and lightweight ciphers

- `caesar [--shift N] <text>` — encode/decode with given shift
- `caesar-brute <text>` — try all 26 shifts, score with English letter-frequency
- `vigenere [--key KEY] <text>` — encode/decode (use `--decrypt` to reverse)
- `xor [--key KEY] <hex>` — XOR-decrypt a hex string with a key (repeating)
- `atbash <text>` — Atbash substitution (A↔Z, B↔Y...)

### `hash` — identification and cracking

- `hash id <digest>` — guess the algorithm from the digest length and shape
- `hash compute --algo md5|sha1|sha256|sha512 <text>` — compute digest
- `hash crack --algo X --wordlist file <digest>` — dictionary attack

### `text` — entropy and frequency analysis

- `text entropy <data>` — Shannon entropy bits/char (useful for "is this base64 vs random vs natural language")
- `text freq <data>` — letter-frequency table (good first move on unknown cipher)

---

## Install

```bash
pip install ctf-toolkit

ctf --help
```

Python 3.11+, **zero external dependencies** — everything uses the standard library so it runs anywhere.

---

## Why I built this

I'm leveling up my offensive-security chops in public — picoCTF, HackTheBox, weekly challenges. The pattern is the same: encoded blob lands in front of you, and you start a tedious sequence of "try b64 → try hex → try caesar → ...". This tool collapses that loop.

It's also a good interview artifact for **Red Team / Offensive Security** roles because every detector and breaker here is implemented from first principles — no opaque libraries, just standard library + a clean CLI.

---

## Example: solving a chained challenge

A CTF gives you `'Olcpu' Vf gur xrl. nccvr'`:

```bash
$ ctf cipher caesar-brute "Olcpu' Vf gur xrl. nccvr'"
# best by English freq: shift=13 → "Apple' Is the key. apple'"
$ ctf cipher vigenere --key apple --decrypt "Lmwt cm yhx"
# → "Look in the box"
```

Two commands, one solve.

---

## Roadmap

- [x] Encoders / decoders (b64, b32, hex, url, rot13, morse, binary)
- [x] Classical ciphers (Caesar, Caesar brute, Vigenère, XOR, Atbash)
- [x] Hash identification + wordlist crack
- [x] Entropy + frequency analysis
- [ ] RSA helpers (small-e, common-modulus, Wiener's attack)
- [ ] Steganography helpers (LSB extract, strings on images)
- [ ] PCAP quick-look (extract HTTP/DNS/credentials)
- [ ] CTF write-up template generator

---

## License

[MIT](LICENSE)

---

*Built by [@forgehk](https://github.com/forgehk) — [DarkForge AI](https://darkforgeai.com)*
