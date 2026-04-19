# Discord Token Generator

Android-style Discord token generator built on a custom OkHttp + Conscrypt TLS stack and an integrated hCaptcha HSJ solver with real phone fingerprint replay.

## ⚠️ Disclaimer

**This project is provided for educational and research purposes only.**

It exists to demonstrate TLS fingerprinting, captcha internals, and mobile client emulation. I am **not responsible** for any misuse of this code. Generating fake accounts, automating registrations, spamming, or any action that violates Discord's [Terms of Service](https://discord.com/terms) is your responsibility alone.

By running this tool you accept full liability for what you do with it. Use it to learn how these systems work — not to abuse them.

---

## Features

- **Android client emulation** — mimics Discord Android 323.12 (OkHttp + Conscrypt) with matching TLS/HTTP2 fingerprint via a Java proxy. Falls back to `tls_client` when the Java backend is unavailable.
- **Integrated hCaptcha solver** (`solver/`) — local HSJ proof-of-work with captured real-phone fingerprint replay. Silent-passes when the profile matches; image challenges are routed to nopecha.
- **Multiple captcha providers** — HSJ local (default), aiclientz, anysolver (RiskBypass / VoidSolver / OnyxSolver / EZCaptcha / AetherSolver / BruxSolver), OnyxSolver direct.
- **Email providers** — CyberTemp (temp mail, default), Hotmail/Outlook via IMAP, Zeus (on-demand purchase API).
- **Optional phone verification** via HeroSMS.
- **Humanize** — optional bio + avatar post-registration.
- **Region selection** — EU or US (affects signup flow region routing).
- **Threaded** — configurable thread count for parallel generation.
- **Proxy rotation** with automatic bad-proxy quarantine.
- Output saved to `io/output/` (tokens + account metadata).

---

## Requirements

- **Python 3.10+**
- **Java 17+** (for the OkHttp proxy backend)
- **Node.js 18+** (fallback path for hsj.js execution — optional if phone profile replay is available)
- **Windows / Linux / macOS**

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Typical deps: `requests`, `websocket-client`, `tls_client`, `pycryptodome`, `zstandard`, `urllib3`, `certifi`.

---

## Setup

1. **Clone the repo** and open the `TokenGen` directory.
2. **Configure API keys** in `config/api_keys.json`:
   ```json
   {
     "aiclientz": "",
     "anysolver": "",
     "onyx": "",
     "nopecha": "",
     "cybertemp": "",
     "hero_sms_api_key": ""
   }
   ```
   Only fill the ones you plan to use. The default flow (HSJ solver + CyberTemp) needs `nopecha` and `cybertemp`.

3. **Add proxies** to `config/proxies.txt`, one per line:
   ```
   host:port:user:password
   ```

4. **(Optional)** Build the OkHttp Java proxy — prebuilt `okhttp-proxy.jar` is shipped in `okhttp-proxy/`. If you need to rebuild:
   ```bash
   cd okhttp-proxy
   python build.py
   ```

---

## Proxies

**Use residential or mobile proxies.** Datacenter proxies are instantly flagged by hCaptcha and Discord risk scoring — tokens made on them will die on first phone/email verify prompt or get phone-locked at creation.

Recommended:
- **Mobile** (4G/5G rotating) — best silent-pass rate, lowest account mortality.
- **Residential** (ISP-rotating) — good balance of cost and success.

Avoid:
- Datacenter IPs (AWS / OVH / DigitalOcean ranges).
- Free public proxies.
- Overused pools — if the same IP has generated 50 accounts today, the 51st will die.

Format (`host:port:user:password`, one per line):
```
res.example.com:8000:user123:pass456
res.example.com:8000:user124:pass457
```

Bad proxies are auto-quarantined to `config/bad_proxies.txt`.

---

## Usage

```bash
python main.py
```

You will be prompted interactively:

1. **Mail provider** — 1 CyberTemp (default) / 2 Hotmail IMAP / 3 Zeus.
2. **Captcha solver** — 1 aiclientz / 2 anysolver / 3 OnyxSolver / 4 HSJ local (default).
3. **Threads** — parallel generation count (default 1).
4. **Account count** — how many tokens to generate.
5. **Region** — 1 EU (default) / 2 US.
6. **Debug mode** — verbose logs.
7. **Humanize** — bio + avatar after registration.
8. **Per-token logs** — write one log file per token in `io/output/logs/`.
9. **Phone verify** — if enabled, uses HeroSMS to attach a phone number.

Output:
- `io/output/tokens.txt` — plain tokens.
- `io/output/accounts.json` — full account dicts (email / password / token / UA / proxy).

---

## Captcha Solver Notes

The default `hsj` solver:
- Runs locally (no external solve cost beyond nopecha for image challenges).
- Replays **real Android WebView fingerprints** captured from actual phones.
- Rotates the fingerprint tuple (canvas / parent_win / performance / common_keys) per solve from a 2800+ entry pool.
- Silent-passes when the captured profile scores well; otherwise falls back to nopecha for image recognition (~60% success on drag-drop).
- Auto-retries up to 4 times on checkcaptcha rejection with fresh challenges from hCaptcha.

External solvers (aiclientz, anysolver, onyx) are supported for users who prefer paid services.

---

## Project Layout

```
TokenGen/
├── main.py                 # interactive CLI
├── generator.py            # AccountGenerator, mail providers
├── solvers.py              # captcha routing
├── http_client.py          # OkHttp Java bridge / tls_client fallback
├── utils.py                # proxy loading / helpers
├── config/                 # api_keys.json, proxies.txt, etc.
├── io/
│   ├── input/              # hotmail lists (optional)
│   └── output/             # tokens.txt, accounts.json
├── okhttp-proxy/           # Java TLS proxy (jar + sources)
└── solver/                 # hCaptcha HSJ solver (self-contained)
    ├── hcaptcha_solver.py
    ├── phone_profile.py
    ├── phone_motion.py
    ├── patch_hsj_events.py
    ├── hsj_runner.py + .js
    ├── core/               # HSJ core (config, hsj, motion, checkcaptcha, foox1_pool)
    ├── pools/              # fingerprint_pool.json, mobile_fp_pool.json
    └── profiles/           # captured phone profiles + motion templates + foox1
```

---

## Building a Standalone Executable

A PyInstaller spec is included:

```bash
pyinstaller build.spec
```

Output in `dist/tokengen/`. Ship the whole `dist/tokengen/` folder.

---

## License

MIT — do whatever you want, but **this repository is for educational use only**. See the disclaimer above. The author assumes no liability for misuse.
