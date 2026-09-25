# Pandora

> *Everything in the box was meant to stay inside. Pandora finds what got out.*

**Targeted data-exposure & breach monitoring for a single organisation.**

`pandora` continuously checks a defined set of OSINT and threat-intelligence
sources for mentions of *your* organisation — its name, domains, and keywords —
across the **surface web** and **dark web**. It remembers what it has already
seen and reports **only new** findings on each run, so you get a clean "what
changed" feed instead of a wall of repeats.

It is **not** an internet crawler. It queries the right *indexes and APIs* —
which is how real breach-hunting is done, and what commercial digital-risk
platforms do under the hood with larger private feeds.

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

> **Authorised, defensive use only.** Point this at identifiers for an
> organisation you are authorised to protect. Findings are evidence to
> **remediate** — leaked secrets should be **rotated/revoked** by their owner,
> not tested. See [Responsible use](#responsible-use).

---

## Why

organisations generally, leak data in places nobody is watching:
credentials in public code, files on misconfigured buckets, look-alike phishing
domains, forgotten internet-facing apps, and dumps on paste/leak/dark-web sites.
`pandora` gives a small team a repeatable way to *find their own exposure
first* — and produces a dated report trail that supports breach-detection and
notification duties.

## What it does

Two run modes, each hitting a different set of sources:

| Mode | Sources |
|------|---------|
| `surface` | **crt.sh** (assets/subdomains), **Shodan** (exposed hosts/services), **dnstwist** (look-alike domains), **GitHub** code search, search dorks (SerpAPI), **Have I Been Pwned**, **LeakCheck/DeHashed**, **Intelligence X** |
| `dark` | **Ahmia** (Tor index), **Intelligence X** (dark/breach buckets) |

- **Only-new reporting** — persistent state means a repeat finding is tracked
  silently; a brand-new one is what surfaces and alerts.
- **Runs out of the box on free sources** — crt.sh + Ahmia need no key;
  dnstwist just needs its CLI. Everything else lights up as you add API keys.
- **Optional alerts** — Slack/Teams/Discord webhook or SMTP email, fired *only*
  when there are new findings.
- **Modular** — a source is a ~20-line function; add your own (or a commercial
  feed) by copying an existing one.

## How it works

```
             +----------- sources (surface | dark) -----------+
 config.yaml | crtsh  shodan  dnstwist  github  serpapi  hibp  |
   (org,     | leakcheck  intelx        ahmia                  |
 domains,    +-------------------+----------------------------+
   keys)                         | Finding[]
                                 v
                        dedupe store (state/)  --->  only NEW findings
                                 |
                                 v
                 reports/ (markdown + json)  +  optional webhook/email
```

Each source returns `Finding` objects; the store assigns a stable dedupe key,
records `first_seen` / `last_seen`, and returns only findings not seen before.

## Install

Python 3.10+. A virtual environment is recommended (and required on Kali/Debian
due to PEP 668):

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# optional free extra for the dnstwist source:
pip install dnstwist             # or, on Kali/Debian: apt install dnstwist
```

## Configure

```bash
cp config.example.yaml config.yaml
```

Edit `config.yaml` — the only file you need to change:

```yaml
org_name: "lexcorp"
domains:
  - "lexcorp.dc"        # your REAL public domain (not an internal .local)
keywords:
  - "lock heed martin"
  - "palantir"
```

- Use your **public** domain(s); crt.sh discovers subdomains for you.
- Free/no-key: `crtsh`, `ahmia`. Free-with-CLI: `dnstwist`.
- Add keys when ready — a **free GitHub token** (public-repo, read-only) and a
  **Shodan** key are the highest-value first additions.
- `config.yaml` holds secrets — it is git-ignored and must never be committed.

Key reference:

| Config key | Source | Cost |
|------------|--------|------|
| *(none)* | crtsh, ahmia | free |
| *(CLI only)* | dnstwist | free |
| `github_token` | github | free token |
| `shodan_key` | shodan | cheap membership for search |
| `serpapi_key` | search_dorks | free tier / paid |
| `hibp_key` | hibp | subscription |
| `leakcheck_key` | leakcheck | paid |
| `intelx_key` | intelx | paid |
| `leakcheckio_key` | leakcheck_io | free
| `dehashed_key` | dehashed | free tier

## Usage

```bash
# one-shot (validate config / drive from a scheduler)
python -m pandora --config config.yaml --mode surface -v
python -m pandora --config config.yaml --mode dark -v

# continuous - runs until you press Ctrl-C, resumes state on restart
python -m pandora --config config.yaml --mode surface --loop --interval 12
```

Run surface and dark in two terminals to watch both at once. For hands-off
scheduling instead of `--loop`, use cron / systemd timers / Windows Task
Scheduler (examples below).

<details>
<summary>Scheduling examples</summary>

```cron
0  6,18 * * * cd /opt/pandora && .venv/bin/python -m pandora --config config.yaml --mode surface >> logs/surface.log 2>&1
30 6,18 * * * cd /opt/pandora && .venv/bin/python -m pandora --config config.yaml --mode dark    >> logs/dark.log 2>&1
```
Windows Task Scheduler: Basic Task -> daily, repeat every 12 h -> action
`python -m pandora --config config.yaml --mode surface`, "Start in" = repo folder.
</details>

## Output

```
reports/surface-<timestamp>.md    # new findings from that run (human-readable)
reports/surface-latest.json       # full current snapshot
state/surface-findings.json       # dedupe memory - keep it to resume; delete to reset
```

Example console summary:

```
=== breach hunt [surface] : 2 new / 37 total ===
  [HIGH    ] (github)   acme/backup/db.env  -> https://github.com/acme/backup/...
  [HIGH    ] (dnstwist) Look-alike domain registered: examp1e-hospital.com
```

## Extending

Add a source by copying one in `pandora/sources.py`:

```python
@source("mysource", modes=("surface",), key_of="mysource_key")
def mysource(cfg: dict) -> list[Finding]:
    ...
    return [Finding(source="mysource", mode="surface", title=..., severity="high")]
```

Register the key in `config.example.yaml` and it appears automatically.

## Roadmap

- [ ] Brave Search source (free alternative to SerpAPI dorks)
- [ ] gitleaks/trufflehog pass to confirm whether a code hit is a *live* secret
- [ ] theHarvester + Amass asset-discovery sources
- [ ] Commercial dark-web feed adapter (SpyCloud / Flare / Cybersixgill)
- [ ] HTML dashboard for the latest snapshot

## Responsible use

- Only query identifiers for an organisation you are **authorised** to monitor.
- Respect each source's Terms of Service and rate limits (the tool uses timeouts
  and polite delays - don't remove them).
- Treat findings as **evidence**: report exposed assets to their owner, get
  leaked secrets rotated/revoked, and don't access or log in to exposed systems
  to "confirm" a finding.
- See [SECURITY.md](SECURITY.md).

## License

MIT - see [LICENSE](LICENSE).
