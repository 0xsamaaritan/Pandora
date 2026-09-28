# Example report

A sanitised sample of what Pandora writes to `reports/` after a run. The
organisation, domains, hosts, and URLs below are fictional
(`lexcorp` / `lexcorp.com`) — this is only to show the output format.

Real runs write one of these per cycle as `reports/<mode>-<timestamp>.md`, plus
a full JSON snapshot at `reports/<mode>-latest.json`.

---

# Pandora — surface run @ 20260925-114352Z

- New findings this run: **4**
- Total tracked (surface): **41**

## New findings

### [HIGH] luthor-lexcorp.com (look-alike domain registered)
- source: `dnstwist`  |  matched: example.com
- url: http://luthor-lexcorp.com.com
- context: technique=replacement resolves_to=203.0.113.44

### [HIGH] acme-infra/backups/prod.env
- source: `github`  |  matched: example.com
- url: https://github.com/acme-infra/backups/blob/main/prod.env
- context: 'example.com' referenced in public code.

### [HIGH] Exposed service 198.51.100.20:3389 (RDP)
- source: `shodan`  |  matched: Example Hospital
- url: https://www.shodan.io/host/198.51.100.20
- context: host=vpn.example.com product=Microsoft Terminal Services org=Example Hospital

### [MEDIUM] Patient list — Example Hospital (pastebin)
- source: `search_brave`  |  matched: Example Hospital
- url: https://pastebin.com/xxxxxxxx
- context: Appointment export mentioning "Example Hospital" front desk...

---

## How to read this

- **New findings this run** is what changed since the previous run — the whole
  point of the tool. A finding that was already seen is tracked silently and
  does not reappear here.
- **Severity** is Pandora's triage hint, worst-first:
  `critical > high > medium > low > info`. Risky exposed services (RDP, SMB,
  databases), leaked code, and look-alike domains default to HIGH.
- Each finding names the **source** that produced it and which of your
  **matched** terms it hit on.

## What to do with it

Treat every finding as evidence to **remediate**, never to test:

| Finding type | Action |
|--------------|--------|
| Look-alike domain (`dnstwist`) | Report for takedown; watch for phishing using it |
| Secret in public code (`github`) | Have the owner **rotate/revoke** the secret and remove it |
| Exposed service (`shodan`) | Get it off the public internet / behind VPN; patch |
| Data on paste/leak site (`search_brave`, `intelx`) | Request removal; assess breach-notification duties |
