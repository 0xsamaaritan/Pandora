# Security & Responsible Use

`pandora` is a **defensive** tool for monitoring an organisation's own
exposure. Use it only against identifiers (names, domains, keywords) for an
organisation you are authorised to protect.

## Handling findings

- **Do not access, log in to, or probe** any exposed system, account, or app a
  finding points to — even one belonging to your own organisation — without
  explicit, documented authorisation. "The credentials worked" is already the
  finding; you don't need to go inside to prove it.
- Treat any leaked secret (API key, password, connection string, token) as
  **compromised**. The correct response is to have its owner **rotate/revoke**
  it and remove the exposure — never to test whether it still works.
- Report exposed assets and leaks through your organisation's incident/risk
  process so remediation and any legal/regulatory duties (e.g. DPDPA breach
  notification) are handled properly.

## Operational safety

- Keep `config.yaml`, `state/`, and any tokens out of version control (see
  `.gitignore`). Rotate API tokens on a schedule; revoke immediately if leaked.
- Respect every data source's Terms of Service and rate limits. The tool's
  built-in timeouts and delays exist for this reason — do not remove them.

## Reporting an issue with this tool

Open a GitHub issue for bugs. For anything sensitive, contact the maintainer
privately rather than filing a public issue.
