# Sendermap architecture

What Sendermap is for, how it is built, and the rules the code keeps. Read this before changing
anything structural.

## The question

"Which services send email as this domain, and how do we know?"

Every answer Sendermap gives is a claim about a service, backed by evidence a reader can check
for themselves in public data. A claim with no evidence is never shown, and the strength of a claim
is stated in words, from the evidence, never guessed.

## Principles

1. **Evidence first.** A source observes public facts and turns each into a claim about one
   service, carrying the evidence: "the SPF record at example.com includes servers.mcsv.net".
   Inference groups claims into services and ranks them. Rendering shows each service with the
   evidence under it.
2. **Say how sure, in words.** Four tiers for a sender, strongest first:
   - **In use**: the domain's mail is delivered there (MX).
   - **Configured**: set up to send as the domain (an SPF include, a DKIM key the service hosts
     through a CNAME, a bounce or tracking CNAME, a network the service owns in SPF).
   - **Likely**: a DKIM key known only by its name, or a script on the domain's website.
   - **Account only**: a trace of an account with nothing set up to send (a verification
     token, an autodiscover CNAME, a retired key).
   Services that only receive the domain's DMARC or TLS reports are shown as **reporting
   services**, never as senders.
3. **Silence is not absence.** A lookup that failed, timed out or was cut short is recorded as
   such. "Nothing found" is said only about names that were actually asked and answered.
4. **Public data only, read politely.** DNS, certificate transparency, the domain's own public web
   pages and public registry data. No logins, no guessing passwords, no sending mail. One request
   per resource, cached, rate limited.
5. **Plain words.** Every claim and finding reads as a sentence a non-specialist can follow, with
   the technical detail one click away.
6. **One engine, every surface.** The library is the product; the command line, the web site and
   the bulk scanner are thin layers over it.

## Layout

```
sendermap/
  model.py         Evidence, Claim, Service, Finding, SenderMap: frozen dataclasses
  catalog.py       the vendor catalog from sendermap/data/vendors.json, and every matching rule
  dns.py           a Resolver protocol, dnspython and DNS over HTTPS implementations, a cache
  sources/         one module per source; each returns an Observed: claims, unknowns, findings, gaps
    mx.py            MX hosts
    spf.py           the SPF tree: includes, redirects, nested wrappers, IP ranges, lookup count
    dkim.py          selector scan, CNAME chains, retired and dangling keys, wildcard canary
    labels.py        bounce, tracking and autodiscover CNAMEs at fixed labels
    tokens.py        verification tokens in TXT records
    reports.py       DMARC and TLS-RPT report addresses
    subdomains.py    sending subdomains from a wordlist and certificate transparency
    networks.py      who owns the IP ranges in SPF and the MX addresses (ASN over DNS)
    web.py           the homepage and privacy pages: forms, widgets, named subprocessors
    mta_sts.py       the MTA-STS policy and the MX hosts it names
    bimi.py          the BIMI record and logo
  infer.py         evidence to claims to services, tiers and roles
  findings.py      what needs attention: dangling CNAMEs, lookup limit, retired keys, unknowns
  engine.py        runs the sources concurrently under one budget and streams progress
  render/          text, Markdown and JSON
  cli.py           `sendermap example.com`
  web/             the site: an API that streams a map as it builds, and the static page
sendermap/data/vendors.json  the catalog: one block per service
tests/             a fake resolver, recorded fixtures, and the rules each test pins
```

## The data model

- `Evidence(name, rtype, value)` is one observed fact: a record at a name, or a line on a page.
- `Claim(service, kind, where, evidence)` says what a piece of evidence, found at `where` (the
  domain or one of its subdomains), shows about one service: its
  MX, an SPF include, a DKIM key by CNAME, a key by name, a bounce CNAME, a tracking CNAME, an
  owned network, a website script, a verification token, a report address.
- `Service(name, category, tier, role, claims)` is one row of the map. Its tier is the strongest
  of its claims, so a reader can always see which claim decided it.
- `Finding(severity, title, detail, evidence)` is something that needs attention.
- `Unknown(what, value, where)` is a clear sign of a sender that matches no service yet.
- `Gap(what, why)` is a lookup that did not complete, so its silence says nothing.
- `SenderMap(domain, services, findings, unknowns, gaps, subdomains_checked, logo, lookups,
  elapsed)` is the result,
  serialised to versioned JSON (`"schema": "sendermap/1"`).

## Rules carried from dns-audit

These were learned on live domains and each has a test:

- Hostname patterns match on label boundaries and the longest pattern wins
  (`u161779.wl030.sendgrid.net` is Klaviyo's own SendGrid account, not SendGrid).
- A DKIM key belongs to a service by CNAME first; `selector1` and `selector2` name nobody
  without the Microsoft CNAME; a generic name (`default`, `mail`, `s`, any two letters not
  allowed by name) names a service only when SPF or MX already shows it.
- Only authorizing SPF terms count: a bare or `+` include, or a redirect, before `all`.
  Includes inside a service's own record are that service, not an account at another.
- A service seen only by a bounce or tracking CNAME sends from that subdomain; it needs nothing
  in the main domain's SPF.
- A hosted SPF service (Valimail, OnDMARC) or a macro include can authorize a service without
  naming it, so no include is ever called missing behind one.
- A wildcard answers every name: each wave of probes asks one random name first, and an answer
  that matches the wildcard is not evidence.

## Surfaces

- **Library**: `await sendermap.map_domain("example.com")`.
- **Command line**: `sendermap example.com`, `--json`, `--markdown`, and `--list domains.txt`
  for a polite bulk scan.
- **Web site**: a FastAPI app. `GET /api/map?d=` streams progress and the finished map as
  server-sent events; the page draws the map as the evidence arrives. The server keeps no record
  of the domains looked up; results are cached in memory for a few minutes so a shared link
  opens instantly.

## Quality bar

- Python 3.12, typed throughout, `mypy --strict` and `ruff` clean.
- Small pure functions; side effects only in `dns.py`, `sources/` and the surfaces.
- Every rule above has a test with the live domain that taught it named in the docstring.
- No network in unit tests: a fake resolver serves recorded answers. A separate, opt-in suite
  runs against live DNS.
