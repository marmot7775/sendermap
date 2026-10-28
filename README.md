# Sendermap

<!-- mcp-name: io.github.marmot7775/sendermap -->

[![Test](https://github.com/marmot7775/sendermap/actions/workflows/test.yml/badge.svg)](https://github.com/marmot7775/sendermap/actions/workflows/test.yml)
[![Verify proofs](https://github.com/marmot7775/sendermap/actions/workflows/verify-proofs.yml/badge.svg)](https://github.com/marmot7775/sendermap/actions/workflows/verify-proofs.yml)

Type a domain, see every service that sends email as it, and the public evidence for each one.

**Status: early release (0.1.11).** The command-line tool works, and the website runs at [sendermap.dns-audit.com](https://sendermap.dns-audit.com).
Needs Python 3.12 or later.

## What it shows

For any domain, Sendermap builds a map of the services that send or receive its mail: mailbox
providers, marketing and transactional platforms, support desks, security gateways and the
services that receive its reports. Each one comes with:

- **The evidence**, record by record: the SPF include, MX host, DKIM key, bounce or tracking
  CNAME, verification token or report address that gave it away.
- **How sure we are**, in words, not a percentage (the terminal and the site show these as
  Receives your mail, Set up to send, Likely sends and Account only; the JSON keeps the tier
  names):
  - **In use**: mail for the domain is delivered there.
  - **Configured**: set up to send as the domain.
  - **Likely**: a signing key whose name points at the service.
  - **Account only**: a trace of an account with nothing set up to send.

It looks beyond the main domain: brands often send from subdomains such as `email.`, `mg.` or
`bounce.`, which a check of the main domain never sees. It also points out what needs attention:
DKIM records that point at names that no longer exist, SPF records past the 10 lookup limit,
revoked keys, and senders nobody can name. Raw IP ranges nobody can name are grouped by the
network that announces them, so a dozen ranges from one provider read as one line.

Each DKIM key is shown with the tags that change what it does: `t=y` (testing, so verifiers
treat mail signed with it as unsigned), `t=s` (strict), `h=` (hash algorithms), `s=` (service
types) and `k=` (key type). A tag that weakens the key, such as testing mode or SHA-1 only, is
raised as a finding. Each key also gets a fingerprint, `fp` and 16 hex characters, so the same
key published at two selectors is easy to spot, and the map points it out when it is.

## Looked for and not found

The map also lists what it looked for and did not find, with the DNS answers that show it. Today
that covers DKIM keys. Whether "not there" can be trusted depends on how the domain's DNS answers
for a name that does not exist, so at each name Sendermap first asks for a selector nobody
publishes and reads the answer as one of four classes:

- **Classic**: the zone says "no such name". Answers can be trusted. If `_domainkey` itself does
  not exist, no selector exists under it. The map checks only the few names the domain's SPF and
  MX point to, rather than its full list, and says so. If `_domainkey` exists but every name asked is missing, the map says selectors exist but
  none of the names it tried is one.
- **None by rcode**: the zone gives an empty answer for every missing name (compact denial), so
  the answer says nothing about what exists. The map asks its full list and claims no absence.
- **Wildcard**: every name answers. The map ignores what the wildcard repeats and asks its full
  list.
- **Unknown**: the test lookup failed, so nothing is read from it, and the map lists it as not
  checked.

## How it works

Everything comes from public sources: DNS, certificate transparency logs, the domain's own
website, and public records of who owns each network. Each finding is shown with the record
that supports it, so you can check it yourself.

- **SPF** is walked as a tree, crediting only links that actually authorize senders.
- **DKIM** keys are found by scanning the names services use, and credited by where they point.
  A plain name many hosts use, such as `s1`, credits its service (Klaviyo) only where the
  domain's SPF, MX or an NS delegation already shows that service.
- **Raw IP ranges** in SPF are named by matching them against the ranges each service publishes,
  then by who owns the network.
- **Sending subdomains** come from the names services ask for and from certificate logs. A
  subdomain delegated by NS to a service's nameservers, as Klaviyo and Salesforce Marketing
  Cloud set up, counts as that service's.
- **The website** shows the scripts and stylesheets it loads, the services it mentions, and the
  services its subprocessor page names. Every page fetch goes through one guard: https only,
  with the host's addresses checked first, so a domain cannot point a fetch at a private or
  internal address. A refused fetch is listed as not checked.
- **Certificate transparency**: Cert Spotter's log is read on every map for the subdomain search.
  With `--ct` (off by default), crt.sh is read too, since it also holds expired certificates,
  and every logged name is resolved now and matched like any DNS record, so a branded tracking
  link such as `link.example.com` pointing at an email platform shows up. A logged name that no
  longer resolves but still points at a service is listed as a possible past vendor, not a
  current sender. crt.sh is often slow; it is tried three times, each log's answers are cached
  for a day, and a log that never answers is listed as not checked while the map finishes
  without it.

Run it from the command line. It installs from PyPI (Python 3.12 or later):

```
pip install sendermap
uvx sendermap example.com             # run without installing
```

The latest code, ahead of a release, installs from GitHub with
`pip install git+https://github.com/marmot7775/sendermap`.

```
sendermap example.com
sendermap example.com --evidence     # every piece of evidence
sendermap example.com --markdown     # a summary to paste
sendermap example.com --json         # everything, for scripts
sendermap example.com --ct           # resolve every name in certificate logs, crt.sh too
sendermap example.com --claimed "Office 365, Mailchimp"   # hold the services you were told of against the map
sendermap example.com --json --output map.json            # write the map to a file
```

For scripts and agents: the exit code is 0 when the map was built, 2 for bad input and 3 when
the domain's own records could not be read (no map). Progress goes to stderr, and only to a
terminal, so stdout holds the map alone. `sendermap --help` explains every flag.

The website keeps no record of the domains looked up.

## MCP

With the `mcp` extra, `sendermap mcp` serves two tools over MCP on stdio: `sendermap_map`, whose
structured content is the map as `sendermap/1` JSON (summary or full), and `sendermap_vendor`,
one vendor's patterns, proofs and documented setup. The schema and the vendor list are resources.

```json
{
  "mcpServers": {
    "sendermap": { "command": "uvx", "args": ["--from", "sendermap[mcp]", "sendermap", "mcp"] }
  }
}
```

The website serves the same tools at `/mcp` over streamable HTTP. For agents without MCP,
[`skills/sendermap/SKILL.md`](skills/sendermap/SKILL.md) is an Agent Skill that runs the command
line and reads the JSON.

## Honest limits

- **No volume.** Public records show which services are set up to send, not how much mail each
  one sends, or whether it sent any this month.
- **No proof a key is in use.** A DKIM key in DNS shows it was published, not that anything
  signs with it. Only real mail shows that, and Sendermap reads no mail.
- **No sight of vendors sending from their own domain.** A service that mails your customers from
  its own domain, such as a receipt from a payment platform, leaves nothing in your DNS.
- **Selector discovery is never complete.** DNS cannot list DKIM selectors. Sendermap asks the
  names services are known to use and some common ones, and says how many it asked. A key under
  any other name stays unseen.
- **Absence is read from how the zone answers, and said as such.** "Not there" is claimed only
  where the zone's denial class makes the answer trustworthy, and every such line carries the
  answers it rests on.

## The JSON contract

`sendermap DOMAIN --json` and the site's API give one map as JSON, schema `sendermap/1`,
described by [`sendermap/data/schema/sendermap-1.json`](sendermap/data/schema/sendermap-1.json)
(JSON Schema 2020-12; `sendermap.schema()` in Python, `/schema/sendermap-1.json` on the site).
`sendermap/1` grows by addition only: new fields and new values (a new kind of evidence, a new
gap kind) may appear, and nothing is removed, renamed or changed in meaning. Ignore fields you do
not know and tolerate values you do not know. A breaking change would be `sendermap/2`.

## The vendor data

All vendor knowledge lives in one file, [`sendermap/data/vendors.json`](sendermap/data/vendors.json), one block per
service, so adding or correcting a vendor is a small pull request. The first version was imported
from the vendor tables in [dns-audit](https://github.com/marmot7775/dns-audit) (MIT).

## Contributing

Each vendor gets one block in `sendermap/data/vendors.json`, and everything known about it goes
there. Every pattern in a block (an SPF include, an MX host, a CNAME target, a report address, a
verification token, a network, a website host, a selector name, a subprocessor name) carries one
proof of its own: a live domain that publishes it, the record name or page as found, and the
date checked (a numbered series of selectors such as s1, s2 needs one for the series). A pattern without a proof
does not get merged, and Sendermap refuses to load one. A block may also list `aliases`, the
other names customers call the service by ("Office 365" for Microsoft 365). An alias needs no
proof, since it matches only what a person types, never a record.

Patterns not yet proven wait in `sendermap/data/vendors_pending.json`, each block with a note of
what was checked; Sendermap never reads that file, so a record they would match shows as not
recognised. A vendor moves from pending to vendors.json with one proof per pattern, the same rule
as any new block. `tools/hunt_proofs.py` looks for those proofs on the customer domains in
`data/hunt_domains.txt`, with the same checks as the weekly recheck.

Which vendor to add next comes from [the benchmark](benchmark/README.md): `tools/benchmark.py`
maps the same 300 domains each release and ranks what it could not name by how many domains
publish it. On 0.1.7, 83 such groups showed at two domains or more.

Every proof is rechecked against live DNS and the web each week and on any pull request that
touches `vendors.json`. A proof that no longer holds opens an issue, so a stale pattern is caught
and fixed.

A tag `v*` builds the release files and, while the repository variable `PYPI_READY` is `true`
(Settings, Secrets and variables, Actions, Variables), publishes them to PyPI by trusted
publishing and makes the GitHub release with the tag's notes from `CHANGELOG.md`.

## Related

- [dns-audit.com](https://dns-audit.com): a full email security audit of a domain.

## License

MIT
