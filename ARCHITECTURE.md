# Sendermap architecture

Sendermap answers one question: which services send email as this domain, and what public
record shows it? This file describes the code as it is. Where the code falls short of the
rules it is meant to keep, the gap is named below rather than left out.

## The result

Everything Sendermap reports is built from a few frozen dataclasses in `sendermap/model.py`.

- **Evidence**: one observed public fact: the name it was found at, the record type (or `page`
  or `policy` for web content), the value, and `checked_at`, the moment of the run.
- **Claim**: what one piece of evidence shows about one service, of one **Kind** (an MX host, an
  SPF include, a DKIM key behind a CNAME, a verification token, and so on), at one name: the
  domain itself or one of its subdomains.
- **Service**: one row of the map: a name, a category from the vendor data, a tier, a role and
  its claims. The tier is the strongest tier among its claims, so a reader can always find the
  claim that decided it (`Service.decided_by`).
- **Tier**: how sure the map is that a service sends, in words, strongest first:
  - **In use**: an MX record at the domain.
  - **Configured**: an authorizing SPF include, a range in SPF that a service publishes or
    whose network it owns, a DKIM key served through a CNAME into the service's zone, a bounce
    or tracking CNAME, a sending service's MX on a subdomain, a permitted MX host in the
    MTA-STS policy (the policy lists hosts allowed to receive, in any mode, not where mail
    goes), or a mailbox provider's or security gateway's MX on a subdomain. That last claim
    reads "in use for a subdomain's mail" and is in use there only, so it does not make the
    service In use for the whole domain.
  - **Likely**: a DKIM key known only by its selector name; a script or stylesheet the homepage
    loads from the service's host (a `script src` or `link href`); the service's host
    mentioned anywhere else in the homepage's HTML (a link, a form, text); or the service named
    as a subprocessor.
  - **Account only**: a verification token, an autodiscover CNAME, a revoked DKIM key (an empty
    `p=`), or a DKIM CNAME to a name that no longer exists.
- **Role**: `sender`, or `reporting` for a service that only receives the domain's DMARC or
  TLS reports. A reporting service has no tier (`null` in JSON): nothing shows that it sends.
- **Finding**: something that needs attention (a dangling DKIM CNAME, SPF over ten lookups,
  a short key), with a severity of risk, warning or note.
- **Unknown**: a record that clearly points at a sender no service in the vendor data matches.
- **Gap**: a question that got no usable answer: what was `asked` (the record type and name,
  the page, or the check) and what `happened` (the lookup failed, HTTP 404, the check was turned
  off, the source crashed), so its silence is not read as absence.
- **Checked**: what was asked at one name: the DKIM selectors probed, the labels whose CNAMEs
  were asked, and the pages requested (homepage, subprocessor page, MTA-STS policy). With the
  gaps, it says what the map's silence covers.
- **Run**: when and how one map was made: `checked_at`, `elapsed` seconds and DNS `lookups`.
- **SenderMap**: the domain, its services, findings, unknowns, gaps, the sending subdomains
  checked, one Checked per name, the BIMI logo if any, and the Run. `to_dict()` gives JSON with
  schema `sendermap/1`.

## From domain to result

```
pasted text ─ clean_domain (engine) ─> domain
  Context = domain + Lookups (one DNS cache per map, counts queries)
          + Catalog (vendors.json) + checked_at + optional HTTP client
Phase 1, concurrent
  spf.collect(domain)   -> claims + SpfTree (IP ranges, include hints, lookup count)
  mx, tokens, reports, labels, mta_sts, web   -> claims, unknowns, findings, gaps
  bimi.logo             -> logo URL, not evidence
  subdomains.discover   -> wordlist + CT log names that publish SPF or MX
Phase 2, the domain itself
  backed = generic DKIM names that belong to services SPF or MX already shows
  probe order = selector rules ranked by MX and SPF hints, then the sweep list
  dkim.collect  ||  networks.collect (SPF IP ranges: published vendor ranges, then ASN)
Phase 3, each sending subdomain (first 30)
  spf + mx -> backed -> dkim (27 names + backed)  ||  networks
Assembly
  all Observed summed -> infer.services: group by service,
     tier = strongest Kind, report-only services -> role "reporting"
  findings sorted by severity, + gateway note; unknowns and gaps deduplicated
  -> SenderMap + Run -> render.text | render.markdown | to_dict JSON | web stream
```

Each source returns an `Observed`: claims, unknowns, findings, gaps and what it checked. Sources never raise
for a failed lookup: every DNS answer has a status (`ok`, `no such name`, `no record of this
type`, `lookup failed`), and every source turns a failed lookup or page into a gap, while an
answer of no such name or no record is an absence. A failed network-owner lookup leaves the
range listed as unknown with "network lookup failed", not "no network". If the MX, token,
report, label, MTA-STS or website source or the subdomain search raises an exception, it
becomes a gap that says it crashed instead of losing the map. A check turned off by the caller
(`--no-web`, `--no-subdomains`) is a gap too, and with both off the MTA-STS policy is not
fetched, which is also a gap.

Every cap that leaves names unasked records a gap naming the cap and the count it dropped: 30
sending subdomains, 27 DKIM names per sending subdomain beyond the ones its SPF or MX backs, 24
SPF ranges for the network lookup, 60 names from the certificate log and names more than two
labels below the domain, an SPF depth of 10, a vendor's own SPF read 3 levels deep for its
published ranges, and 2,000,000 bytes of a web page.

## Modules

| Module | Owns |
|---|---|
| `model.py` | The result types above, and which Tier each Kind supports |
| `dns.py` | The Resolver interface, the system and DNS-over-HTTPS resolvers, and `Lookups`: the per-map cache that asks each name and type once and counts the queries |
| `catalog.py` | Loading vendors.json into match tables; matching a host, token or selector to a service |
| `selectors.py` | DKIM selector rules with proofs: loading and checking them, and ordering the probes |
| `infer.py` | Turning claims into ranked services; the map of backed selectors |
| `engine.py` | `map_domain`: input cleaning, the phase order, subdomain scans, limits, the gateway note |
| `sources/spf.py` | Walking the SPF tree: credited includes, IP ranges, the lookup count, SPF findings |
| `sources/mx.py`, `sources/mta_sts.py` | Where the domain receives mail |
| `sources/dkim.py` | DKIM probing, the wildcard check, reading keys, dangling and short keys |
| `sources/labels.py`, `tokens.py`, `reports.py`, `bimi.py` | Fixed-label CNAMEs, verification TXT, report addresses, the BIMI logo |
| `sources/networks.py` | Naming SPF IP ranges by the ranges services publish, then by network owner |
| `sources/subdomains.py` | Finding sending subdomains from a wordlist and the certificate log |
| `render/text.py`, `render/markdown.py` | The terminal and Markdown views; both show the gaps and what was asked at each name, as the web page does |
| `cli.py` | The `sendermap` command |
| `web/app.py` | The site: a page, and an API that streams progress and the finished map |

## Matching rules

These live in `catalog.py` and the sources, and each has a test.

- A hostname pattern matches the host or any name under it, on a label boundary, and the
  longest pattern wins: `u161779.wl030.sendgrid.net` is Klaviyo, not SendGrid.
- A DKIM key belongs to a service by CNAME first. `selector1` and `selector2` name nobody
  without the Microsoft CNAME. Next, a selector on the list of a service that SPF or MX already
  shows is that service's. Last, the name table, except for generic names (`default`, `mail`,
  any two-letter name not explicitly allowed).
- The SPF lookup count follows receivers: an include met twice adds the lookups of everything
  below it each time, read from the lookup cache, so no record is asked twice. An include that
  is already being evaluated above itself is a loop, reported as a risk.
- Only authorizing SPF terms are credited: a bare or `+` include or redirect, before `all`.
  A redirect is ignored when the record has `all`. Inside a service's own record nothing more
  is credited, except inside a flattening service's record (EasyDMARC), which copies the
  domain's own senders.
- A hosted SPF service (Valimail, OnDMARC, EasyDMARC) or a macro include is reported as a note,
  since it can authorize services without naming them.
- A wildcard answers every name, so DKIM probes and label CNAMEs first ask a fixed name nobody
  publishes (`sendermap-wildcard-check`). A wildcard DKIM key ends the DKIM scan at that name
  with a note; a label CNAME that matches the wildcard target is ignored.
- An IP range in SPF, IPv4 or IPv6, is named by the narrowest range a service publishes in its own SPF record
  that contains it, when exactly one service publishes that range. Otherwise the network that
  announces it decides, from Team Cymru's IP to ASN data over DNS (`origin` for IPv4, `origin6`
  for IPv6), sampled at three points for a range wider than an IPv4 /24 or an IPv6 /48: the
  range goes to the service the vendor data lists as owning that network. Anything left is
  listed as unknown, with the cloud named when the network is a shared cloud and the services
  that publish the range. A cloud is never credited: 74.125.0.0/16, published by Google
  Workspace and HubSpot and announced by Google's network, stays unknown.
- A DKIM key's size is read from the key: the RSA modulus length, or 256 for Ed25519.
- DKIM tags are read by exact name, so `ap=` is not `p=`. A record with no `p=` tag at all is
  malformed, a warning of its own; an empty `p=` is a revoked key. A wildcard answer that is
  not a key is ignored wherever it echoes.
- A security gateway in the domain's MX is a note that states what MX shows and is labelled as
  inferred from it. A flattening SPF service (EasyDMARC) is a note that says whether the walk
  read its record; other hosted services and macro includes are a note that they can authorize
  services without naming them.

## Determinism

The same DNS answers (and the same web pages and certificate log, when those are read) and the
same `checked_at` give the same map. `map_domain` takes
`checked_at` from the caller and refuses one without a timezone. Only the Run's `elapsed`
differs between such runs, and `SenderMap` equality ignores the Run. The SPF walk asks for every
reachable record at once, then walks the tree depth first in the order of its terms, so its
output never follows DNS timing. The vendor range table is built per map through the same
lookups and counted with them. `tests/test_determinism.py` maps one busy fake domain twenty
times with random delays on every answer and requires identical output.

## The vendor data

All vendor knowledge is in `sendermap/data/vendors.json`: one block per service with its
category and the patterns that identify it (SPF includes, MX hosts, DKIM CNAME targets and
selector names, bounce and tracking CNAMEs, report addresses, verification tokens, networks,
website hosts), plus shared `rules` (generic selectors, hosted SPF services, cloud networks,
the labels and selectors to probe).

A `selectors` entry names a vendor's DKIM selectors with how they are known and a proof: a live
domain that publishes the record, the record name and the date checked. Loading refuses an entry
without one. Four vendors have such entries so far; they set the order of DKIM probes. Every
other pattern, including the `dkim_selectors` lists used to credit keys, carries no proof yet.
`tools/verify_proofs.py` rechecks every proof against live DNS; the `Verify proofs` workflow runs
it weekly and on any pull request that touches vendors.json.

## Surfaces

- **Library**: `await sendermap.map_domain("example.com", checked_at=datetime.now(UTC))`.
  Optional: `resolver`, `http`, `use_web`, `use_subdomains`, and a `progress` callback.
- **Command line**: `sendermap example.com`, with `--json`, `--markdown`, `--evidence` (every
  claim, not only the deciding one), `--no-web`, `--no-subdomains` and `--doh` (Cloudflare DNS
  over HTTPS).
- **Web site**: a FastAPI app. `GET /api/map?d=` returns the map as JSON, `GET /api/map.md?d=`
  as Markdown, and `GET /api/map/stream?d=` streams progress then the map as server-sent events.
  Uvicorn's access log is turned off when the app starts, so no query string is logged; a test
  runs a real server and checks that a request logs nothing. Visitor addresses are held in
  memory for one minute for the rate limit.
  Results are kept in memory for ten minutes, keyed by domain only, and concurrent requests for
  one domain share one build. At most six maps build at once, and each visitor may make twelve
  map requests a minute.

## Known limits

These are open items from the October 2026 review, listed so the description above is not read
as more than it is.

- Some claims leave out a record that decided them: a range credited by a published range or a
  network carries the domain's `ip4:` or `ip6:` term with the reason in words, not the vendor's
  record or Team Cymru's answer; a DKIM key credited through a backed selector does not carry
  the SPF or MX claim that backed it; an Unknown carries no Evidence.

## Tests

`tests/conftest.py` provides a fake DNS zone (`Zone`) with CNAMEs, wildcards and names that fail
on purpose, and an HTTP client that answers the certificate log with nothing and fails the test
on any other request, so the suite never reaches the network. Run `pytest`. `mypy --strict` and
`ruff check` pass on `sendermap/`; the tests and tools are not yet typed strictly.
