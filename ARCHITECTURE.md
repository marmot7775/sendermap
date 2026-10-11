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
  domain itself or one of its subdomains. When the evidence alone does not name the service, the
  claim also carries the records that do (`supporting`): for an IP range in SPF, the term in
  the service's own SPF record that publishes the holding range, or Team Cymru's answers for
  the network that announces it; for a DKIM key credited through a backed selector, the SPF or
  MX record that backed it. Every view shows them after the evidence, as "via".
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
- **Unknown**: a record that clearly points at a sender no service in the vendor data matches,
  with the Evidence that shows it, which every view prints with it.
- **Gap**: a question that got no usable answer: what was `asked` (the record type and name,
  the page, or the check) and what `happened` (the lookup failed, HTTP 404, the check was turned
  off, the source crashed), so its silence is not read as absence.
- **Absence**: a question answered "not there": what was `asked`, what `happened`, and the
  negative answers that show it as `evidence` (each an Evidence whose value is the status in
  words, such as `no such name`). Unlike a gap, it can be read as absent. Today only the DKIM
  source records one; see "The _domainkey triage" below.
- **Checked**: what was asked at one name: the DKIM selectors probed, the labels whose CNAMEs
  were asked, the pages requested (homepage, subprocessor page, MTA-STS policy), and the
  `denial`: how the zone under the name's `_domainkey` answers for names that do not exist
  (`classic`, `none by rcode`, `wildcard`, or `unknown`, the default where DKIM was not read).
  With the gaps and absences, it says what the map's silence covers.
- **CertificateEvidence**: the evidence type of the CT source: an Evidence (`rtype`
  `certificate`, `name` the hostname) that also carries the latest certificate's `not_before`
  and `not_after`, and the CNAME `target` that matched, when a CNAME did.
- **Historical**: a name in certificate logs that no longer resolves but whose leftover CNAME
  points at a service: a possible past vendor, kept apart from the services.
- **CtSummary**: whether CT was off, read from crt.sh, read from the cache, or unavailable, with
  counts of names logged, resolved, and gone without naming a service.
- **Run**: when and how one map was made: `checked_at`, `elapsed` seconds and DNS `lookups`.
- **SenderMap**: the domain, its services, findings, unknowns, gaps, the sending subdomains
  checked, one Checked per name, the BIMI logo if any, the absences, and the Run. `to_dict()` gives JSON with
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
  ct.collect (--ct)     -> crt.sh names, each resolved for CNAME, A and MX and matched
Phase 2, the domain itself
  backed = generic DKIM names that belong to services SPF or MX already shows
  probe order = selector rules ranked by MX and SPF hints, then the generic names
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
published ranges, 2,000,000 bytes of a web page, 5 redirects of a web page, and 200 names from
crt.sh.

## Fetching pages

A domain chooses the address its pages are served from, so on the server a page fetch could be
pointed back at the server itself or at a cloud metadata address. Every page fetch, the
homepage, the subprocessor page (which may sit on another host) and the MTA-STS policy, goes
through one guard in `sources/web.py`:

- https on port 443 only;
- before the request, the host's A and AAAA records are asked through the map's lookups (cached,
  counted, and faked in tests); the fetch is refused when either lookup failed, when the host
  has no address, or when any address is private, loopback, link local, multicast, reserved or
  unspecified (an IPv4 address inside IPv6 is judged as IPv4); a host that is an address
  literal is judged as that address;
- redirects are not followed by the HTTP client: up to 5 are followed by hand, each Location
  checked the same way before it is requested, and a sixth is a gap. The MTA-STS policy follows
  none, as RFC 8461 requires.

A refused fetch sends no request and is a gap worded `not fetched: <reason>`. Each request keeps
the 10 second timeout (8 for the MTA-STS policy) and the 2,000,000 byte cap on a web page.

The guard's limit: the address is checked before the request and not pinned during it. The HTTP
client resolves the name again when it connects, so a name that answers with a public address
for the check and a private one a moment later (DNS rebinding) is not caught.

## Modules

| Module | Owns |
|---|---|
| `model.py` | The result types above, and which Tier each Kind supports |
| `dns.py` | The Resolver interface, the system and DNS-over-HTTPS resolvers, and `Lookups`: the per-map cache that asks each name and type once and counts the queries |
| `catalog.py` | Loading vendors.json into match tables, refusing any pattern without a proof; matching a host, token or selector to a service |
| `proofs.py` | The Proof type and the checks every proof must pass on loading |
| `selectors.py` | DKIM selector rules with proofs: parsing and checking them, and ordering the probes |
| `infer.py` | Turning claims into ranked services; the map of backed selectors |
| `engine.py` | `map_domain`: input cleaning, the phase order, subdomain scans, limits, the gateway note |
| `sources/spf.py` | Walking the SPF tree: credited includes, IP ranges, the lookup count, SPF findings |
| `sources/mx.py`, `sources/mta_sts.py` | Where the domain receives mail |
| `sources/web.py` | The homepage and subprocessor page, and the guard every page fetch goes through |
| `sources/dkim.py` | DKIM probing, the wildcard check, reading keys, dangling and short keys |
| `sources/labels.py`, `tokens.py`, `reports.py`, `bimi.py` | Fixed-label CNAMEs, verification TXT, report addresses, the BIMI logo |
| `sources/networks.py` | Naming SPF IP ranges by the ranges services publish, then by network owner |
| `sources/ct.py` | Certificate transparency (`--ct`): crt.sh with retries and a one-day disk cache, then each logged name resolved and matched by the same catalog matchers as the DNS sources |
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

## The _domainkey triage

Beside the wildcard check at `sendermap-wildcard-check._domainkey.<where>`, the DKIM source asks
TXT at `_domainkey.<where>` itself and reads the two answers together. The wildcard check's
answer is the zone's denial class, recorded on Checked:

- **classic**: no such name. The zone denies names that do not exist with NXDOMAIN, so no such
  name at `_domainkey` means no selector exists below it (RFC 8020 section 2, RFC 4592 section
  2.2.3), and an empty answer there (no record of this type) means at least one does.
- **none by rcode**: an empty answer. The zone answers NOERROR for names that do not exist
  (compact denial or black lies, RFC 9824), so the answer code says nothing about existence.
  The sweep runs as it always has.
- **wildcard**: an answer. A key there is the wildcard path above; anything else is ignored
  wherever it echoes, and the sweep runs.
- **unknown**: the check failed. The sweep runs, with the gap it has always had.

In a classic zone whose `_domainkey` is no such name, the full sweep is not run. Only the names
the domain's MX and SPF back or hint at are asked (every backed name and the first 8 of the
ranked order), as a check on servers that answer no such name for a name with names below it
(RFC 8020 section 5). If none of them exists, the result is an Absence, "DKIM keys at <where>:
no selectors exist", whose text says the sweep was not run and why, so the unasked names are
explained the way a cap explains them, and whose evidence is the two negative answers. For a
sending subdomain this also replaces the gap for the 27-name budget, which did not apply. If one
of them exists, there is no Absence: a gap says the server answered no such name at the node
but a key (or a record) exists at that name, so existence could not be read from it, and the
full sweep runs.

In a classic zone whose `_domainkey` is an empty answer, the sweep runs, and when every name it
asked is no such name the result is an Absence, "selectors exist but none of the N names asked
is one", with the node's answer as evidence. A name that answers anything (a key, a revoked
key, a malformed record, a dangling CNAME) is a selector, so then there is no Absence, and a
failed lookup leaves the gap it has always left. Absences are shown in every view under
"Checked and not there", each with its evidence; JSON carries them as `absences` and each
Checked's class as `denial`.
- An IP range in SPF, IPv4 or IPv6, is named by the narrowest range a service publishes in its own SPF record
  that contains it, when exactly one service publishes that range. Otherwise the network that
  announces it decides, from Team Cymru's IP to ASN data over DNS (`origin` for IPv4, `origin6`
  for IPv6), sampled at three points for a range wider than an IPv4 /24 or an IPv6 /48: the
  range goes to the service the vendor data lists as owning that network. Anything left is
  listed as unknown, with the cloud named when the network is a shared cloud and the services
  that publish the range. A cloud is never credited: 74.125.0.0/16, published by Google
  Workspace and HubSpot and announced by Google's network, stays unknown.
- A name from certificate logs (`--ct`) is matched with the matchers the DNS path uses: each
  hop of its CNAME chain through `label_cname` with the name's first label, as a label CNAME
  is; then its MX hosts through the MX table; then its addresses through the published ranges
  and network owners, as SPF ranges are (Likely only: a web host is not mail set up). Its claim
  gets the Kind the DNS path gives the same record (a subdomain MX; a bounce, tracking or
  autodiscover CNAME when its label is one the DNS path asks for), or, for a CNAME at any other
  label, "CNAME into its zone", which does not guess what the CNAME is for. It counts
  as gone when its address lookup says no such name and it has no MX; gone with a CNAME that
  still names a service, it is a possible past vendor. At most 200 names are resolved, with a
  gap for the rest.
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
website hosts, the names a subprocessor page would list it by), plus shared `rules` (generic selectors, hosted SPF services, cloud networks,
the labels to probe). `catalog.load` reads the file once per process, selector rules included.

Every SPF include, MX host, DKIM CNAME target, bounce, tracking and other CNAME, report address,
verification token, network, website host and subprocessor name is an entry with its value and
a proof: a domain that publishes it, the record (a DNS name, or a page's URL) and the date
checked. A subprocessor name's proof is a page on the vendor's own site that uses the name; only
sending services list one, and a name that is also an ordinary word ("Kit", "Wix") is not
listed, so the web source has no rule of its own about which names count. `catalog.build`
refuses an entry without one, and checks that the record could show the pattern: a report
address at `_dmarc.` or `_smtp._tls.` of the domain, a token at the domain itself, a DKIM CNAME
under its `_domainkey`, a website host or subprocessor name on an https page of the domain,
anything else at or under the domain. `proofs.py` holds those checks.

A `selectors` entry names a vendor's DKIM selectors with how they are known (the vendor's docs,
a pattern, an aggregate report, or the vendor's own domain) and a proof per name: a live domain
that publishes the record, the record name and the date checked. Loading refuses an entry
without one. These entries are the only list of vendor selectors: they credit a key by its
name, give the names a service shown by SPF or MX backs, and make the probe sweep, which is
every name they claim, in rule order with the rules the domain's MX and SPF hint at first, then
the generic names (`default`, `dkim`, `mail` and the rest), which credit nobody by name but show
that a key is there.

`sendermap/data/vendors_pending.json` holds the patterns with no proof yet, in the same block
shape, each block with a note of where they were looked for. Nothing in the package reads it, so
a record only a pending pattern would match is reported as not recognised: an SPF include, MX
host, report address or network as it always was, a bounce or tracking CNAME into a zone outside
the domain as "CNAME at <label>" with its target, and a DKIM key behind a CNAME with the chain it
is served through. A test watches every file the engine opens and fails if the pending file is
one. `tools/verify_proofs.py` rechecks every proof against live DNS and, for website hosts, the
page; the `Verify proofs` workflow runs it weekly and on any pull request that touches
vendors.json.

A vendor's own domain rarely publishes what it asks its customers to publish, so
`tools/hunt_proofs.py` looks for the pending patterns on customer domains: `data/hunt_domains.txt`,
the top 2,000 of a Tranco list (its id and date on the first line) and three retail brands. At each
domain it reads what the engine reads (SPF down the whole include chain, MX, DKIM keys at every
proven, pending and generic selector name, the bounce and tracking labels, report addresses,
tokens, networks, the sending subdomains and one fetch of the homepage), one query at a time per
domain with domains in parallel, and confirms each find with the check `verify_proofs.py` defines
for its kind, so found means the same in both. A name under a wildcard proves nothing. Answers and
pages are cached on disk, so a rerun asks only what failed. The highest ranked domain that shows a
pattern becomes its proof; `--move` moves proven patterns into vendors.json.

## Surfaces

- **Library**: `await sendermap.map_domain("example.com", checked_at=datetime.now(UTC))`.
  Optional: `resolver`, `http`, `use_web`, `use_subdomains`, `use_ct` (off by default) with
  `ct_cache` (a directory, or None for no cache), and a `progress` callback.
- **Command line**: `sendermap example.com`, with `--json`, `--markdown`, `--evidence` (every
  claim, not only the deciding one), `--no-web`, `--no-subdomains`, `--ct` (names from
  certificate logs, cached in `$XDG_CACHE_HOME/sendermap/crtsh` or `~/.cache/sendermap/crtsh`)
  and `--doh` (Cloudflare DNS over HTTPS). The web site does not use CT.
- **Web site**: a FastAPI app. `GET /api/map?d=` returns the map as JSON, `GET /api/map.md?d=`
  as Markdown, and `GET /api/map/stream?d=` streams progress then the map as server-sent events.
  Uvicorn's access log is turned off when the app starts, so no query string is logged; a test
  runs a real server and checks that a request logs nothing. Visitor addresses are held in
  memory for one minute for the rate limit.
  Results are kept in memory for ten minutes, keyed by domain only, and concurrent requests for
  one domain share one build. At most six maps build at once, and each visitor may make twelve
  map requests a minute.

## Tests

`tests/conftest.py` provides a fake DNS zone (`Zone`) with CNAMEs, wildcards, names that fail
on purpose, empty non-terminals that exist (RFC 8020), a compact denial mode and names forced to
no such name, and an HTTP client that answers the certificate log with nothing and fails the test
on any other request, so the suite never reaches the network (the web test serves on loopback
only). `Zone.public` gives a host a public address, which a fake page needs to pass the fetch
guard. Run `pytest`. `mypy` (strict, over `sendermap/`, `tests/` and `tools/`), `ruff check` and
`ruff format --check` pass on the whole repository.

Tests that hold the rules: `test_evidence.py` maps a fake domain that reaches every kind of
claim and requires evidence on every claim, unknown and finding, and the supporting records on
every claim whose evidence does not name its service; `test_dkim_denial.py` holds the
_domainkey triage for each denial class, the absences with their evidence, and their rendering;
`test_gaps.py` and `test_caps.py`
require a gap for each failed question and each cap; `test_web_guard.py` requires that a
refused fetch sends nothing and is a gap, for each reason the guard refuses, on every redirect
and on the subprocessor and MTA-STS pages; `test_checked.py` requires the record of
what was asked and its rendering; `test_labels_say_what_was_seen.py` holds the wording of the
labels; `test_determinism.py` requires the same map from the same answers;
`test_vendor_proofs.py`, `test_one_selector_list.py` and `test_subprocessor_names.py` require a
proof on every vendor pattern and one proofed selector list read once; `test_pending_vendors.py`
requires that the engine never opens the pending file and that a host only a pending pattern
matches shows as not recognised; `test_hunt_proofs.py` holds where the hunt may find each kind of
pattern, which domain's proof wins, that a rerun asks nothing and that a moved proof loads. `test_ct.py` runs the CT source on a recorded crt.sh answer
(`tests/fixtures/crtsh_allbirds.json`).
