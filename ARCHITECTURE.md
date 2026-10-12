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
- **Service**: one row of the map: a name, a category from the vendor data, a tier, a role,
  its claims and its setups. The tier is the strongest tier among its claims, so a reader can
  always find the claim that decided it (`Service.decided_by`).
- **Setup**: a vendor's documented setup at one name where the service has claims: one
  **SetupItem** per record the setup lists (its need, its state, the evidence for that state,
  what was asked and a detail), and `complete`. See "Setups" below.
- **Tier**: how sure the map is that a service sends, in words, strongest first:
  - **In use**: an MX record at the domain.
  - **Configured**: an authorizing SPF include, a range in SPF that a service publishes or
    whose network it owns, a DKIM key served through a CNAME into the service's zone, a bounce
    or tracking CNAME, a sending service's MX on a subdomain, a subdomain delegated by NS to
    the service's nameservers, a permitted MX host in the
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
  a short key, a key in testing mode, one key at two selectors), with a severity of risk,
  warning or note.
- **Unknown**: a record that clearly points at a sender no service in the vendor data matches,
  with the Evidence that shows it, which every view prints with it.
- **Gap**: a question that got no usable answer: what was `asked` (the record type and name,
  the page, or the check) and what `happened` (the lookup failed, HTTP 404, the check was turned
  off, the source crashed), so its silence is not read as absence. Its **GapKind**, set by the
  source that records it, says what it leaves unchecked: `website`, `page` (the subprocessor
  page), `certificate_log`, `subdomains`, `dkim`, `labels`, `spf`, `mx`, `networks`,
  `published_ranges`, `reports`, `tokens`, `mta_sts`, or `off` for a check the caller turned
  off. The default, `other`, is never left on a gap the engine records. `count` is how many
  names, ranges or selectors it leaves unanswered when the source counted them (0: the check as
  a whole), and `cap` the limit that left them unasked (0: a failure). All three are in JSON.
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
- **CtSummary**: whether the logged names were resolved and matched (`off` without `--ct`,
  `unavailable` when no certificate log answered), with counts of names logged by all providers
  together, resolved, and gone without naming a service, and one **CtProvider** per certificate
  log: its name, whether it was read, read from the cache, unavailable or off, and how many names
  under the domain it logged.
- **Reconciliation**: the services a client says they use, held against the map, in four parts,
  each a **Reconciled** (the service, its tier in the map, the names the client wrote for it):
  `confirmed`, claimed and found, with the tier; `unclaimed`, every sending service found that
  nobody claimed (a reporting service is never unclaimed); `unfound`, claimed and known but with
  no claim at any name checked; and `unknown`, the claimed names no service goes by, kept as the
  client wrote them, so a client's words are never silently dropped. See "Claimed senders".
- **Story**: one paragraph, a string, written by rules from the map for a reader who runs a
  company. See "The story".
- **Run**: when and how one map was made: `checked_at`, `elapsed` seconds and DNS `lookups`.
- **SenderMap**: the domain, its services, findings, unknowns, gaps, the sending subdomains
  checked, one Checked per name, the BIMI logo if any, the absences, the reconciliation (`null`
  when nothing was claimed), the story and the Run. `to_dict()` gives JSON with
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
  ct.read_logs          -> logged names, once per map: Cert Spotter, + crt.sh with --ct
    subdomains.discover -> wordlist + those names, the ones that publish SPF or MX or are
                           delegated by NS to a service (that delegation is a claim)
    ct.collect (--ct)   -> those names, each resolved for CNAME, A and MX and matched
Phase 2, the domain itself
  backed = generic DKIM names that belong to services SPF or MX already shows
  probe order = selector rules ranked by MX and SPF hints, then the generic names
  dkim.collect  ||  networks.collect (SPF IP ranges: published vendor ranges, then ASN)
Phase 3, each sending subdomain (first 30)
  spf + mx + its delegation -> backed -> dkim (27 names + backed)  ||  networks
Assembly
  all Observed summed -> infer.services: group by service,
     tier = strongest Kind, report-only services -> role "reporting"
  setup.build: each service's setups from the claims, the Reads the sources kept, Checked,
     absences and gaps; no query
  findings sorted by severity, + gateway note + same key notes + setup findings; unknowns and
     gaps deduplicated
  -> SenderMap + Run
  story.write: the paragraph from the map; no query
  reconcile.with_claimed: the claimed names against the services; no query
  -> render.text | render.markdown | to_dict JSON | web stream
```

Each source returns an `Observed`: claims, unknowns, findings, gaps and what it checked. Sources never raise
for a failed lookup: every DNS answer has a status (`ok`, `no such name`, `no record of this
type`, `lookup failed`), and every source turns a failed lookup or page into a gap, while an
answer of no such name or no record is an absence. A failed network-owner lookup leaves the
range listed as unknown with "network lookup failed", not "no network". If the MX, token,
report, label, MTA-STS or website source or the subdomain search raises an exception, it
becomes a gap that says it crashed instead of losing the map. A check turned off by the caller
(`--no-web`, `--no-subdomains`) is a gap too, and with both off the MTA-STS policy is not
fetched, which is also a gap. Certificate logs are read by `ct.py` alone, once per map: each
provider that failed or was off (crt.sh without `--ct`) is a gap of its own, worded with the
provider's name and what happened, and each provider asked is recorded as a page in Checked. With
`--no-subdomains` and no `--ct`, nothing reads the logs and no provider is asked.

Every cap that leaves names unasked records a gap naming the cap and the count it dropped: 30
sending subdomains, 27 DKIM names per sending subdomain beyond the ones its SPF, MX or delegation
backs, 24 SPF ranges for the network lookup, 60 names from the certificate log and names more than two
labels below the domain, an SPF depth of 10, a vendor's own SPF read 3 levels deep for its
published ranges, 2,000,000 bytes of a web page, 5 redirects of a web page, and 200 names from
the certificate logs.

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
| `catalog.py` | Loading vendors.json into match tables, refusing any pattern without a proof; matching a host, token or selector to a service, and a name a person typed (`normalise`, `named`) |
| `proofs.py` | The Proof type and the checks every proof must pass on loading |
| `selectors.py` | DKIM selector rules with proofs: parsing and checking them, and ordering the probes |
| `infer.py` | Turning claims into ranked services; the map of backed selectors |
| `story.py` | The story: at most five sentences from the map, each counted where it is written |
| `reconcile.py` | The claimed list against the map: the four parts, splitting a comma separated list |
| `setup.py` | Setups: each item's state from what the map already asked, `complete`, the findings a setup raises, and the setup line every view shows |
| `engine.py` | `map_domain`: input cleaning, the phase order, subdomain scans, limits, the gateway note |
| `sources/spf.py` | Walking the SPF tree: credited includes, IP ranges, the lookup count, SPF findings |
| `sources/spf_eval.py` | `check_host()` from RFC 7208: the result one address gets from a domain's record, and what decided it |
| `sources/mx.py`, `sources/mta_sts.py` | Where the domain receives mail |
| `sources/web.py` | The homepage and subprocessor page, and the guard every page fetch goes through |
| `sources/dkim.py` | DKIM probing, the wildcard check, reading keys and their flags, the key fingerprint, dangling, short and shared keys |
| `sources/labels.py`, `tokens.py`, `reports.py`, `bimi.py` | Fixed-label CNAMEs, verification TXT, report addresses, the BIMI logo |
| `sources/networks.py` | Naming SPF IP ranges by the ranges services publish, then by network owner |
| `sources/ct.py` | Certificate transparency: the only reader of certificate logs. Reads them once per map through a provider list (Cert Spotter always, crt.sh with `--ct`), each with its own tries, timeout and one-day disk cache, into one set of names; with `--ct`, each logged name resolved and matched by the same catalog matchers as the DNS sources |
| `sources/subdomains.py` | Finding sending subdomains from a wordlist and the names `ct.py` read |
| `render/text.py`, `render/markdown.py` | The terminal and Markdown views; both show the gaps and what was asked at each name, as the web page does, and group unrecognised IP ranges by network |
| `cli.py` | The `sendermap` command |
| `testing.py` | Recording and replaying DNS answers and pages, and replaying a recorded case |
| `web/app.py` | The site: a page, and an API that streams progress and the finished map |

## Matching rules

These live in `catalog.py` and the sources, and each has a test.

- A hostname pattern matches the host or any name under it, on a label boundary, and the
  longest pattern wins: `u161779.wl030.sendgrid.net` is Klaviyo, not SendGrid.
- A DKIM key belongs to a service by CNAME first. `selector1` and `selector2` name nobody
  without the Microsoft CNAME. Next, a selector on the list of a service that SPF, MX or an NS
  delegation already shows is that service's. Last, the name table, except for generic names (`default`, `mail`,
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
- A subdomain delegated by NS is the service's when its NS records name the service's
  nameservers (`delegation_ns`), as Klaviyo's recommended setup delegates `send.example.com` to
  `ns1.klaviyo.com` through `ns4`. The claim is Configured and its evidence is the first NS
  record that names the service. NS records reached through a CNAME are the target's and credit
  nobody, and a delegation to nameservers no service is known by (a DNS host such as Route 53)
  says nothing about mail and is not asked about further. The gap: Klaviyo's nameservers answer
  no such name at `_domainkey.send.<domain>` while serving `s1` and `s2` below it as CNAMEs into
  its own SendGrid account, so the triage below asks only the names the delegation backs
  (Klaviyo's `kl`, `kl1` and `kl2`), and those two keys are not read. `s1` and `s2` stay
  SendGrid's names: no selector name belongs to two vendors.
- A wildcard answers every name, so DKIM probes and label CNAMEs first ask a fixed name nobody
  publishes (`sendermap-wildcard-check`). A wildcard DKIM key ends the DKIM scan at that name
  with a note; a label CNAME that matches the wildcard target is ignored.

### SPF evaluation

`sources/spf_eval.py` is `check_host()` from RFC 7208: given an address, a domain, a sender and
a HELO name, it returns the result a receiver would reach (pass, fail, softfail, neutral, none,
permerror, temperror) as a frozen `Verdict`. The Verdict names the term that matched and the
record it sits in (for a match inside an include, the term inside the included record), the
include and redirect links walked to that record as Evidence, the lookup count and the void
lookup count. It keeps the limits of section 4.6.4 (ten lookups, two void lookups, ten MX
records, ten PTR names), every mechanism, redirect (ignored when the record has `all`) and the
macros of section 7; `exp` is checked for syntax and never looked up. It reads DNS only through
the map's lookups, and a failed lookup is temperror with the question named in `reason`. A
target name no query can be made of (an empty or overlong label) matches nothing, one of the two
results the test suite allows. The walk above reads who a domain names; the evaluator answers
whether a given address passes. Nothing in the map uses it yet: G2 wires it in.

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
the domain's MX, SPF and delegations back or hint at are asked (every backed name and the first 8 of the
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
  that contains it, when exactly one service publishes that range. Otherwise the networks that
  announce it decide, from Team Cymru's IP to ASN data over DNS (`origin` for IPv4, `origin6`
  for IPv6). An address can be announced from more than one network (Amazon answers from
  AS16509 and AS14618), one answer per prefix and sometimes several origins in one answer, and
  those answers are a set, so every origin ASN is read and kept in ASN order, and the evidence
  carries every answer read. A range wider than an IPv4 /24 or an IPv6 /48 is sampled at three
  points, and of the union of the networks the samples return, those announcing a majority of
  the samples are kept. The range goes to a service only when the vendor data lists every kept
  network as that service's. Anything left is listed as unknown with every network named: the
  cloud's name for a shared cloud, otherwise the owner's, networks under one name together
  ("AS14618 and AS16509, Amazon Web Services") and different names after a semicolon, so nothing
  is asserted that only one answer shows; then the services that publish the range. A cloud is never credited: 74.125.0.0/16, published by Google
  Workspace and HubSpot and announced by Google's network, stays unknown. The data keeps one
  Unknown per range. The views group them: the ranges and addresses at one name that share a
  set of networks, an owner name and a list of publishers are one line, "2 ranges and 1 address
  in AS16509 (Amazon Web Services)", with the publishers once after it, then the ranges, the first
  record and "+ N more" (every record with `--evidence`). `render.grouped_unknowns` does this
  for the text and Markdown views by reading the value networks.py writes, and app.js does the
  same with the same pattern, `render.NETWORK_VALUE`. A range with no network, one alone in its
  network, one whose networks have different names, and any unknown that is not an IP range stay
  single lines.
- Every provider's answer becomes rows of (name, not before, not after) that go through one
  parse, `ct.logged_names`: lowercased, a leading `*.` dropped (the name below a wildcard is a
  name too), names outside the domain and other wildcards dropped, sorted, and a name on several
  certificates keeps the dates of the one that expires last. Cert Spotter's dates lose their
  trailing `Z` so they compare with crt.sh's (both are UTC).
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
- A DKIM key's size is read from the key: the RSA modulus length, or 256 for an Ed25519 key
  whose p= holds 32 bytes.
- Each key's summary line, its evidence, shows its tags as published with p= shortened to a
  prefix, the size and a fingerprint, `fp <hex>`: the first 16 hex characters of SHA-256 over the
  decoded p= bytes, from `dkim.fingerprint`, the one function that computes it and the seed of the
  key index. The t= flags are put in words: `t=y (testing)`, `t=s (strict)`. Read from the tags,
  each a finding carrying the key's evidence: t=y, a warning (verifiers treat the mail as
  unsigned, RFC 6376 section 3.6.1); h= listing sha1 only, a risk (RFC 8301 section 3.1); s=
  listing neither email nor `*`, a warning (verifiers ignore the record for email); k= other than
  rsa or ed25519, a warning (unknown type, unusable); k=ed25519 whose p= does not decode to 32
  bytes, a warning (malformed). A revoked key has no fingerprint and none of these findings.
- Every key read is kept on the source's Observed as a KeyPrint (selector, name, fingerprint,
  evidence). After every name is scanned, `dkim.same_keys` makes a note for each fingerprint seen
  at more than one selector anywhere in the map ("The k1 and s1 keys at <where> are the same
  key"), carrying each selector's record, in the order the keys were first seen.
- DKIM tags are read by exact name, so `ap=` is not `p=`. A record with no `p=` tag at all is
  malformed, a warning of its own; an empty `p=` is a revoked key. A wildcard answer that is
  not a key is ignored wherever it echoes.
- A security gateway in the domain's MX is a note that states what MX shows and is labelled as
  inferred from it. A flattening SPF service (EasyDMARC) is a note that says whether the walk
  read its record; other hosted services and macro includes are a note that they can authorize
  services without naming them.

## Setups

The rule: a setup costs no query and names only what was asked. `setup.py` is pure. It reads
the map's claims, the answers the sources kept while asking (`Read`: the SPF record and the MX
records at each name, each DKIM selector that answered with no usable key, each CNAME label),
what was asked at each name (`Checked`), the absences, the gaps and the catalog. Reads stay in the
engine; JSON shows them only as the evidence of the items that use them. A test maps a domain with
and without the vendor setups and requires the same questions in the same order.

A vendor block may carry a `setup` list. Each item has a `record` (`spf`, `dkim`,
`return_path`, `tracking` or `mx`), a `need` (`required`, `optional` or `none`), the `values` a
complete setup publishes, which must be the block's own patterns for that record (an SPF
include, a selector name or DKIM CNAME target, a bounce or tracking target, an MX host), and a
proof whose record is an https page on the vendor's own documentation site, dated. Loading
refuses an item whose values are not patterns of its block, a needed item with no values, an item
that is not needed with any, a record listed twice, and a proof that is not an https page of its
domain. `tools/verify_proofs.py` fetches each page and the proof holds when it contains every
value; a page that cannot be fetched is could not check. Every Mailbox and Security gateway
vendor carries one, except Mimecast, Proofpoint and Outlook.com (consumer), whose own docs name
the values to no plain HTTP client; so do the most seen senders across `data/hunt_domains.txt`
whose docs can be read that way. A mailbox's MX is optional, as a security gateway in front of
it takes its place in MX. A gateway's SPF item is left out where its docs ask for the include
only for mail sent out through it (Barracuda), since a receiver with SPF missing is a risk.
`tests/test_setup.py` names which vendors carry one, and fails on a receiver with neither a
setup nor a reason. The other vendors have no setups.

For each service with setup data, one Setup per name it has claims at, the domain first, except
a bounce domain: a name below another of the service's names where its MX takes the replies and
bounces (a SendGrid `send.` subdomain under a domain whose keys are SendGrid's). That name is the
return path of the setup above it, so its MX counts as that setup's bounce item and its own DKIM
is never judged. The states:

- **present**: a claim shows it, and its evidence is the item's. For SPF, an SPF include or a
  range in SPF the service owns (and any later SPF evaluation claim); for DKIM, a key through
  the service's CNAME or by a selector name credited to it; for MX, its MX at the name; for a
  bounce or tracking item, its CNAME, or for the bounce item a bounce domain's MX. A key at a
  selector the block lists that the setup does not name reads present with an older setup
  detail naming the current selectors (Mailchimp's `k1` beside the documented `k2`).
- **broken**: the only key is revoked or dangling (its claim) or malformed at a selector the
  setup names (the record), or the name publishes more than one SPF record.
- **missing**: the names were asked and nothing answered: the SPF record read with no claim for
  the service, or no SPF record at all; every selector the setup names asked and each a negative
  answer, worded by the zone's denial class (`no such name` in a classic zone; `no record of
  this type` where the zone gives that answer for every name, said so), with the absence's own
  evidence when there is one; where `_domainkey` itself does not exist, that no selector does;
  no CNAME into the vendor at any of the labels asked, with each label's answer.
- **not checked**: the lookup failed, a cap left the names unasked, a wildcard answers every
  name, the SPF record is hosted or a macro (the reason is named), no label was asked at a
  subdomain (labels are asked at the domain only), or the setup names no selector to ask
  (Klaviyo's current selectors are not yet in its block). The gap or reason is the detail.
- **not needed**: the vendor's docs need no such record.

`complete` is False when a required item is missing or broken, otherwise None when a required
item is not checked, otherwise True.

Findings, each with the item's evidence: a Mailbox or Security gateway service in the domain's
MX whose DKIM is missing is a risk ("<vendor> receives the domain's mail and does not sign it"),
and with SPF missing a risk too; any other service with a required item missing is a warning for
DKIM or SPF and a note for a bounce or tracking CNAME. A service whose only claims are Account
only is one note asking whether the account is still used, and nothing about what its setup
lacks. Broken raises nothing new: the key and SPF findings already exist. Every view shows one
line per setup under its service, "Setup at <where>: SPF present, DKIM missing (selector1 and
selector2 no such name), bounce CNAME not needed.", built by `setup.line` and, on the web page,
by the same words in app.js. An optional item that is missing reads "not used (optional, <what
was asked>)" in every view, so a reader does not take an optional record for a fault; its state
in JSON stays `missing`, with its detail and evidence.

## The story

The rule: nothing stated past what the evidence shows. `story.py` is pure: it reads a finished
SenderMap and writes at most five sentences, in this order, each built only from objects in the
map and left out when they are absent:

1. **Risks**: every finding of severity risk, one clause each by its own title, in the map's
   order ("The map shows two risks: ..."). Warnings and notes are not in the story.
2. **Who receives the mail**: each service in the domain's own MX. For a mailbox provider, what
   its DKIM setup item at the domain shows: a key in place to sign, no key in place, only a
   broken key, or that it could not be checked; with no setup data, only that it receives the
   mail. "Has a DKIM key in place to sign it", not "signs it", since a published key does not
   show that anything signs with it. A security gateway "stands in front of the domain's mail
   ... so the mailbox provider is not visible from MX".
3. **Senders**: the Configured senders grouped by category, groups and names in the map's order
   ("eleven other services are set up to send as the domain: four transactional (...)", "other"
   when sentence 2 named a receiver), then the Likely ones grouped by the kind of the claim that
   decided them ("two more are likely from a DKIM key name alone (...)"). When the map has no
   sender and no unknown, and records what was asked at the domain, the sentence states the
   absence from what was checked there: "No sending service shows in DNS for example.com: no
   MX, no sender in SPF, and no DKIM key at the 106 names asked." A null MX is said as one, and
   a DKIM wildcard as "a wildcard that answers every DKIM name". The map keeps what SPF names,
   not the SPF record, so a domain with `v=spf1 -all` and one with no SPF record both read "no
   sender in SPF". A part whose kind has a gap is left out; the last sentence names it.
4. **Traces and reports**: the Account only services, then who receives the DMARC and the TLS
   reports, by the report claims.
5. **Not checked**: one clause per gap kind, in plain words and counted from the gaps'
   `count` and `cap`, the detail left to the Not checked section below the map: "Not checked:
   the website (turned off), DKIM selectors past the first 27 on five subdomains, network owners
   for 12 of 36 ranges, six subdomains whose lookups failed, and the crt.sh certificate log (read
   only with --ct)." The website comes first, then the kinds in a fixed order (page, DKIM,
   networks, subdomains, SPF, MX, published ranges, labels, reports, tokens, MTA-STS, certificate
   logs), then the other checks turned off. Caps and failures of one kind fold into one clause
   ("DKIM selectors past the first 27 on five subdomains and one that could not be read"). No
   URL, no raw gap text, no nested brackets and no flag but the one that turns a check on. A gap
   in reading another service's own SPF for its published ranges is about the vendor data, not
   the domain, and would name a service the map did not find, so those services are counted.

Counts are in words up to twenty, a pair such as "12 of 36" both in digits once either is
past it, and counted in the function that writes the sentence. The
words are plain, with no abbreviation the map does not already print, no adjectives and no
advice. The engine writes the story before the reconciliation, so a claimed list never changes
it. The text view prints it under the headline, the Markdown view as the first paragraph, the
web page above the map, and JSON carries it as `story`.

## Claimed senders

A client says which services they use; the map says what DNS shows. `reconcile.py` is pure: it
reads the finished map, the names the client wrote and the catalog, and asks nothing, so a map
built with a claimed list asks the same questions as one without (a test holds it).

A claimed name matches a service only exactly, after both are normalised by
`catalog.normalise`: casefolded, spaces and punctuation gone, a leading "the" and a trailing
"inc", "llc" or "ltd" dropped when other words remain. "The Mailchimp, Inc." is Mailchimp;
"Mailchimps" is nobody. There is no fuzzy matching. A name matches its vendor's own name or one
of the vendor block's `aliases`: a plain list of the other names customers call the service by
("Office 365", "O365", "Exchange Online" for Microsoft 365; "Sendinblue" for Brevo). An alias
carries no proof, unlike every other entry in a block, because it matches text a person typed and
nothing in DNS, so no record could show it. Loading refuses an alias that is not a string, that
normalises to nothing, or that names a vendor already named the same way, by its own name or
another vendor's name or alias; a name with two readings ("Outlook", "Zoho", "GoDaddy") is left
out.

Found services keep the map's order; unfound services and unknown names keep the order they were
claimed in. Blank names are left out and a name written twice the same way counts once. Nothing
claimed is no reconciliation: `null` in JSON and no section in any view. Every view shows a
CLAIMED SENDERS section with all four parts, "none" for an empty one, each found service with
its tier and, when the client wrote another name, "claimed as" with their words. The text and
Markdown views build it with `render.claimed_parts`, and app.js with the same words.

The web site caches maps by domain only; the claimed names a request carries are applied to the
cached map for that response and kept nowhere. The page passes its own `?claimed=` on to the API,
so it needs no input of its own. A recorded corpus case holds no claims, so `testing.comparable`
leaves out a `null` reconciliation and the corpus did not change.

## Determinism

The same DNS answers (and the same web pages and certificate logs, when those are read) and the
same `checked_at` give the same map. `map_domain` takes
`checked_at` from the caller and refuses one without a timezone. Only the Run's `elapsed`
differs between such runs, and `SenderMap` equality ignores the Run. The SPF walk asks for every
reachable record at once, then walks the tree depth first in the order of its terms, so its
output never follows DNS timing. A record set has no order (RFC 2181 section 5) and a resolver
returns it in any, while a source that takes a record by position or lists claims in record order
would follow it, so every Answer's records are sorted at the boundary, in `dns.Answer` itself:
MX by preference then host, everything else by text. Every resolver, the recorded replay and the
test zone included, hands out the same order for the same set. A CNAME chain keeps its order,
since hops are a sequence. The vendor range table is built per map through the same
lookups and counted with them. `tests/test_determinism.py` maps one busy fake domain twenty
times with random delays on every answer, and again with every record set shuffled on every
query, and requires identical output: the JSON, the deciding claim of each service and every view.

## The vendor data

All vendor knowledge is in `sendermap/data/vendors.json`: one block per service with its
category and the patterns that identify it (SPF includes, MX hosts, DKIM CNAME targets and
selector names, bounce and tracking CNAMEs, report addresses, verification tokens, networks,
website hosts, the names a subprocessor page would list it by), plus shared `rules` (generic selectors, hosted SPF services, cloud networks,
the labels to probe). `catalog.load` reads the file once per process, selector rules included.

Every SPF include, MX host, DKIM CNAME target, bounce, tracking and other CNAME, delegation
nameserver, report address, verification token, network, website host and subprocessor name is an entry with its value and
a proof: a domain that publishes it, the record (a DNS name, or a page's URL) and the date
checked. A subprocessor name's proof is a page on the vendor's own site that uses the name; only
sending services list one, and a name that is also an ordinary word ("Kit", "Wix") is not
listed, so the web source has no rule of its own about which names count. `catalog.build`
refuses an entry without one, and checks that the record could show the pattern: a report
address at `_dmarc.` or `_smtp._tls.` of the domain, a token at the domain itself, a DKIM CNAME
under its `_domainkey`, a delegation at a name under the domain (the domain's own nameservers are
its DNS host, not a sending setup), a website host or subprocessor name on an https page of the
domain, anything else at or under the domain. `proofs.py` holds those checks.

A vendor block may carry `sending_ip`: one address the vendor sends from, for SPF evaluation
to ask a domain's record about. Its proof's record is either the vendor's own SPF record host,
publishing an authorizing range that holds the address, or a host of the vendor's whose A or
AAAA record is the address; `verify_proofs.py` reads both at the record, since an outbound host
may publish a HELO record of its own. Loading refuses a second address or a value that is not an
IP address. Every shipped address is an outbound host's: one whose PTR name leads back to it,
in a range the vendor's customer-facing SPF record publishes and no other vendor's does, and
evaluation gives that host as the HELO name, as the vendor's server would. A HELO name matters:
Valimail answers per address and HELO name, and passes Google's address for
`mail-sor-f41.google.com` but not for a name no Google server uses. Vendors whose every range
is another's (Mandrill inside Mailchimp, Atlassian and Customer.io inside SendGrid), whose ranges
are per customer (Proofpoint), whose hosts carry no name of their own (Intercom, MailPoet), or
that publish no range have none.

A `selectors` entry names a vendor's DKIM selectors with how they are known (the vendor's docs,
a pattern, an aggregate report, or the vendor's own domain) and a proof per name: a live domain
that publishes the record, the record name and the date checked. Loading refuses an entry
without one. These entries are the only list of vendor selectors: they credit a key by its
name, give the names a service shown by SPF, MX or an NS delegation backs, and make the probe sweep, which is
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
vendors.json. A network proof reads an address's origins with the map's own `networks.owner`
and credits them by its rule (`networks.credited`): it holds only when every origin network is
the vendor's, so an address two networks announce gives the same verdict in any order. The hunt
reads origins the same way and confirms with the same check.

A vendor's own domain rarely publishes what it asks its customers to publish, so
`tools/hunt_proofs.py` looks for the pending patterns on customer domains: `data/hunt_domains.txt`,
the top 2,000 of a Tranco list (its id and date on the first line) and three retail brands. At each
domain it reads what the engine reads (SPF down the whole include chain, MX, DKIM keys at every
proven, pending and generic selector name, the bounce and tracking labels, report addresses,
tokens, networks, the sending subdomains with their NS delegations and one fetch of the
homepage), one query at a time per
domain with domains in parallel, and confirms each find with the check `verify_proofs.py` defines
for its kind, so found means the same in both. A name under a wildcard proves nothing. Answers and
pages are cached on disk, so a rerun asks only what failed. The highest ranked domain that shows a
pattern becomes its proof; `--move` moves proven patterns into vendors.json. Both tools, and
`tools/record_corpus.py`, take `--doh` to ask Cloudflare's DNS over HTTPS, for a machine whose
resolver cannot be trusted (one that answers MX and TXT with nothing, as some sandboxes do); the
recorder keeps the answers, not those requests.

## Surfaces

- **Library**: `await sendermap.map_domain("example.com", checked_at=datetime.now(UTC))`.
  Optional: `resolver`, `http`, `use_web`, `use_subdomains`, `use_ct` (off by default) with
  `ct_cache` (a directory, or None for no cache), a `progress` callback, and `claimed`, a
  sequence of the service names the client says they use.
- **Command line**: `sendermap example.com`, with `--json`, `--markdown`, `--evidence` (every
  claim, not only the deciding one), `--no-web`, `--no-subdomains`, `--ct` (crt.sh read too,
  and every logged name resolved and matched), `--doh` (Cloudflare DNS over HTTPS), `--claimed`
  (a comma separated list of the services the client says they use) and `--claimed-file` (one
  per line; both may be given). Both
  certificate logs are cached in `$XDG_CACHE_HOME/sendermap/ct` or `~/.cache/sendermap/ct`, one
  directory per provider. The web site does not use `--ct` or the cache: it reads Cert Spotter
  for the subdomain search on each map it builds.
- **Web site**: a FastAPI app. `GET /api/map?d=` returns the map as JSON, `GET /api/map.md?d=`
  as Markdown, and `GET /api/map/stream?d=` streams progress then the map as server-sent events.
  Each takes `claimed`, a comma separated list, for the map's reconciliation.
  Uvicorn's access log is turned off when the app starts, so no query string is logged; a test
  runs a real server and checks that a request logs nothing. Visitor addresses are held in
  memory for one minute for the rate limit.
  Results are kept in memory for ten minutes, keyed by domain only, and concurrent requests for
  one domain share one build. At most six maps build at once, and each visitor may make twelve
  map requests a minute.

## Tests

`tests/conftest.py` provides a fake DNS zone (`Zone`) with CNAMEs, wildcards, names that fail
on purpose, types that fail at one name, empty non-terminals that exist (RFC 8020), a compact
denial mode and names forced to no such name, and an HTTP client that answers the certificate
log with nothing and fails the test on any other request, so the suite never reaches the
network (the web test serves on loopback only). `Zone.public` gives a host a public address, which a fake page needs to pass the fetch
guard. Run `pytest`. `mypy` (strict, over `sendermap/`, `tests/` and `tools/`), `ruff check` and
`ruff format --check` pass on the whole repository.

Tests that hold the rules: `test_evidence.py` maps a fake domain that reaches every kind of
claim and requires evidence on every claim, unknown and finding, and the supporting records on
every claim whose evidence does not name its service; `test_story.py` holds a map that reaches every sentence and one
that reaches none, each receiver's wording, each gap kind's clause and the folding, the
sentence for a domain with no sender, that every service the story names is a service of the
map and every count is the map's count, and that the last sentence holds no URL, raw gap text,
nested bracket or other flag (on the fake map and every corpus case), the views and the
optional wording; `test_reconcile.py` holds the normaliser, the aliases and the loading
rules, each of the four parts on a fake map, that claiming asks nothing more, the CLI flags, the
JSON field, the API parameter and the views; `test_setup.py` holds each setup state
with its evidence, the findings, the bounce domain, `complete`, the views, the loading rules and
that a setup asks nothing more; `test_dkim_denial.py` holds the
_domainkey triage for each denial class, the absences with their evidence, and their rendering;
`test_gaps.py` and `test_caps.py`
require a gap for each failed question and each cap; `test_gap_kinds.py` maps the busy fake
domain with every source failing, every cap reached, each check turned off and each guarded
source crashing, and requires every kind and no gap at the default, and that every `Gap` in the
package is given a kind; `test_web_guard.py` requires that a
refused fetch sends nothing and is a gap, for each reason the guard refuses, on every redirect
and on the subprocessor and MTA-STS pages; `test_checked.py` requires the record of
what was asked and its rendering; `test_labels_say_what_was_seen.py` holds the wording of the
labels, the key flag and same key findings and the grouping of unrecognised ranges by network among them; `test_dkim.py` holds the key reading,
the fingerprint and which keys raise which flag; `test_determinism.py` requires the same map from the same answers;
`test_vendor_proofs.py`, `test_one_selector_list.py` and `test_subprocessor_names.py` require a
proof on every vendor pattern and one proofed selector list read once; `test_pending_vendors.py`
requires that the engine never opens the pending file and that a host only a pending pattern
matches shows as not recognised; `test_hunt_proofs.py` holds where the hunt may find each kind of
pattern, which domain's proof wins, that a rerun asks nothing and that a moved proof loads. `test_delegation.py` holds the delegation pattern's loading
rules, the claim and the sending subdomain it makes, that an unknown delegation or one reached
through a CNAME credits nobody, and the delegation proof's check. `test_verify_proofs.py` holds what each kind of proof needs, among them a network proof on an
address with two origins, in both orders. `test_spf_eval.py` loads the RFC 7208 test suite (`tests/vectors/`, from pyspf, with its
licence) into fake zones and runs every case, with the cases it does not pass listed at the
top with a reason (none today), and holds hosted SPF shapes: a macro include, an exists record
and a flattened record. `test_ct.py` runs the CT source on a recorded crt.sh answer
(`tests/fixtures/crtsh_allbirds.json`) beside Cert Spotter answers, and holds that the logs are
read once per map, crt.sh only with `--ct`, one gap per provider that failed or was off, and the
cache per provider.

### Record and replay

`sendermap/testing.py` ships in the package, so other projects can replay too.
`RecordingResolver` wraps any Resolver and keeps every question and Answer; `save` writes them
as JSON sorted by name and type, one object per question. `ReplayResolver` answers from that
file, and a recorded failed lookup replays as failed, which is how could not check is modelled.
`RecordingTransport` and `ReplayTransport` do the same for pages: method, URL, status, content
type, redirect target and body text, or the transport error the request ended in. A question or
request the recording does not hold raises `UnrecordedError` naming it. The engine's guards turn
an exception in a source into a gap, so each replayer also lists what it missed, and a replay
with anything missed fails.

`tests/corpus/` holds real domains recorded this way (`tools/record_corpus.py DOMAIN`), each
with the map it gave as `expected.json`; `tests/test_corpus.py` maps each again offline and
requires that map. `--update` rebuilds every `expected.json` from the recorded answers without
the network, for a change that rightly changes a map; the diff it causes is the review. Every
bug found on a live domain becomes a case there (`tests/corpus/README.md`).

pytest runs with pytest-socket (`--disable-socket --allow-unix-socket --allow-hosts=127.0.0.1`),
so a test that opens a network socket fails, while the loopback web test keeps running.

### Workflows

- `.github/workflows/test.yml` installs the dev and web extras and runs `ruff check`, `ruff
  format --check`, `mypy` and `pytest` on Python 3.12 and 3.13, on every push to main, every
  pull request and by hand. pytest takes its addopts from `pyproject.toml`, so the network is
  blocked in CI as it is locally.
- `.github/workflows/recheck-corpus.yml` maps every corpus case live again on Mondays at 10:00
  UTC, an hour after the proofs job, and by hand, with `tools/record_corpus.py DOMAIN --recheck
  DIR` (held by `tests/test_recheck_corpus.py`): the case's own options and a fresh
  `checked_at`, compared with `expected.json` without `checked_at`, the two run fields or the
  order of lists. The diff for each domain goes to the job summary and the fresh recordings to
  an artifact kept 30 days. Drift fails nothing; only a live map that could not be built fails
  the job. The job commits nothing.

The rule: a drifted case is re-recorded by hand with `python tools/record_corpus.py DOMAIN`,
after reading the diff, never by the job.
