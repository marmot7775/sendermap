---
name: sendermap
description: Maps which services send email as a domain, from public records only (DNS, certificate logs and the domain's own website), with the record behind every claim, a confidence tier for each service, each vendor's documented setup checked item by item, and what was not checked. Use when someone asks who sends mail for a domain, which email vendors a company uses, whether a vendor is set up to send as a domain (SPF, DKIM, bounce or tracking records), why mail from a service might fail authentication, or how the services an owner says they use compare with what DNS shows. Runs as the sendermap command line (uvx sendermap DOMAIN --json) or through the sendermap_map tool when the Sendermap MCP server is connected. It reports what public records show; it does not measure sending volume or reputation, prove that a DKIM key signs mail, or give advice.
license: MIT
---

# Sendermap

Sendermap answers one question: which services send email as this domain, and what public
record shows it? Every claim in a map carries the record it rests on. Your job is to run the
map, read it as written, and report it without stretching it.

## Running the map

Use the MCP tool when the Sendermap server is connected; otherwise use the command line.

**MCP tool `sendermap_map`.** Parameters:

- `domain`: the domain to map. A URL or an email address works; the domain is taken from it.
- `claimed`: the service names the domain's owner says they use, as a list. Leave it empty
  when nobody gave a list.
- `website` (default true): read the homepage and the subprocessor page.
- `subdomains` (default true): search for sending subdomains such as `email.` or `mg.`.
- `certificate_log` (default false): also read crt.sh and resolve every logged name. Slow;
  use it when the question is about past or forgotten vendors.
- `detail`: `summary` (default) keeps each service's deciding claim and its setups and leaves
  out what was asked at each name; `full` has every claim and the full record of what was
  asked. Ask for `full` when you need every claim or the selectors and labels asked.

The result's structured content is the `sendermap/1` JSON. Its text block is the story, then
one line per finding, then the claimed sections when a list was given.

**MCP tool `sendermap_vendor`.** Takes a vendor's name or alias ("Office 365", "Sendinblue")
and returns its block from the vendor data: category, aliases, every pattern with its proof,
the documented setup and the sending address. Use it to explain why a service was credited or
what a vendor's setup asks for.

**Command line.**

```
uvx sendermap example.com --json
uvx sendermap example.com --json --claimed "Office 365, Mailchimp, Klaviyo"
uvx sendermap example.com --markdown --evidence
```

Other flags: `--no-web`, `--no-subdomains`, `--ct` (crt.sh too), `--doh` (DNS over HTTPS through
Cloudflare, for a machine whose resolver cannot be trusted), `--claimed-file FILE` (one name per
line), `--output PATH`. Exit codes: 0 the map was built; 2 bad input (the message on stderr
says which); 3 no map, because both the TXT and the MX lookups at the domain itself failed.
On 3, say the domain's records could not be read and try again or try `--doh`; do not report
"no senders".

## Reading the JSON

Top level: `domain`, `story`, `services`, `findings`, `unknowns`, `gaps`, `absences`,
`reconciliation`, `run` (when it was checked, and how many DNS lookups). The contract grows by
addition only: ignore fields and enum values you do not know.

### Services and tiers

Each service has `name`, `category`, `tier`, `role`, `claims` and `setups`. The tier is the
strongest its claims support, strongest first:

- **In use**: the service's MX at the domain itself. It receives the domain's mail.
- **Configured**: a record that sets the service up to send as the domain: an authorizing SPF
  include, a range in SPF the service publishes or whose network it owns, a DKIM key served
  through a CNAME into its zone, a bounce or tracking CNAME, an MX on a sending subdomain, a
  subdomain delegated to it by NS, or an SPF evaluation pass for its sending address.
- **Likely**: a guess from a name: a DKIM key known only by its selector name, a script the
  homepage loads from the service, the service's host mentioned in the page, or the service
  named as a subprocessor.
- **Account only**: a trace of an account: a verification token, an autodiscover CNAME, a
  revoked DKIM key, or a DKIM CNAME to a name that no longer exists. Not a sign that it sends.

A service whose `role` is `reporting` only receives DMARC or TLS reports. Its tier is null.
Do not count it as a sender.

Each claim has `kind` (in words, such as "included in SPF"), `where` (the domain or a
subdomain), `evidence` (`name`, `rtype`, `value`, `checked_at`) and, when the evidence alone
does not name the service, `supporting`: the records that do (the vendor's own SPF term that
publishes a range, or the network owner's answers). Quote both.

A claim at a subdomain is about that subdomain. "In use for a subdomain's mail" does not make a
service In use for the whole domain.

### Setups

`setups` holds, for each name a service has claims at, the vendor's documented setup checked
item by item. Each item has `record` (`spf`, `dkim`, `return_path`, `tracking`, `mx`), `need`
(`required`, `optional`, `none`), `state`, `evidence`, `asked` and `detail`. States:

- `present`: a claim shows it; the evidence is the record.
- `broken`: the only key is revoked, dangling or malformed, or the name publishes two SPF records.
- `missing`: the names were asked and nothing answered. The evidence or detail says what was asked.
- `not checked`: a lookup failed, a cap left it unasked, or a wildcard answers every name.
  The detail says which. This is not missing.
- `not needed`: the vendor's docs need no such record.

An optional item that is missing means the record is not used, not that something is wrong.
`complete` is true, false (a required item missing or broken) or null (a required item not
checked).

### Findings and unknowns

`findings` have `severity` (`risk`, `warning`, `note`), `title`, `detail` and `evidence`. Report
risks first. `unknowns` are records that point at a sender no vendor in the data matches, such
as an SPF range whose network has no listed owner: report them as unrecognised, with the record.

### Absences, gaps and silence

- An **absence** is a question answered "not there", with the negative answers as evidence
  ("DKIM keys at shop.example: no selectors exist"). You may report it as absent, quoting it.
- A **gap** is a question that got no usable answer, or a check that was capped or turned off:
  `asked`, `happened`, `kind` (what it leaves unchecked: `dkim`, `website`, `networks`, ...),
  and `count` and `cap` when counted. A gap is not an absence.
- **Silence is not absence.** A service missing from the map may sit behind a gap, behind a
  hosted SPF record whose contents the walk could not name, or at a DKIM selector nobody knows.
  Never say "the domain does not use X" because X is not in the map. Say "the public records
  checked do not show X", and name the gaps that could hide it.

### The claimed sections

When a `claimed` list was given, `reconciliation` has four parts:

- `confirmed`: claimed and found, with the tier and `claimed_as` (the owner's words).
- `unclaimed`: found and not claimed. Report each with its tier; a Likely one is still a guess.
- `unfound`: claimed, a known service, with no claim at any name checked. This is silence, not
  proof the service is unused: check the gaps before saying more.
- `unknown`: claimed names no vendor in the data goes by, kept as written. Say Sendermap does
  not know them, not that they are absent.

## Rules you must keep

1. **Quote the record.** Every service or finding you report comes with its evidence: the name,
   the record type and the value, as the map gives them.
2. **Say what was not checked.** Every report ends with the gaps that matter to the question,
   in plain words: what was not checked and why. The story's last sentence is a good start.
3. **Do not raise a tier.** A Likely service stays Likely; never call it Configured, set up or
   sending. An Account only service is not a sender.
4. **Do not call a vendor present without a claim.** A vendor is present only when the map has
   a claim for it. Not on a hunch from the domain's industry, not from `unfound`, not from a
   generic DKIM selector name such as `default` or `selector1` with no CNAME.
5. **Do not go past the evidence.** A map does not show sending volume, reputation, whether
   mail passes DMARC, or that a published DKIM key signs anything ("has a DKIM key in place",
   not "signs its mail").
6. **Give no advice from the map alone.** Nothing in a result is advice. If the person asks
   what to do, keep what the records show apart from your own recommendation, and say which is which.
7. **Date it.** Records change. Say when the map was checked (`run.checked_at`).

## Worked examples

### 1. Who sends for a domain

Asked: "Which services send email for shop.example?" Run `sendermap_map` with
`domain: "shop.example"`. The result, in part:

```
story: "Google Workspace receives the domain's mail and has a DKIM key in place to sign it.
  Three other services are set up to send as the domain: two marketing (Klaviyo, Mailchimp),
  one transactional (SendGrid); one more is likely from a DKIM key name alone (Mandrill).
  Not checked: DKIM selectors past the first 27 on two subdomains."
services: Google Workspace (In use, MX "10 aspmx.l.google.com"), Klaviyo (Configured, NS
  "send.shop.example NS ns1.klaviyo.com"), Mailchimp (Configured, CNAME
  "k2._domainkey.shop.example -> dkim2.mcsv.net"), SendGrid (Configured, "included in SPF",
  "include:sendgrid.net"), Mandrill (Likely, "DKIM key named for it" at
  mandrill._domainkey.shop.example)
```

A good answer:

> As of the check on 11 October 2026, public records show four services set up for
> shop.example. Google Workspace receives its mail (MX `10 aspmx.l.google.com`) and has a DKIM
> key in place. Klaviyo is set up on send.shop.example (NS `ns1.klaviyo.com`), Mailchimp hosts
> a DKIM key (`k2._domainkey` CNAME to `dkim2.mcsv.net`), and SendGrid is included in SPF
> (`include:sendgrid.net`). Mandrill is likely, but only from a DKIM key named `mandrill`; no
> record ties it to Mandrill. Not checked: DKIM selectors past the first 27 on two
> subdomains, so a sender there could be missing.

Not: "shop.example uses Mandrill" (raises Likely), or "they send most mail through Klaviyo"
(volume is not in the map).

### 2. Holding a claimed list against the map

Asked: "The client says they use Office 365, Mailchimp and Postmark. Is that the whole list?"
Run `sendermap_map` with `domain: "client.example"` and
`claimed: ["Office 365", "Mailchimp", "Postmark"]`. The reconciliation:

```
confirmed: Microsoft 365, In use (claimed as "Office 365"); Mailchimp, Configured
unclaimed: Zendesk, Configured; HubSpot, Likely
unfound:   Postmark
unknown:   none
gaps:      DKIM selectors past the first 27 at news.client.example (kind dkim, cap 27)
```

A good answer:

> Two of the three are confirmed: Microsoft 365 receives the mail (MX
> `0 client-example.mail.protection.outlook.com`) and Mailchimp hosts a DKIM key (CNAME
> `k2._domainkey.client.example` to `dkim2.mcsv.net`). Two services were found that nobody
> listed: Zendesk is set up to send (SPF `include:mail.zendesk.com`), and HubSpot is likely,
> but only from a DKIM key at the selector `hs1` with no CNAME into HubSpot. Postmark was not
> found at any name checked. Sendermap knows Postmark by its SPF include `spf.mtasv.net`
> (`sendermap_vendor` shows this), and the domain's SPF does not include it. That is not proof
> Postmark is unused: a key at a selector Sendermap does not know would not show, and DKIM
> selectors past the first 27 at news.client.example were not asked.

### 3. Nothing found

Asked: "Who sends mail as example.com?" The map:

```
story: "No sending service shows in DNS for example.com: a null MX that says it accepts no
  mail, no sender in SPF, and a wildcard that answers every DKIM name. Not checked: the
  crt.sh certificate log (read only with --ct)."
services: []
gaps: certificate transparency, crt.sh: not asked: read only with --ct
```

A good answer:

> The public records checked show no service sending as example.com. Its MX is a null MX
> (`0 .`), which says it accepts no mail; its SPF names no sender (`v=spf1 -all`); and a
> wildcard answers every DKIM name, so selectors could not be told apart. The crt.sh
> certificate log was not read, so past subdomains were not looked for.

Not: "example.com sends no email." The wildcard means DKIM could not be read name by name,
and a record that names no sender is what the map shows, not proof that nothing sends.
