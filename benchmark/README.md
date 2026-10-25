# Benchmark

How much of what real domains publish Sendermap can name, measured the same way every
release, over the same 300 domains.

```
uv run python tools/benchmark.py                          # map the list, write runs/<date>-<version>.json
uv run python tools/benchmark.py --report runs/X.json     # print one run's summary
uv run python tools/benchmark.py --compare runs/OLD.json  # how the newest run differs from OLD
```

The list is `data/benchmark_domains.txt`: the first 297 domains of Tranco list 8PX5V that
published mail records on 2026-10-25, then three retail brands. It stays fixed so runs compare.
A run uses the CLI's defaults and live DNS through the machine's resolver, about 15 minutes.
Run it from a fresh `uv sync --reinstall-package sendermap` after tagging, so the run file
carries the release version rather than a dev string.

## What the numbers mean

- **Shared named groups** is the headline. A named unknown is an SPF include, a mail server, a
  CNAME or a report address that is clearly a sender and matches no service in the catalog.
  Grouped by zone, a group two domains or more publish is almost always a vendor, so each one
  is a `vendors.json` entry waiting to be written. Lower is better.
- **Fully named %** is the share of domains with no named unknown at all.
- **Address unknowns** are IP addresses and ranges in SPF that no service is credited for.
  Most are a company's own servers and should stay unknown, so this number is context, not a
  target.
- **No sender found** counts domains where nothing in DNS shows a sending service.

Live DNS changes between runs, so a comparison mixes catalog changes with the world changing.
A service a domain lost with no catalog change behind it is either drift or a bug worth a look.

## Runs

| run | shared named groups | fully named | senders found | no sender | median seconds |
|---|---|---|---|---|---|
| 0.1.7, 2026-10-25 | 83 | 57 of 300 (19.0%) | 1,417 | 63 | 10.8 |

### Work list from the 0.1.7 run

Leads a catalog pass should look at, from the run's ranked tables:

- Mailbox services with no entry: Yandex 360 and VK WorkMail (Mail.ru for business) are now
  in the catalog. Still open: Amazon WorkMail (`*.awsapps.com` autodiscover), whose MX and SPF
  are Amazon SES patterns, so its setup cannot name values of its own yet, and
  `_spf.myorderbox.com` at hostgator.com, hosting24.com, reg.ru and timeweb.ru, which publishes
  bare ranges and is not yet tied to a named mailbox product.
- Report receivers with no entry: done. `emailanalyst.com` is eDataSource and
  `dmarc.cyber.dhs.gov` is CISA.
- Proofpoint's own networks (AS22843, AS26211) in SPF at 6 domains, not credited.
- `selector1` CNAMEd into `outbound.protection.outlook.com` at 7 domains, which the catalog does
  not match: either a Microsoft 365 shape to add or a common misconfiguration to name.
- Not senders: CNAMEs to web hosting and CDNs (`ghs.googlehosted.com`, `cloudfront.net`,
  `edgekey.net`, `fastly.net`) at labels the label source asks. They inflate the named count;
  the label source could skip a target that is a known web host.

Most of the top 300 run their own mail (Google, Microsoft, Amazon, Meta), so their sibling
domains show up as unknowns too. That is correct and keeps the fully named share low on this
list; it is the trend between runs that counts.
