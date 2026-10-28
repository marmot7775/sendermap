# The golden corpus

Each directory is one domain mapped live and recorded: `dns.json` holds every DNS question and
its answer, `http.json` every page requested (the Cert Spotter log the subdomain search reads,
the MTA-STS policy, the homepage when the website was read), `case.json` the moment the map is
dated by and the options used, and `expected.json` the map's JSON without `run.elapsed` and
`run.lookups`. `tests/test_corpus.py` maps each one again from its files, offline, and requires
`expected.json`.

The rule: every bug found on a live domain becomes a case here. Record it with
`python tools/record_corpus.py <domain>` (add `--web` to read the homepage), fix the code, run
`python tools/record_corpus.py --update`, and review the diff to `expected.json`.

A new vendor pattern makes every map ask a few more questions (a new SPF include adds the TXT
lookup for its published ranges), and the replay fails on the first one it lacks.
`python tools/fill_corpus.py` asks each missed question live through the case's own resolver,
adds the answers to `dns.json` without changing any recorded answer, and repeats until nothing
is missed; then `--update` as above.

Recorded 2026-10-11 through Google's DNS over HTTPS (`--doh google`), with `--ct` off and the
website off except for example.com:

- `allbirds.com`: SPF flattened through EasyDMARC, SendGrid's ranges named by the network that
  announces them, and sending subdomains. Its 18 failed answers were marked `servfail` by hand on
  2026-10-12, when they were checked live as SERVFAIL (REFUSED by the Route 53 nameservers they are
  delegated to) through Google, Cloudflare and the system resolver, rather than re-recorded.
- `mills-reeve.com`: Microsoft 365 behind a Mimecast security gateway in MX.
- `casper.com`: Google Workspace with Campaign Monitor and other marketing platforms, and
  `mail.casper.com` delegated by NS to Salesforce Marketing Cloud.
- `glossier.com`: SPF hosted through a Valimail macro include, the only term in the record.
- `example.com`: no mail footprint (a null MX, SPF `-all`, a revoked wildcard DKIM key), with its
  homepage recorded.

Recorded 2026-10-28 through Google's DNS over HTTPS, `--ct` and the website off:

- `cognifit.com`: an SPF include of `ses.amazonaws.com`, a name that does not exist (Amazon
  SES's include is `amazonses.com`), so the record errors where a receiver reaches it.
