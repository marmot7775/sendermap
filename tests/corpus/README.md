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

Recorded 2026-10-11, with `--ct` off and the website off except for example.com:

- `allbirds.com`: SPF flattened through EasyDMARC, SendGrid's ranges named by the network that
  announces them, and sending subdomains.
- `mills-reeve.com`: Microsoft 365 behind a Mimecast security gateway in MX.
- `casper.com`: Google Workspace with Campaign Monitor and other marketing platforms.
- `glossier.com`: SPF hosted through a Valimail macro include, the only term in the record.
- `example.com`: no mail footprint (a null MX, SPF `-all`, a revoked wildcard DKIM key), with its
  homepage recorded.
