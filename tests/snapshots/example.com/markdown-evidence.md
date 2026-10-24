# Sendermap: example.com

0 sending services found from public records checked 2026-10-12 01:25 UTC (210 lookups in 0.0 s over Google DNS over HTTPS).

No sending service shows in DNS for example.com: a null MX that says it accepts no mail, no sender in SPF, and a wildcard that answers every DKIM name. Not checked: the crt.sh certificate log (read only with --ct).

## Needs attention

- **The domain accepts no mail** (note). It publishes a null MX record, which tells senders it receives no email.
  - `example.com MX 0 `
- **Every name under _domainkey.example.com answers with a key** (note). A wildcard record makes every selector look published, so keys there say nothing about which services sign for the domain.
  - `*._domainkey.example.com TXT v=DKIM1; p=`

## What was asked

210 lookups at 1 name

- **example.com**: 25 CNAME labels, 2 pages

## Not run

- certificate transparency, crt.sh: read only with --ct (it also holds expired certificates)

## Appendix: names asked

- **example.com**
  - Pages: `https://example.com/`, `https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names`
  - CNAME labels: `bounce`, `bounces`, `em`, `email`, `mail`, `send`, `mta`, `rp`, `pm-bounces`, `links`, `link`, `click`, `track`, `tracking`, `url`, `go`, `autodiscover`, `cf-bounce`, `eversrv`, `fwdkim1`, `bnc3`, `bounces.cloud.em`, `bounces.cloud2.em`, `outbound.intercom`, `atlassian-bounces`
