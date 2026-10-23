# Sendermap: example.com

0 sending services found from public records checked 2026-10-12 01:25 UTC (208 lookups in 0.0 s over Google DNS over HTTPS).

No sending service shows in DNS for example.com: a null MX that says it accepts no mail, no sender in SPF, and a wildcard that answers every DKIM name. Not checked: the crt.sh certificate log (read only with --ct).

## Needs attention

- **The domain accepts no mail** (note). It publishes a null MX record, which tells senders it receives no email.
- **Every name under _domainkey.example.com answers with a key** (note). A wildcard record makes every selector look published, so keys there say nothing about which services sign for the domain.

## What was asked

- **example.com**: 23 CNAME labels, 2 pages

## Not run

- certificate transparency, crt.sh: read only with --ct (it also holds expired certificates)
