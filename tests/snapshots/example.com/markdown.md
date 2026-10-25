# Sendermap: example.com

No sending service found  
Checked 2026-10-12 01:25 UTC · 210 lookups in 0.0 s over Google DNS over HTTPS

No sending service shows in DNS for example.com: a null MX that says it accepts no mail, no sender in SPF, and a wildcard that answers every DKIM name.

## Notes

- **The domain accepts no mail**. It publishes a null MX record, which tells senders it receives no email.
- **Every name under _domainkey.example.com answers with a key**. A wildcard record makes every selector look published, so keys there say nothing about which services sign for the domain.

## How this was checked

Asked 210 lookups at 1 name:

- example.com: 25 CNAME labels, 2 pages

Not run:

- certificate transparency, crt.sh: read only with --ct (it also holds expired certificates)
