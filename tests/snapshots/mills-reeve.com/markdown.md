# Sendermap: mills-reeve.com

5 sending services found from public records checked 2026-10-12 01:24 UTC (600 lookups in 0.0 s over Google DNS over HTTPS).

Mimecast stands in front of the domain's mail as a security gateway, so the mailbox provider is not visible from MX. Four other services are set up to send as the domain: one commerce and apps (Docebo), one support and CRM (Freshdesk), one mailbox (Microsoft 365), one transactional (SendGrid). DMARC reports go to Mimecast DMARC Analyzer. Not checked: the website (turned off), DKIM selectors past the first 27 on two subdomains, and the crt.sh certificate log (read only with --ct).

## Needs attention

- **The s2 key at mills-reeve.com is 1024-bit** (warning). Some receivers already treat 1024-bit RSA keys as weak. Rotate to 2048-bit.
- **Microsoft 365 at mills-reeve.com has no DKIM** (warning). Its documented setup needs it and the map shows it missing: no key at selector1._domainkey or selector2._domainkey, names with no TXT record; this zone gives that answer for every name that does not exist.
- **MX at mills-reeve.com points at Mimecast, a security gateway** (note). Inferred from the MX records: a security gateway filters incoming mail and hands it on to the server that holds the mailboxes, and MX records do not say which server that is.

## Senders

| Service | Category | How sure | Evidence | Setup |
|---|---|---|---|---|
| Mimecast | Security gateway | In use | MX: eu-smtp-inbound-1.mimecast.com, eu-smtp-inbound-2.mimecast.com; SPF: include:eu._netblocks.mimecast.com, include:_netblocks.mimecast.com at mills-reeve.com and update.mills-reeve.com |  |
| Docebo | Commerce and apps | Configured | SPF: include:docebosaas.com |  |
| Freshdesk | Support and CRM | Configured | SPF range: ip4:3.120.181.200/29 |  |
| Microsoft 365 | Mailbox | Configured | SPF: include:spf.protection.outlook.com; Verification token: MS=ms75548982; Autodiscover CNAME: autodiscover.mills-reeve.com | setup incomplete: DKIM missing |
| SendGrid | Transactional | Configured | DKIM keys: s1, s2 (1024 and 2048 bit, by CNAME) | setup complete |

## Reports go to

Mimecast DMARC Analyzer

## Not recognised

- SPF include: `emaileuc.freshservice.com`, from `mills-reeve.com TXT include:emaileuc.freshservice.com`
- SPF include: `fsspfeuc.freshemail.io`, from `emaileuc.freshservice.com TXT include:fsspfeuc.freshemail.io`
- SPF include: `spf-uk.vx-email.com`, from `mills-reeve.com TXT include:spf-uk.vx-email.com`
- IP address in SPF: `51.145.78.124 (AS8075, Microsoft)`, from `mills-reeve.com TXT ip4:51.145.78.124`
- 2 ranges in AS16509 (Amazon Web Services): `35.159.219.224/28`, `18.199.180.160/27`, from `fsspfeuc.freshemail.io TXT ip4:35.159.219.224/28` + 1 more
- IP range in SPF: `193.5.144.0/24 (AS14618, Amazon Web Services)`, from `spf-uk.vx-email.com TXT ip4:193.5.144.0/24`
- 4 addresses in AS2110 (AS-BTIRE - Enet Communications LIMITED, IE): `193.120.143.138`, `193.120.143.134`, `193.120.143.70`, `193.120.142.176`, from `mills-reeve.com TXT ip4:193.120.143.138` + 3 more
- SPF include: `spf-uk.vx-email.com` at update.mills-reeve.com, from `update.mills-reeve.com TXT include:spf-uk.vx-email.com`
- mail server: `mx01.mail.vx-email.com` at update.mills-reeve.com, from `update.mills-reeve.com MX 10 mx01.mail.vx-email.com`
- mail server: `mx02.mail.vx-email.com` at update.mills-reeve.com, from `update.mills-reeve.com MX 20 mx02.mail.vx-email.com`
- IP range in SPF: `193.5.144.0/24 (AS14618, Amazon Web Services)` at update.mills-reeve.com, from `spf-uk.vx-email.com TXT ip4:193.5.144.0/24`
- SPF include: `cecollect.com` at updates.mills-reeve.com, from `updates.mills-reeve.com TXT include:cecollect.com`
- mail server: `mail.cecollect.com` at updates.mills-reeve.com, from `updates.mills-reeve.com MX 10 mail.cecollect.com`
- 1 range and 11 addresses in AS2914 (NTT-DATA-2914 - NTT America, Inc., US) at updates.mills-reeve.com: `62.73.189.146`, `83.231.138.176/28`, `62.73.162.65`, `62.73.162.66`, `62.73.162.67`, `62.73.162.68`, `62.73.162.69`, `62.73.162.70`, `62.73.162.71`, `62.73.162.72`, `62.73.162.73`, `62.73.162.74`, from `cecollect.com TXT ip4:62.73.189.146` + 11 more

## Not checked

- the website: not read: web checks were turned off (--no-web)
- certificate transparency, crt.sh: GET https://crt.sh/?q=%25.mills-reeve.com&output=json: not asked: read only with --ct (it also holds expired certificates)
- DKIM selectors at update.mills-reeve.com: 77 of 106 not asked: only the first 27 and the names its own SPF, MX or delegation backs were (cap)
- DKIM selectors at updates.mills-reeve.com: 79 of 106 not asked: only the first 27 and the names its own SPF, MX or delegation backs were (cap)

## What was asked

- **mills-reeve.com**: 106 DKIM selectors, 23 CNAME labels, 1 page
- **update.mills-reeve.com**: 29 DKIM selectors
- **updates.mills-reeve.com**: 27 DKIM selectors
