# Sendermap: mills-reeve.com

5 sending services found from public records checked 2026-10-12 01:24 UTC (627 lookups in 0.0 s over Google DNS over HTTPS).

Mimecast stands in front of the domain's mail as a security gateway, so the mailbox provider is not visible from MX. Four other services are set up to send as the domain: one commerce and apps (Docebo), one support and CRM (Freshdesk), one mailbox (Microsoft 365), one transactional (SendGrid). DMARC reports go to Mimecast DMARC Analyzer. Not checked: the website (turned off), DKIM selectors past the first 27 on two subdomains, and the crt.sh certificate log (read only with --ct).

## Needs attention

- **The s2 key at mills-reeve.com is 1024-bit** (warning). Some receivers already treat 1024-bit RSA keys as weak. Rotate to 2048-bit.
  - `s2._domainkey.mills-reeve.com TXT k=rsa; t=s (strict); p=MIGfMA0GCSqG..., 1024-bit, fp 1d0c1f3114d84753 via s2.domainkey.u10198980.wl231.sendgrid.net`
- **Microsoft 365 at mills-reeve.com has no DKIM** (warning). Its documented setup needs it and the map shows it missing: no key at selector1._domainkey or selector2._domainkey, names with no TXT record; this zone gives that answer for every name that does not exist.
  - `selector1._domainkey.mills-reeve.com TXT no record of this type`
  - `selector2._domainkey.mills-reeve.com TXT no record of this type`
- **MX at mills-reeve.com points at Mimecast, a security gateway** (note). Inferred from the MX records: a security gateway filters incoming mail and hands it on to the server that holds the mailboxes, and MX records do not say which server that is.
  - `mills-reeve.com MX 10 eu-smtp-inbound-1.mimecast.com`
  - `mills-reeve.com MX 10 eu-smtp-inbound-2.mimecast.com`

## Senders

| Service | Category | How sure | Evidence | Setup |
|---|---|---|---|---|
| Mimecast | Security gateway | In use | MX: eu-smtp-inbound-1.mimecast.com, eu-smtp-inbound-2.mimecast.com; SPF: include:eu._netblocks.mimecast.com, include:_netblocks.mimecast.com at mills-reeve.com and update.mills-reeve.com |  |
| Docebo | Commerce and apps | Configured | SPF: include:docebosaas.com |  |
| Freshdesk | Support and CRM | Configured | SPF range: ip4:3.120.181.200/29 |  |
| Microsoft 365 | Mailbox | Configured | SPF: include:spf.protection.outlook.com; Verification token: MS=ms75548982; Autodiscover CNAME: autodiscover.mills-reeve.com | setup incomplete: SPF present, DKIM missing, MX not used (optional, MX at mills-reeve.com), bounce CNAME not needed |
| SendGrid | Transactional | Configured | DKIM keys: s1, s2 (1024 and 2048 bit, by CNAME) | setup complete: DKIM present, bounce CNAME not used (optional, CNAME at 25 labels under mills-reeve.com), SPF not needed, tracking CNAME not used (optional, CNAME at 25 labels under mills-reeve.com) |

## Records

- **Mimecast**
  - MX
    - `mills-reeve.com MX 10 eu-smtp-inbound-1.mimecast.com`
    - `mills-reeve.com MX 10 eu-smtp-inbound-2.mimecast.com`
  - SPF
    - `mills-reeve.com TXT include:eu._netblocks.mimecast.com`
    - `update.mills-reeve.com TXT include:_netblocks.mimecast.com`
- **Docebo**
  - SPF
    - `mills-reeve.com TXT include:docebosaas.com`
- **Freshdesk**
  - SPF range
    - `fsspfeuc.freshemail.io TXT ip4:3.120.181.200/29 via fdspfeuc.freshemail.io TXT ip4:3.120.181.192/28`
- **Microsoft 365**
  - SPF
    - `mills-reeve.com TXT include:spf.protection.outlook.com`
  - Verification token
    - `mills-reeve.com TXT MS=ms75548982`
  - Autodiscover CNAME
    - `autodiscover.mills-reeve.com CNAME autodiscover.outlook.com`
- **SendGrid**
  - DKIM keys
    - `s1._domainkey.mills-reeve.com TXT k=rsa; t=s (strict); p=MIIBIjANBgkq..., 2048-bit, fp ae8406c18072b4fc via s1.domainkey.u10198980.wl231.sendgrid.net`
    - `s2._domainkey.mills-reeve.com TXT k=rsa; t=s (strict); p=MIGfMA0GCSqG..., 1024-bit, fp 1d0c1f3114d84753 via s2.domainkey.u10198980.wl231.sendgrid.net`

## Reports go to

Mimecast DMARC Analyzer

## Not recognised

- SPF include: `emaileuc.freshservice.com`, from `mills-reeve.com TXT include:emaileuc.freshservice.com`
- SPF include: `fsspfeuc.freshemail.io`, from `emaileuc.freshservice.com TXT include:fsspfeuc.freshemail.io`
- SPF include: `spf-uk.vx-email.com`, from `mills-reeve.com TXT include:spf-uk.vx-email.com`
- IP address in SPF: `51.145.78.124 (AS8075, Microsoft)`, from `mills-reeve.com TXT ip4:51.145.78.124`
- 2 ranges in AS16509 (Amazon Web Services): `35.159.219.224/28`, `18.199.180.160/27`
  - `fsspfeuc.freshemail.io TXT ip4:35.159.219.224/28`
  - `fsspfeuc.freshemail.io TXT ip4:18.199.180.160/27`
- IP range in SPF: `193.5.144.0/24 (AS14618, Amazon Web Services)`, from `spf-uk.vx-email.com TXT ip4:193.5.144.0/24`
- 4 addresses in AS2110 (AS-BTIRE - Enet Communications LIMITED, IE): `193.120.143.138`, `193.120.143.134`, `193.120.143.70`, `193.120.142.176`
  - `mills-reeve.com TXT ip4:193.120.143.138`
  - `mills-reeve.com TXT ip4:193.120.143.134`
  - `mills-reeve.com TXT ip4:193.120.143.70`
  - `mills-reeve.com TXT ip4:193.120.142.176`
- SPF include: `spf-uk.vx-email.com` at update.mills-reeve.com, from `update.mills-reeve.com TXT include:spf-uk.vx-email.com`
- mail server: `mx01.mail.vx-email.com` at update.mills-reeve.com, from `update.mills-reeve.com MX 10 mx01.mail.vx-email.com`
- mail server: `mx02.mail.vx-email.com` at update.mills-reeve.com, from `update.mills-reeve.com MX 20 mx02.mail.vx-email.com`
- IP range in SPF: `193.5.144.0/24 (AS14618, Amazon Web Services)` at update.mills-reeve.com, from `spf-uk.vx-email.com TXT ip4:193.5.144.0/24`
- SPF include: `cecollect.com` at updates.mills-reeve.com, from `updates.mills-reeve.com TXT include:cecollect.com`
- mail server: `mail.cecollect.com` at updates.mills-reeve.com, from `updates.mills-reeve.com MX 10 mail.cecollect.com`
- 1 range and 11 addresses in AS2914 (NTT-DATA-2914 - NTT America, Inc., US) at updates.mills-reeve.com: `62.73.189.146`, `83.231.138.176/28`, `62.73.162.65`, `62.73.162.66`, `62.73.162.67`, `62.73.162.68`, `62.73.162.69`, `62.73.162.70`, `62.73.162.71`, `62.73.162.72`, `62.73.162.73`, `62.73.162.74`
  - `cecollect.com TXT ip4:62.73.189.146`
  - `cecollect.com TXT ip4:83.231.138.176/28`
  - `cecollect.com TXT ip4:62.73.162.65`
  - `cecollect.com TXT ip4:62.73.162.66`
  - `cecollect.com TXT ip4:62.73.162.67`
  - `cecollect.com TXT ip4:62.73.162.68`
  - `cecollect.com TXT ip4:62.73.162.69`
  - `cecollect.com TXT ip4:62.73.162.70`
  - `cecollect.com TXT ip4:62.73.162.71`
  - `cecollect.com TXT ip4:62.73.162.72`
  - `cecollect.com TXT ip4:62.73.162.73`
  - `cecollect.com TXT ip4:62.73.162.74`

## Not checked

- DKIM selectors at update.mills-reeve.com: 80 of 109 not asked: only the first 27 and the names its own SPF, MX or delegation backs were (cap)
- DKIM selectors at updates.mills-reeve.com: 82 of 109 not asked: only the first 27 and the names its own SPF, MX or delegation backs were (cap)

## What was asked

- **mills-reeve.com**: 109 DKIM selectors, 25 CNAME labels, 1 page
- **update.mills-reeve.com**: 29 DKIM selectors
- **updates.mills-reeve.com**: 27 DKIM selectors

## Not run

- the website: web checks were turned off (--no-web)
- certificate transparency, crt.sh: read only with --ct (it also holds expired certificates)

## Appendix: names asked

- **mills-reeve.com**
  - Pages: `https://api.certspotter.com/v1/issuances?domain=mills-reeve.com&include_subdomains=true&expand=dns_names`
  - CNAME labels: `bounce`, `bounces`, `em`, `email`, `mail`, `send`, `mta`, `rp`, `pm-bounces`, `links`, `link`, `click`, `track`, `tracking`, `url`, `go`, `autodiscover`, `cf-bounce`, `eversrv`, `fwdkim1`, `bnc3`, `bounces.cloud.em`, `bounces.cloud2.em`, `outbound.intercom`, `atlassian-bounces`
  - DKIM selectors: `selector1`, `selector2`, `acdkim1`, `acdkim2`, `ses`, `aweber_key_a`, `aweber_key_b`, `aweber_key_c`, `brevo`, `brevo1`, `brevo2`, `cm`, `cf2024-1`, `ctct1`, `ctct2`, `krs`, `e2ma-k1`, `e2ma-k2`, `e2ma-k3`, `everlytickey1`, `everlytickey2`, `fm2`, `fm1`, `fm3`, `mesmtp`, `secureserver1`, `secureserver2`, `google`, `gapps`, `gor`, `strong1`, `strong2`, `hs1`, `hs2`, `intercom`, `s1-ionos`, `s42582890`, `s2-ionos`, `cka`, `kl`, `kl1`, `kl2`, `km1`, `km2`, `k2`, `k1`, `k3`, `litesrv`, `mg`, `mailgun`, `mg1`, `pdk1`, `pdk2`, `mailjet`, `mailpoet2`, `mailpoet1`, `mandrill`, `mte1`, `mte2`, `marketo`, `mkto`, `mkto1`, `mimecast`, `mimecast20190719`, `pepipost`, `pp1`, `protonmail`, `protonmail2`, `protonmail3`, `resend`, `sailthru`, `salesforce`, `salesforce2`, `salesforce1`, `sf`, `sf1`, `sf2`, `sfdc`, `200608`, `pardot`, `sfmc`, `s1`, `s2`, `smtpapi`, `scph0819`, `sparkpost`, `squarespace`, `zendesk1`, `zendesk2`, `zoho`, `api`, `default`, `dk`, `dkim`, `dkim1`, `dkim2`, `email`, `k`, `key`, `key1`, `key2`, `mail`, `mta`, `mx`, `pm`, `s`, `selector`, `smtp`, `sp`
- **update.mills-reeve.com**
  - DKIM selectors: `acdkim1`, `acdkim2`, `ses`, `aweber_key_a`, `aweber_key_b`, `aweber_key_c`, `brevo`, `brevo1`, `brevo2`, `cm`, `cf2024-1`, `ctct1`, `ctct2`, `krs`, `e2ma-k1`, `e2ma-k2`, `e2ma-k3`, `everlytickey1`, `everlytickey2`, `fm2`, `fm1`, `fm3`, `mesmtp`, `secureserver1`, `secureserver2`, `google`, `gapps`, `mimecast`, `mimecast20190719`
- **updates.mills-reeve.com**
  - DKIM selectors: `acdkim1`, `acdkim2`, `ses`, `aweber_key_a`, `aweber_key_b`, `aweber_key_c`, `brevo`, `brevo1`, `brevo2`, `cm`, `cf2024-1`, `ctct1`, `ctct2`, `krs`, `e2ma-k1`, `e2ma-k2`, `e2ma-k3`, `everlytickey1`, `everlytickey2`, `fm2`, `fm1`, `fm3`, `mesmtp`, `secureserver1`, `secureserver2`, `google`, `gapps`
