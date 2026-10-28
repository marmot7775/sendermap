# Who handles email for allbirds.com?

**15 services handle email for allbirds.com. 3 things need fixing.**

Microsoft 365 receives the domain's mail and has a DKIM key in place to sign it.

Twelve other services are set up to send as the domain: six transactional (Amazon SES, Mailgun, Mailjet, Postmark, SendGrid, SparkPost), two support and CRM (Freshdesk, Zendesk), one mailbox (Google Workspace), two marketing (Iterable, Mailchimp), one commerce and apps (Shopify); two more are likely from a DKIM key name alone (Customer.io, Mandrill).

## Who handles your email

Each service below receives or sends email for allbirds.com.

Receives your mail: your MX records deliver the domain's mail there.

Set up to send: its records for sending are in your DNS.

Likely sends: one clue points to it, such as a key named for it.

- **Microsoft 365** (Mailbox): receives your mail; setup complete
- **Amazon SES** (Transactional): set up to send
- **Freshdesk** (Support and CRM): set up to send
- **Google Workspace** (Mailbox): set up to send; setup incomplete
- **Iterable** (Marketing): set up to send
- **Mailchimp** (Marketing): set up to send; setup complete
- **Mailgun** (Transactional): set up to send; setup complete
- **Mailjet** (Transactional): set up to send; setup incomplete
- **Postmark** (Transactional): set up to send; setup complete
- **SendGrid** (Transactional): set up to send; setup complete
- **Shopify** (Commerce and apps): set up to send
- **SparkPost** (Transactional): set up to send; setup complete
- **Zendesk** (Support and CRM): set up to send; setup complete
- **Customer.io** (Marketing): likely sends; from: DKIM key
- **Mandrill** (Transactional): likely sends; from: DKIM key

## What to fix

Problems found in the setup, most serious first.

1. **Two DKIM keys at allbirds.com are 1024-bit: k1 (Mailchimp) and mandrill (Mandrill)** (warning)

   Some receivers already treat 1024-bit RSA keys as weak. Rotate to 2048-bit.

2. **Google Workspace at alerts.allbirds.com and mail.allbirds.com has no DKIM** (warning)

   Its documented setup needs it and the map shows it missing: no key at google._domainkey, a name that does not exist.

3. **Mailjet at allbirds.com has no DKIM** (warning)

   Its documented setup needs it and the map shows it missing: no key at mailjet._domainkey, a name that does not exist.

## Good to know

Nothing to change here. These explain what the map shows.

- **SPF at allbirds.com is managed through EasyDMARC**. EasyDMARC copies the domain's senders into its own record. The walk read that record, so the services and ranges it lists are reported here as the domain's.

## The proof, service by service

The DNS records behind each service above, for anyone who wants to check them.

MX: where the domain's mail is delivered.

SPF: the list of servers allowed to send as the domain.

DKIM: a signature key that proves mail really came from the domain.

Verification token: proves the domain owner set up an account with the service.

Autodiscover: lets mail apps find their settings.

Tracking CNAME: links in a service's emails point here.

Bounce CNAME: lets a service handle bounced mail under the domain's name.

### Microsoft 365

Mailbox · receives your mail

- MX: allbirds-com.mail.protection.outlook.com
- SPF: include:spf.protection.outlook.com
- DKIM keys: selector1, selector2 (both 2048 bit, by CNAME)
- Verification tokens: MS=A01B077C9CEAFC03E22F0B625C7E7600E37CC59A, MS=ms40651830, MS=ms79507765
- Autodiscover CNAME: autodiscover.allbirds.com
- Setup: complete

### Amazon SES

Transactional · set up to send

- SPF ranges: ip4:199.255.192.0/22, ip4:199.127.232.0/22 and 11 more
- SPF: include:amazonses.com at alerts.allbirds.com and mail.allbirds.com

### Freshdesk

Support and CRM · set up to send

- SPF ranges: ip4:3.7.25.40/29, ip4:13.127.153.86 and 6 more

### Google Workspace

Mailbox · set up to send

- SPF ranges: ip4:74.125.0.0/16, ip4:209.85.128.0/17 and 6 more
- MX for a subdomain's mail: aspmx.l.google.com, alt1.aspmx.l.google.com, alt2.aspmx.l.google.com at mail.allbirds.com
- SPF: include:_spf.google.com at alerts.allbirds.com and mail.allbirds.com
- DKIM key: google (2048 bit, named for it)
- Setup: incomplete: DKIM missing at alerts.allbirds.com and mail.allbirds.com

### Iterable

Marketing · set up to send

- Tracking CNAME: links.allbirds.com

### Mailchimp

Marketing · set up to send

- DKIM key: k1 (1024 bit, by CNAME)
- Setup: complete

### Mailgun

Transactional · set up to send

- SPF ranges: ip4:141.193.32.0/23, ip4:159.135.140.80/29 and 16 more
- Tracking CNAME: email.allbirds.com
- MX for bounces: mxa.mailgun.org, mxb.mailgun.org at email.allbirds.com
- SPF: include:mailgun.org, include:_spf.mailgun.org, include:_spf.eu.mailgun.org at alerts.allbirds.com, email.allbirds.com and mail.allbirds.com
- Setup: complete

### Mailjet

Transactional · set up to send

- SPF ranges: ip4:87.253.232.0/21, ip4:185.189.236.0/22 and 2 more
- Setup: incomplete: DKIM missing

### Postmark

Transactional · set up to send

- Bounce CNAME: pm-bounces.allbirds.com
- Setup: complete

### SendGrid

Transactional · set up to send

- SPF ranges: ip4:208.117.48.0/20, ip4:50.31.32.0/19 and 16 more
- DKIM keys: s1, s2 (both 2048 bit, by CNAME)
- Setup: complete

### Shopify

Commerce and apps · set up to send

- SPF: include:shops.shopify.com at alerts.allbirds.com and mail.allbirds.com

### SparkPost

Transactional · set up to send

- Bounce CNAME: bounce.allbirds.com
- MX for bounces: smtp.sparkpostmail.com at bounce.allbirds.com and info.allbirds.com
- Setup: complete

### Zendesk

Support and CRM · set up to send

- SPF ranges: ip4:103.151.192.0/23, ip4:185.12.80.0/22 and 3 more
- Setup: complete

### Customer.io

Marketing · likely sends

- DKIM key: krs (2048 bit, named for it)
- Setup: complete

### Mandrill

Transactional · likely sends

- DKIM key: mandrill (1024 bit, named for it)
- Setup: complete

## Not matched to a service

These records point somewhere Sendermap does not recognise: a service it does not know yet, or your own servers.

- 2 ranges in AS16509 (Amazon Web Services): `35.159.219.224/28`, `18.199.180.160/27`, from `_spf1.allbirds_com._d.easydmarc.pro TXT ip4:35.159.219.224/28` + 1 more
- IP address in SPF: `157.131.136.130 (AS46375, AS-SONICTELECOM - Sonic Telecom LLC, US)` at mail.allbirds.com, from `mail.allbirds.com TXT ip4:157.131.136.130`
- IP address in SPF: `116.66.213.98 (AS3491, PCCWG-APAC-HK PCCW Global HK Ltd., HK)` at mail.allbirds.com, from `mail.allbirds.com TXT ip4:116.66.213.98`
- IP address in SPF: `96.71.160.117 (AS7922, COMCAST-7922 - Comcast Cable Communications, LLC, US)` at mail.allbirds.com, from `mail.allbirds.com TXT ip4:96.71.160.117`
- IP address in SPF: `216.40.27.182 (AS53828, NITEL - NETWORK INNOVATIONS, LLC, US)` at mail.allbirds.com, from `mail.allbirds.com TXT ip4:216.40.27.182`

## Looked for and not found

Records Sendermap looked for and did not find.

- DKIM keys at alerts.allbirds.com: selectors exist but none of the 32 names asked is one
  - `_domainkey.alerts.allbirds.com TXT no record of this type`
- DKIM keys at bounce.allbirds.com: no selectors exist: _domainkey.bounce.allbirds.com does not exist, so the 27-name sweep was skipped; the 8 names its MX, SPF and delegations point to were asked as a check, and none exists (RFC 8020 section 5)
  - `_domainkey.bounce.allbirds.com TXT no such name`
  - `sendermap-wildcard-check._domainkey.bounce.allbirds.com TXT no such name`
- DKIM keys at email.allbirds.com: no selectors exist: _domainkey.email.allbirds.com does not exist, so the 32-name sweep was skipped; the 13 names its MX, SPF and delegations point to were asked as a check, and none exists (RFC 8020 section 5)
  - `_domainkey.email.allbirds.com TXT no such name`
  - `sendermap-wildcard-check._domainkey.email.allbirds.com TXT no such name`
- DKIM keys at info.allbirds.com: selectors exist but none of the 27 names asked is one
  - `_domainkey.info.allbirds.com TXT no record of this type`
- DKIM keys at mail.allbirds.com: selectors exist but none of the 32 names asked is one
  - `_domainkey.mail.allbirds.com TXT no record of this type`

## How this was checked

Checked 2026-10-12 01:24 UTC: 764 DNS lookups in 0.0 s over Google DNS over HTTPS.

- At allbirds.com: 110 possible DKIM key names, 25 service record names, 1 web page.
- At alerts.allbirds.com: 32 possible DKIM key names.
- At bounce.allbirds.com: 8 possible DKIM key names.
- At email.allbirds.com: 13 possible DKIM key names.
- At info.allbirds.com: 27 possible DKIM key names.
- At mail.allbirds.com: 32 possible DKIM key names.

Not checked:

- certificate log names more than 2 labels deep: 34 not asked. Names up to 2 labels below the domain were asked (cap 2 labels).
- sending subdomains: TXT, MX and NS at apisdk.allbirds.com, community.allbirds.com, dataplane.allbirds.com, jssdk.allbirds.com, rerun.allbirds.com, www.jssdk.allbirds.com: the domain's DNS servers failed to answer (SERVFAIL), so whether they send is not known
- DKIM selectors at alerts and mail.allbirds.com: 78 of 110 not asked at each. The first 27 were asked, plus any the name's own SPF, MX or delegation points to (cap 27).
- DKIM selectors at info.allbirds.com: 83 of 110 not asked. The first 27 were asked, plus any the name's own SPF, MX or delegation points to (cap 27).

Not run:

- the website. Web checks were turned off (--no-web).
- certificate transparency, crt.sh. Read only with --ct (it also holds expired certificates).
