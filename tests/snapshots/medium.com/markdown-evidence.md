# Who handles email for medium.com?

**10 services handle email for medium.com. 4 things need fixing.**

Google Workspace receives the domain's mail and has a DKIM key in place to sign it.

Six other services are set up to send as the domain: two transactional (Amazon SES, SendGrid), two support and CRM (Intercom, Zendesk), two commerce and apps (KnowBe4, Tipalti); three more are likely from a DKIM key name alone (Cloudflare Email Routing, Kit, Mandrill).

DMARC reports go to Valimail.

## Who handles your email

Each service below receives or sends email for medium.com.

Receives your mail: your MX records deliver the domain's mail there.

Set up to send: its records for sending are in your DNS.

Likely sends: one clue points to it, such as a key named for it.

- **Google Workspace** (Mailbox): receives your mail; setup incomplete
- **Amazon SES** (Transactional): set up to send
- **Intercom** (Support and CRM): set up to send; setup complete
- **KnowBe4** (Commerce and apps): set up to send
- **SendGrid** (Transactional): set up to send; setup complete
- **Tipalti** (Commerce and apps): set up to send
- **Zendesk** (Support and CRM): set up to send; setup complete
- **Cloudflare Email Routing** (Mailbox): likely sends; from: DKIM key
- **Kit** (Marketing): likely sends; from: DKIM key
- **Mandrill** (Transactional): likely sends; from: DKIM key

## What to fix

Problems found in the setup, most serious first.

1. **Seven DKIM keys at medium.com are 1024-bit: google (Google Workspace), s2 (SendGrid), smtpapi (SendGrid), intercom (Intercom), cka (Kit), mandrill (Mandrill) and mx** (warning)

   Some receivers already treat 1024-bit RSA keys as weak. Rotate to 2048-bit.

   - `google._domainkey.medium.com TXT v=DKIM1; k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp ed74a6d0292ef851`
   - `s2._domainkey.medium.com TXT k=rsa; t=s (strict); p=MIGfMA0GCSqG..., 1024-bit, fp 656c793271cffad5 via s2.domainkey.u1815634.wl135.sendgrid.net`
   - `smtpapi._domainkey.medium.com TXT k=rsa; t=s (strict); p=MIGfMA0GCSqG..., 1024-bit, fp 303963420cfee1c6`
   - `intercom._domainkey.medium.com TXT k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp c5fb9f656f567b63 via 5fdfac11-2ed9-41ef-9460-e56a59043246.dkim.intercom.io`
   - `cka._domainkey.medium.com TXT k=rsa; t=s (strict); p=MIGfMA0GCSqG..., 1024-bit, fp ae2635ee9f973947 via dkim.dm-0m73zvny.sg7.convertkit.com`
   - `mandrill._domainkey.medium.com TXT v=DKIM1; k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp 9cee89b6f986543a`
   - `mx._domainkey.medium.com TXT k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp ed9c30e7c3b40a07`

2. **The SendGrid key smtpapi at email.medium.com is 1024-bit** (warning)

   Some receivers already treat 1024-bit RSA keys as weak. Rotate to 2048-bit.

   - `smtpapi._domainkey.email.medium.com TXT k=rsa; t=s (strict); p=MIGfMA0GCSqG..., 1024-bit, fp 303963420cfee1c6`

3. **Google Workspace at mail.medium.com has no SPF** (warning)

   Its documented setup needs it and the map shows it missing: no SPF record.

   - `mail.medium.com TXT no SPF record (v=spf1)`

4. **Google Workspace at mail.medium.com has no DKIM** (warning)

   Its documented setup needs it and the map shows it missing: no key at google._domainkey, a name that does not exist.

   - `google._domainkey.mail.medium.com TXT no such name`
   - `_domainkey.mail.medium.com TXT no record of this type`

## Good to know

Nothing to change here. These explain what the map shows.

- **The smtpapi key at medium.com and the smtpapi key at email.medium.com are the same key**. They publish one public key, fp 303963420cfee1c6, so one private key signs for all of them, and replacing the key at one selector leaves it live at the others.
  - `smtpapi._domainkey.medium.com TXT k=rsa; t=s (strict); p=MIGfMA0GCSqG..., 1024-bit, fp 303963420cfee1c6`
  - `smtpapi._domainkey.email.medium.com TXT k=rsa; t=s (strict); p=MIGfMA0GCSqG..., 1024-bit, fp 303963420cfee1c6`
- **Cloudflare Email Routing at medium.com has no SPF**. Its documented setup needs it and the map shows it missing: the record does not authorize _spf.mx.cloudflare.net. The map shows this service only as likely, so check it still sends first.
  - `medium.com TXT v=spf1 include:amazonses.com include:_spf.google.com include:mail.zendesk.com include:sendgrid.net include:spf.tipalti.com include:_spf.psm.knowbe4.com ~all`

## The proof, service by service

The DNS records behind each service above, for anyone who wants to check them.

MX: where the domain's mail is delivered.

SPF: the list of servers allowed to send as the domain.

DKIM: a signature key that proves mail really came from the domain.

Bounce CNAME: lets a service handle bounced mail under the domain's name.

### Google Workspace

Mailbox · receives your mail

- MX: aspmx.l.google.com, alt1.aspmx.l.google.com and 3 more
  - `medium.com MX 1 aspmx.l.google.com`
  - `medium.com MX 5 alt1.aspmx.l.google.com`
  - `medium.com MX 5 alt2.aspmx.l.google.com`
  - `medium.com MX 10 aspmx2.googlemail.com`
  - `medium.com MX 10 aspmx3.googlemail.com`
- SPF: include:_spf.google.com
  - `medium.com TXT include:_spf.google.com`
- MX for a subdomain's mail: aspmx.l.google.com, alt1.aspmx.l.google.com and 3 more at mail.medium.com
  - `mail.medium.com MX 1 aspmx.l.google.com`
  - `mail.medium.com MX 5 alt1.aspmx.l.google.com`
  - `mail.medium.com MX 5 alt2.aspmx.l.google.com`
  - `mail.medium.com MX 10 alt3.aspmx.l.google.com`
  - `mail.medium.com MX 10 alt4.aspmx.l.google.com`
- DKIM key: google (1024 bit, named for it)
  - `google._domainkey.medium.com TXT v=DKIM1; k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp ed74a6d0292ef851 via medium.com TXT include:_spf.google.com`
- Setup: incomplete: SPF present at medium.com, DKIM present at medium.com, MX present at medium.com and mail.medium.com, bounce CNAME not needed at medium.com and mail.medium.com, SPF missing at mail.medium.com, DKIM missing at mail.medium.com

### Amazon SES

Transactional · set up to send

- SPF: include:amazonses.com
  - `medium.com TXT include:amazonses.com`

### Intercom

Support and CRM · set up to send

- DKIM key: intercom (1024 bit, by CNAME)
  - `intercom._domainkey.medium.com TXT k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp c5fb9f656f567b63 via 5fdfac11-2ed9-41ef-9460-e56a59043246.dkim.intercom.io`
- Bounce CNAME: outbound.intercom.medium.com
  - `outbound.intercom.medium.com CNAME rp.medium-a7e301761373.intercom-mail.com`
- Setup: complete: SPF not needed, DKIM present

### KnowBe4

Commerce and apps · set up to send

- SPF: include:_spf.psm.knowbe4.com
  - `medium.com TXT include:_spf.psm.knowbe4.com`

### SendGrid

Transactional · set up to send

- SPF: include:sendgrid.net
  - `medium.com TXT include:sendgrid.net`
- DKIM keys: s1 2048 bit, s2 1024 bit (by CNAME)
  - `s1._domainkey.medium.com TXT k=rsa; t=s (strict); p=MIIBIjANBgkq..., 2048-bit, fp c8d37e821f8cbd21 via s1.domainkey.u1815634.wl135.sendgrid.net`
  - `s2._domainkey.medium.com TXT k=rsa; t=s (strict); p=MIGfMA0GCSqG..., 1024-bit, fp 656c793271cffad5 via s2.domainkey.u1815634.wl135.sendgrid.net`
- MX for bounces: mx.sendgrid.net at email.medium.com
  - `email.medium.com MX 10 mx.sendgrid.net`
- SPF ranges: ip4:149.72.137.151, ip4:149.72.133.6 and 32 more at email.medium.com
  - `_digest-one.medium.com TXT ip4:149.72.137.151 via sendgrid.net TXT ip4:149.72.0.0/16`
  - `_digest-one.medium.com TXT ip4:149.72.133.6 via sendgrid.net TXT ip4:149.72.0.0/16`
  - `_digest-one.medium.com TXT ip4:149.72.133.59 via sendgrid.net TXT ip4:149.72.0.0/16`
  - `_digest-two.medium.com TXT ip4:149.72.177.63 via sendgrid.net TXT ip4:149.72.0.0/16`
  - `_digest-two.medium.com TXT ip4:149.72.177.236 via sendgrid.net TXT ip4:149.72.0.0/16`
  - `_digest-two.medium.com TXT ip4:149.72.177.231 via sendgrid.net TXT ip4:149.72.0.0/16`
  - `_digest-two.medium.com TXT ip4:149.72.177.225 via sendgrid.net TXT ip4:149.72.0.0/16`
  - `_digest-two.medium.com TXT ip4:149.72.177.21 via sendgrid.net TXT ip4:149.72.0.0/16`
  - `_digest-two.medium.com TXT ip4:149.72.177.204 via sendgrid.net TXT ip4:149.72.0.0/16`
  - `_digest-two.medium.com TXT ip4:149.72.177.190 via sendgrid.net TXT ip4:149.72.0.0/16`
  - `_digest-two.medium.com TXT ip4:149.72.177.155 via sendgrid.net TXT ip4:149.72.0.0/16`
  - `_digest-two.medium.com TXT ip4:149.72.122.8 via sendgrid.net TXT ip4:149.72.0.0/16`
  - `_digest-two.medium.com TXT ip4:149.72.117.99 via sendgrid.net TXT ip4:149.72.0.0/16`
  - `_legal.medium.com TXT ip4:159.183.144.235 via sendgrid.net TXT ip4:159.183.0.0/16`
  - `_legal.medium.com TXT ip4:159.183.145.91 via sendgrid.net TXT ip4:159.183.0.0/16`
  - `_legal.medium.com TXT ip4:159.183.160.29 via sendgrid.net TXT ip4:159.183.0.0/16`
  - `_letters.medium.com TXT ip4:159.183.172.152 via sendgrid.net TXT ip4:159.183.0.0/16`
  - `_letters.medium.com TXT ip4:149.72.199.196 via sendgrid.net TXT ip4:149.72.0.0/16`
  - `_partnerprogram.medium.com TXT ip4:159.183.176.0 via sendgrid.net TXT ip4:159.183.0.0/16`
  - `_transactional.medium.com TXT ip4:149.72.36.156 via sendgrid.net TXT ip4:149.72.0.0/16`
  - `_auth.medium.com TXT ip4:149.72.23.220 via sendgrid.net TXT ip4:149.72.0.0/16`
  - `_auth.medium.com TXT ip4:159.183.87.116 via sendgrid.net TXT ip4:159.183.0.0/16`
  - `_campaigns.medium.com TXT ip4:167.89.66.191 via 191.66.89.167.origin.asn.cymru.com TXT 11377 | 167.89.64.0/19 | US | arin | 2013-10-31 via as11377.asn.cymru.com TXT 11377 | US | arin | 2012-06-28 | SENDGRID - SendGrid, Inc., US`
  - `_campaigns.medium.com TXT ip4:167.89.66.175 via 175.66.89.167.origin.asn.cymru.com TXT 11377 | 167.89.64.0/19 | US | arin | 2013-10-31 via as11377.asn.cymru.com TXT 11377 | US | arin | 2012-06-28 | SENDGRID - SendGrid, Inc., US`
  - `_digest-one.medium.com TXT ip4:168.245.100.68 via 68.100.245.168.origin.asn.cymru.com TXT 11377 | 168.245.96.0/19 | US | arin | 2016-11-10 via as11377.asn.cymru.com TXT 11377 | US | arin | 2012-06-28 | SENDGRID - SendGrid, Inc., US`
  - `_digest-one.medium.com TXT ip4:168.245.3.222 via 222.3.245.168.origin.asn.cymru.com TXT 11377 | 168.245.0.0/18 | US | arin | 2016-11-10 via as11377.asn.cymru.com TXT 11377 | US | arin | 2012-06-28 | SENDGRID - SendGrid, Inc., US`
  - `_digest-one.medium.com TXT ip4:167.89.47.62 via 62.47.89.167.origin.asn.cymru.com TXT 11377 | 167.89.0.0/18 | US | arin | 2013-10-31 via as11377.asn.cymru.com TXT 11377 | US | arin | 2012-06-28 | SENDGRID - SendGrid, Inc., US`
  - `_digest-one.medium.com TXT ip4:167.89.15.8 via 8.15.89.167.origin.asn.cymru.com TXT 11377 | 167.89.0.0/18 | US | arin | 2013-10-31 via as11377.asn.cymru.com TXT 11377 | US | arin | 2012-06-28 | SENDGRID - SendGrid, Inc., US`
  - `_digest-one.medium.com TXT ip4:167.89.15.48 via 48.15.89.167.origin.asn.cymru.com TXT 11377 | 167.89.0.0/18 | US | arin | 2013-10-31 via as11377.asn.cymru.com TXT 11377 | US | arin | 2012-06-28 | SENDGRID - SendGrid, Inc., US`
  - `_digest-one.medium.com TXT ip4:167.89.110.85 via 85.110.89.167.origin.asn.cymru.com TXT 11377 | 167.89.96.0/20 | US | arin | 2013-10-31 via as11377.asn.cymru.com TXT 11377 | US | arin | 2012-06-28 | SENDGRID - SendGrid, Inc., US`
  - `_digest-one.medium.com TXT ip4:167.89.110.59 via 59.110.89.167.origin.asn.cymru.com TXT 11377 | 167.89.96.0/20 | US | arin | 2013-10-31 via as11377.asn.cymru.com TXT 11377 | US | arin | 2012-06-28 | SENDGRID - SendGrid, Inc., US`
  - `_legal.medium.com TXT ip4:168.245.8.34 via 34.8.245.168.origin.asn.cymru.com TXT 11377 | 168.245.0.0/18 | US | arin | 2016-11-10 via as11377.asn.cymru.com TXT 11377 | US | arin | 2012-06-28 | SENDGRID - SendGrid, Inc., US`
  - `_letters.medium.com TXT ip4:167.89.49.168 via 168.49.89.167.origin.asn.cymru.com TXT 11377 | 167.89.0.0/18 | US | arin | 2013-10-31 via as11377.asn.cymru.com TXT 11377 | US | arin | 2012-06-28 | SENDGRID - SendGrid, Inc., US`
  - `_transactional.medium.com TXT ip4:167.89.65.228 via 228.65.89.167.origin.asn.cymru.com TXT 11377 | 167.89.64.0/19 | US | arin | 2013-10-31 via as11377.asn.cymru.com TXT 11377 | US | arin | 2012-06-28 | SENDGRID - SendGrid, Inc., US`
- DKIM keys: smtpapi (both 1024 bit, named for it) at medium.com and email.medium.com
  - `smtpapi._domainkey.medium.com TXT k=rsa; t=s (strict); p=MIGfMA0GCSqG..., 1024-bit, fp 303963420cfee1c6 via medium.com TXT include:sendgrid.net`
  - `smtpapi._domainkey.email.medium.com TXT k=rsa; t=s (strict); p=MIGfMA0GCSqG..., 1024-bit, fp 303963420cfee1c6`
- Setup: complete: DKIM present, bounce CNAME present, SPF not needed, tracking CNAME not used (optional, CNAME at 25 labels under medium.com)

### Tipalti

Commerce and apps · set up to send

- SPF: include:spf.tipalti.com
  - `medium.com TXT include:spf.tipalti.com`

### Zendesk

Support and CRM · set up to send

- SPF: include:mail.zendesk.com at medium.com and help.medium.com
  - `medium.com TXT include:mail.zendesk.com`
  - `help.medium.com TXT include:mail.zendesk.com`
- DKIM keys: zendesk1, zendesk2 (both 2048 bit, by CNAME)
  - `zendesk1._domainkey.medium.com TXT v=DKIM1; t=s (strict); n=core; k=rsa; p=MIIBIjANBgkq..., 2048-bit, fp cb942434bd40aaba via zendesk1._domainkey.zendesk.com`
  - `zendesk2._domainkey.medium.com TXT v=DKIM1; t=s (strict); n=core; k=rsa; p=MIIBIjANBgkq..., 2048-bit, fp c5fa8a017cd8c5a5 via zendesk2._domainkey.zendesk.com`
- MX for bounces: mail-pod-23.int.zendesk.com at help.medium.com
  - `help.medium.com MX 10 mail-pod-23.int.zendesk.com`
- Setup: complete: SPF present, DKIM present

### Cloudflare Email Routing

Mailbox · likely sends

- DKIM key: cf2024-1 (2048 bit, named for it)
  - `cf2024-1._domainkey.medium.com TXT v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkq..., 2048-bit, fp 3893fd85802c0281`
- Setup: incomplete: MX not used (optional, MX at medium.com), SPF missing, DKIM present

### Kit

Marketing · likely sends

- DKIM key: cka (1024 bit, named for it)
  - `cka._domainkey.medium.com TXT k=rsa; t=s (strict); p=MIGfMA0GCSqG..., 1024-bit, fp ae2635ee9f973947 via dkim.dm-0m73zvny.sg7.convertkit.com`

### Mandrill

Transactional · likely sends

- DKIM key: mandrill (1024 bit, named for it)
  - `mandrill._domainkey.medium.com TXT v=DKIM1; k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp 9cee89b6f986543a`
- Setup: complete: DKIM present (older setup: a key at mandrill; the current setup names mte1 and mte2), bounce CNAME not used (optional, CNAME at 25 labels under medium.com), tracking CNAME not used (optional, CNAME at 25 labels under medium.com)

## Not matched to a service

These records point somewhere Sendermap does not recognise: a service it does not know yet, or your own servers.

- CNAME at link: `custom.bnc.lt`, from `link.medium.com CNAME custom.bnc.lt`
- DKIM key: `mx`, from `mx._domainkey.medium.com TXT k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp ed9c30e7c3b40a07`

## Looked for and not found

Records Sendermap looked for and did not find.

- DKIM keys at help.medium.com: no selectors exist: _domainkey.help.medium.com does not exist, so the 30-name sweep was skipped; the 11 names its MX, SPF and delegations point to were asked as a check, and none exists (RFC 8020 section 5)
  - `_domainkey.help.medium.com TXT no such name`
  - `sendermap-wildcard-check._domainkey.help.medium.com TXT no such name`
- DKIM keys at mail.medium.com: selectors exist but none of the 34 names asked is one
  - `_domainkey.mail.medium.com TXT no record of this type`
- DKIM keys at read.medium.com: no selectors exist: _domainkey.read.medium.com does not exist, so the 27-name sweep was skipped; the 8 names its MX, SPF and delegations point to were asked as a check, and none exists (RFC 8020 section 5)
  - `_domainkey.read.medium.com TXT no such name`
  - `sendermap-wildcard-check._domainkey.read.medium.com TXT no such name`

## How this was checked

Checked 2026-11-14 06:40 UTC: 677 DNS lookups in 0.0 s over Google DNS over HTTPS.

- At medium.com: 126 possible DKIM key names, 25 service record names, 1 web page.
- At email.medium.com: 27 possible DKIM key names.
- At help.medium.com: 11 possible DKIM key names.
- At mail.medium.com: 34 possible DKIM key names.
- At read.medium.com: 8 possible DKIM key names.

Not checked:

- DKIM selectors at email.medium.com: 95 of 122 not asked. The first 27 were asked, plus any the name's own SPF, MX or delegation points to (cap 27).
- DKIM selectors at mail.medium.com: 92 of 126 not asked. The first 27 were asked, plus any the name's own SPF, MX or delegation points to (cap 27).

Not run:

- the website. Web checks were turned off (--no-web).
- certificate transparency, crt.sh. Read only with --ct (it also holds expired certificates).

Names asked:

- medium.com, Pages: `https://api.certspotter.com/v1/issuances?domain=medium.com&include_subdomains=true&expand=dns_names`
- medium.com, CNAME labels: `bounce`, `bounces`, `em`, `email`, `mail`, `send`, `mta`, `rp`, `pm-bounces`, `links`, `link`, `click`, `track`, `tracking`, `url`, `go`, `autodiscover`, `cf-bounce`, `eversrv`, `fwdkim1`, `bnc3`, `bounces.cloud.em`, `bounces.cloud2.em`, `outbound.intercom`, `atlassian-bounces`
- medium.com, DKIM selectors: `google`, `gapps`, `googlemail`, `s1`, `s2`, `smtpapi`, `sendgrid`, `acdkim1`, `acdkim2`, `ses`, `ses1`, `ses2`, `aweber_key_a`, `aweber_key_b`, `aweber_key_c`, `brevo`, `brevo1`, `brevo2`, `cm`, `cf2024-1`, `ctct1`, `ctct2`, `krs`, `cio`, `e2ma-k1`, `e2ma-k2`, `e2ma-k3`, `everlytickey1`, `everlytickey2`, `fm2`, `fm1`, `fm3`, `mesmtp`, `secureserver1`, `secureserver2`, `gor`, `strong1`, `strong2`, `hs1`, `hs2`, `intercom`, `s1-ionos`, `s42582890`, `s2-ionos`, `cka`, `kl`, `kl1`, `kl2`, `km1`, `km2`, `k2`, `k1`, `k3`, `mailchimp`, `litesrv`, `mg`, `mailgun`, `mg1`, `pdk1`, `pdk2`, `mailjet`, `mailpoet2`, `mailpoet1`, `mandrill`, `mte1`, `mte2`, `marketo`, `mkto`, `mkto1`, `selector1`, `selector2`, `mimecast`, `mimecast20190719`, `mc1`, `pepipost`, `pm1`, `pp1`, `proofpoint`, `protonmail`, `protonmail2`, `protonmail3`, `resend`, `sailthru`, `sailthru2`, `salesforce`, `salesforce2`, `salesforce1`, `sf`, `sf1`, `sf2`, `sfdc`, `200608`, `pardot`, `sfmc`, `scph0819`, `sparkpost`, `squarespace`, `mailru`, `mail`, `zendesk1`, `zendesk2`, `zendesk`, `zoho`, `zohomail`, `api`, `default`, `dk`, `dkim`, `dkim1`, `dkim2`, `email`, `k`, `key`, `key1`, `key2`, `mta`, `mx`, `pm`, `s`, `selector`, `smtp`, `sp`, `20161025`, `20210112`, `20221208`, `20230601`
- email.medium.com, DKIM selectors: `s1`, `s2`, `smtpapi`, `sendgrid`, `acdkim1`, `acdkim2`, `ses`, `ses1`, `ses2`, `aweber_key_a`, `aweber_key_b`, `aweber_key_c`, `brevo`, `brevo1`, `brevo2`, `cm`, `cf2024-1`, `ctct1`, `ctct2`, `krs`, `cio`, `e2ma-k1`, `e2ma-k2`, `e2ma-k3`, `everlytickey1`, `everlytickey2`, `fm2`
- help.medium.com, DKIM selectors: `acdkim1`, `acdkim2`, `ses`, `ses1`, `ses2`, `aweber_key_a`, `aweber_key_b`, `aweber_key_c`, `zendesk`, `zendesk1`, `zendesk2`
- mail.medium.com, DKIM selectors: `acdkim1`, `acdkim2`, `ses`, `ses1`, `ses2`, `aweber_key_a`, `aweber_key_b`, `aweber_key_c`, `brevo`, `brevo1`, `brevo2`, `cm`, `cf2024-1`, `ctct1`, `ctct2`, `krs`, `cio`, `e2ma-k1`, `e2ma-k2`, `e2ma-k3`, `everlytickey1`, `everlytickey2`, `fm2`, `fm1`, `fm3`, `mesmtp`, `secureserver1`, `20161025`, `20210112`, `20221208`, `20230601`, `gapps`, `google`, `googlemail`
- read.medium.com, DKIM selectors: `acdkim1`, `acdkim2`, `ses`, `ses1`, `ses2`, `aweber_key_a`, `aweber_key_b`, `aweber_key_c`
