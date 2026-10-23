# Sendermap: casper.com

14 sending services found from public records checked 2026-10-12 01:25 UTC (699 lookups in 0.0 s over Google DNS over HTTPS).

Google Workspace receives the domain's mail and has a DKIM key in place to sign it. Eleven other services are set up to send as the domain: four marketing (Campaign Monitor, Iterable, Mailchimp, Salesforce Marketing Cloud Engagement), two commerce and apps (Docebo, Q4), four transactional (Mailgun, Mandrill, Postmark, SendGrid), one support and CRM (Salesforce); one more is likely from a DKIM key name alone (Customer.io). One service shows an account and nothing set up to send (Microsoft 365); DMARC reports go to DMARCian. Not checked: the website (turned off), DKIM selectors past the first 27 on five subdomains, and the crt.sh certificate log (read only with --ct).

## Needs attention

- **Eight DKIM keys at casper.com are 1024-bit: google, cm, k1, mandrill, salesforce, s2, smtpapi and mx** (warning). Some receivers already treat 1024-bit RSA keys as weak. Rotate to 2048-bit.
  - `google._domainkey.casper.com TXT v=DKIM1; k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp e6d74f2ed99fdbb5`
  - `cm._domainkey.casper.com TXT k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp 9347c624a5a8cd6f`
  - `k1._domainkey.casper.com TXT k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp 53d7bb0466c8346d via dkim.mcsv.net`
  - `mandrill._domainkey.casper.com TXT v=DKIM1; k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp 9cee89b6f986543a`
  - `salesforce._domainkey.casper.com TXT v=DKIM1; k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp 2b895d381a879705`
  - `s2._domainkey.casper.com TXT k=rsa; t=s (strict); p=MIGfMA0GCSqG..., 1024-bit, fp ea13ef38e66c6769 via s2.domainkey.u895984.wl235.sendgrid.net`
  - `smtpapi._domainkey.casper.com TXT k=rsa; t=s (strict); p=MIGfMA0GCSqG..., 1024-bit, fp 303963420cfee1c6`
  - `mx._domainkey.casper.com TXT v=DKIM1; k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp 273e0630e2eb6478`
- **Google Workspace at e.casper.com has no SPF** (warning). Its documented setup needs it and the map shows it missing: the record does not authorize _spf.google.com.
  - `e.casper.com TXT v=spf1 include:mailgun.org ~all`
- **Google Workspace at e.casper.com has no DKIM** (warning). Its documented setup needs it and the map shows it missing: no key at google._domainkey, a name that does not exist.
  - `google._domainkey.e.casper.com TXT no such name`
- **Google Workspace at mail.casper.com has no SPF** (warning). Its documented setup needs it and the map shows it missing: the record does not authorize _spf.google.com.
  - `mail.casper.com TXT v=spf1 include:cust-spf.exacttarget.com -all`
- **Google Workspace at mail.casper.com has no DKIM** (warning). Its documented setup needs it and the map shows it missing: no key at google._domainkey, a name that does not exist.
  - `google._domainkey.mail.casper.com TXT no such name`
- **Google Workspace at orders.casper.com has no SPF** (warning). Its documented setup needs it and the map shows it missing: no SPF record.
  - `orders.casper.com TXT no record of this type`
- **The mte1 key at casper.com and the mte1 key at email.casper.com are the same key** (note). They publish one public key, fp 402b5aebde0f1c9f, so one private key signs for all of them, and replacing the key at one selector leaves it live at the others.
  - `mte1._domainkey.casper.com TXT v=DKIM1; k=rsa; p=MIIBIjANBgkq..., 2048-bit, fp 402b5aebde0f1c9f via dkim1.mandrillapp.com`
  - `mte1._domainkey.email.casper.com TXT v=DKIM1; k=rsa; p=MIIBIjANBgkq..., 2048-bit, fp 402b5aebde0f1c9f via dkim1.mandrillapp.com`
- **The mte2 key at casper.com and the mte2 key at email.casper.com are the same key** (note). They publish one public key, fp bd970c8868f21f9b, so one private key signs for all of them, and replacing the key at one selector leaves it live at the others.
  - `mte2._domainkey.casper.com TXT v=DKIM1; k=rsa; p=MIIBIjANBgkq..., 2048-bit, fp bd970c8868f21f9b via dkim2.mandrillapp.com`
  - `mte2._domainkey.email.casper.com TXT v=DKIM1; k=rsa; p=MIIBIjANBgkq..., 2048-bit, fp bd970c8868f21f9b via dkim2.mandrillapp.com`
- **Microsoft 365 shows only an account at casper.com** (note). The records name an account (a verification token, an autodiscover CNAME, or a revoked or dangling key) and nothing that sends or receives mail. Is the account still used? If not, remove its records.
  - `casper.com TXT MS=ms55520198`

## Senders

| Service | Category | How sure | Evidence | Setup |
|---|---|---|---|---|
| Google Workspace | Mailbox | In use | MX: aspmx.l.google.com, alt1.aspmx.l.google.com and 3 more; SPF: include:_spf.google.com; MX for a subdomain's mail: aspmx.l.google.com, alt1.aspmx.l.google.com and 5 more at e.casper.com, mail.casper.com and orders.casper.com; DKIM keys: google (1024 and 2048 bit, named for it) at casper.com and orders.casper.com | setup incomplete: SPF present at casper.com, DKIM present at casper.com and orders.casper.com, MX present at casper.com, e.casper.com, mail.casper.com and orders.casper.com, bounce CNAME not needed at casper.com, e.casper.com, mail.casper.com and orders.casper.com, SPF missing at e.casper.com, mail.casper.com and orders.casper.com, DKIM missing at e.casper.com and mail.casper.com |
| Campaign Monitor | Marketing | Configured | SPF: include:_spf.createsend.com; DKIM key: cm (1024 bit, named for it) | setup complete: DKIM present |
| Docebo | Commerce and apps | Configured | SPF: include:docebosaas.com |  |
| Iterable | Marketing | Configured | Tracking CNAME: links.casper.com |  |
| Mailchimp | Marketing | Configured | DKIM key: k1 (1024 bit, by CNAME) | setup complete: DKIM present (older setup: a key at k1; the current setup names k2), SPF not needed, bounce CNAME not needed |
| Mailgun | Transactional | Configured | MX for bounces: mxa.mailgun.org, mxb.mailgun.org at e.casper.com and t.casper.com; SPF: include:mailgun.org at e.casper.com and t.casper.com | setup complete: SPF present at e.casper.com and t.casper.com, MX present at e.casper.com and t.casper.com, tracking CNAME not checked (no label was asked at e.casper.com) at e.casper.com, tracking CNAME not checked (no label was asked at t.casper.com) at t.casper.com |
| Mandrill | Transactional | Configured | DKIM keys: mte1, mte2 (all 2048 bit, by CNAME) at casper.com and email.casper.com; SPF: include:spf.mandrillapp.com at email.casper.com; DKIM key: mandrill (1024 bit, named for it) | setup complete: DKIM present at casper.com and email.casper.com, bounce CNAME not used (optional, CNAME at 23 labels under casper.com) at casper.com, tracking CNAME not used (optional, CNAME at 23 labels under casper.com) at casper.com, bounce CNAME not checked (no label was asked at email.casper.com) at email.casper.com, tracking CNAME not checked (no label was asked at email.casper.com) at email.casper.com |
| Postmark | Transactional | Configured | Bounce CNAME: pm-bounces.casper.com | setup complete: SPF not needed, bounce CNAME present |
| Q4 | Commerce and apps | Configured | SPF: include:_spf.q4press.com |  |
| Salesforce | Support and CRM | Configured | SPF: include:_spf.salesforce.com; DKIM key: salesforce (1024 bit, named for it) |  |
| Salesforce Marketing Cloud Engagement (mail.casper.com) | Marketing | Configured | SPF: include:cust-spf.exacttarget.com; Delegated by NS: mail.casper.com |  |
| SendGrid | Transactional | Configured | DKIM keys: s1, s2 (1024 and 2048 bit, by CNAME); DKIM key: smtpapi (1024 bit, named for it) | setup complete: DKIM present, bounce CNAME not used (optional, CNAME at 23 labels under casper.com), SPF not needed, tracking CNAME not used (optional, CNAME at 23 labels under casper.com) |
| Customer.io (e.casper.com) | Marketing | Likely | DKIM key: krs (2048 bit, named for it) | setup complete: tracking CNAME not checked (no label was asked at e.casper.com) |
| Microsoft 365 | Mailbox | Account only | Verification token: MS=ms55520198 | setup incomplete: SPF missing (the record does not authorize spf.protection.outlook.com), DKIM missing (no key at selector1._domainkey or selector2._domainkey, names with no TXT record; this zone gives that answer for every name that does not exist), MX not used (optional, MX at casper.com), bounce CNAME not needed |

## Records

- **Google Workspace**
  - MX
    - `casper.com MX 1 aspmx.l.google.com`
    - `casper.com MX 5 alt1.aspmx.l.google.com`
    - `casper.com MX 5 alt2.aspmx.l.google.com`
    - `casper.com MX 10 aspmx2.googlemail.com`
    - `casper.com MX 10 aspmx3.googlemail.com`
  - SPF
    - `casper.com TXT include:_spf.google.com`
  - MX for a subdomain's mail
    - `e.casper.com MX 1 aspmx.l.google.com`
    - `e.casper.com MX 5 alt1.aspmx.l.google.com`
    - `e.casper.com MX 5 alt2.aspmx.l.google.com`
    - `e.casper.com MX 10 alt3.aspmx.l.google.com`
    - `e.casper.com MX 10 alt4.aspmx.l.google.com`
    - `mail.casper.com MX 1 aspmx.l.google.com`
    - `mail.casper.com MX 5 alt1.aspmx.l.google.com`
    - `mail.casper.com MX 5 alt2.aspmx.l.google.com`
    - `mail.casper.com MX 10 alt3.aspmx.l.google.com`
    - `mail.casper.com MX 10 alt4.aspmx.l.google.com`
    - `orders.casper.com MX 25 aspmx.l.google.com`
    - `orders.casper.com MX 30 alt1.aspmx.l.google.com`
    - `orders.casper.com MX 30 alt2.aspmx.l.google.com`
    - `orders.casper.com MX 35 aspmx2.googlemail.com`
    - `orders.casper.com MX 35 aspmx3.googlemail.com`
  - DKIM keys
    - `google._domainkey.casper.com TXT v=DKIM1; k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp e6d74f2ed99fdbb5 via casper.com TXT include:_spf.google.com`
    - `google._domainkey.orders.casper.com TXT v=DKIM1; k=rsa; p=MIIBIjANBgkq..., 2048-bit, fp 66efacf170b65970 via orders.casper.com MX 25 aspmx.l.google.com`
- **Campaign Monitor**
  - SPF
    - `casper.com TXT include:_spf.createsend.com`
  - DKIM key
    - `cm._domainkey.casper.com TXT k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp 9347c624a5a8cd6f via casper.com TXT include:_spf.createsend.com`
- **Docebo**
  - SPF
    - `casper.com TXT include:docebosaas.com`
- **Iterable**
  - Tracking CNAME
    - `links.casper.com CNAME links.iterable.com`
- **Mailchimp**
  - DKIM key
    - `k1._domainkey.casper.com TXT k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp 53d7bb0466c8346d via dkim.mcsv.net`
- **Mailgun**
  - MX for bounces
    - `e.casper.com MX 10 mxa.mailgun.org`
    - `e.casper.com MX 10 mxb.mailgun.org`
    - `t.casper.com MX 10 mxa.mailgun.org`
    - `t.casper.com MX 10 mxb.mailgun.org`
  - SPF
    - `e.casper.com TXT include:mailgun.org`
    - `t.casper.com TXT include:mailgun.org`
- **Mandrill**
  - DKIM keys
    - `mte1._domainkey.casper.com TXT v=DKIM1; k=rsa; p=MIIBIjANBgkq..., 2048-bit, fp 402b5aebde0f1c9f via dkim1.mandrillapp.com`
    - `mte2._domainkey.casper.com TXT v=DKIM1; k=rsa; p=MIIBIjANBgkq..., 2048-bit, fp bd970c8868f21f9b via dkim2.mandrillapp.com`
    - `mte1._domainkey.email.casper.com TXT v=DKIM1; k=rsa; p=MIIBIjANBgkq..., 2048-bit, fp 402b5aebde0f1c9f via dkim1.mandrillapp.com`
    - `mte2._domainkey.email.casper.com TXT v=DKIM1; k=rsa; p=MIIBIjANBgkq..., 2048-bit, fp bd970c8868f21f9b via dkim2.mandrillapp.com`
  - SPF
    - `email.casper.com TXT include:spf.mandrillapp.com`
  - DKIM key
    - `mandrill._domainkey.casper.com TXT v=DKIM1; k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp 9cee89b6f986543a`
- **Postmark**
  - Bounce CNAME
    - `pm-bounces.casper.com CNAME pm.mtasv.net`
- **Q4**
  - SPF
    - `casper.com TXT include:_spf.q4press.com`
- **Salesforce**
  - SPF
    - `casper.com TXT include:_spf.salesforce.com`
  - DKIM key
    - `salesforce._domainkey.casper.com TXT v=DKIM1; k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp 2b895d381a879705 via casper.com TXT include:_spf.salesforce.com`
- **Salesforce Marketing Cloud Engagement**
  - SPF
    - `mail.casper.com TXT include:cust-spf.exacttarget.com`
  - Delegated by NS
    - `mail.casper.com NS ns1.exacttarget.com`
- **SendGrid**
  - DKIM keys
    - `s1._domainkey.casper.com TXT k=rsa; t=s (strict); p=MIIBIjANBgkq..., 2048-bit, fp fdc0f9d77c779856 via s1.domainkey.u895984.wl235.sendgrid.net`
    - `s2._domainkey.casper.com TXT k=rsa; t=s (strict); p=MIGfMA0GCSqG..., 1024-bit, fp ea13ef38e66c6769 via s2.domainkey.u895984.wl235.sendgrid.net`
  - DKIM key
    - `smtpapi._domainkey.casper.com TXT k=rsa; t=s (strict); p=MIGfMA0GCSqG..., 1024-bit, fp 303963420cfee1c6`
- **Customer.io**
  - DKIM key
    - `krs._domainkey.e.casper.com TXT k=rsa; p=MIIBIjANBgkq..., 2048-bit, fp 1eb1e97f362ad520`
- **Microsoft 365**
  - Verification token
    - `casper.com TXT MS=ms55520198`

## Reports go to

DMARCian

## Not recognised

- DKIM key: `mx`, from `mx._domainkey.casper.com TXT v=DKIM1; k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp 273e0630e2eb6478`
- IP address in SPF: `208.89.14.209 (AS11054, LIVEPERSON - LivePerson, Inc., US)`, from `casper.com TXT ip4:208.89.14.209`
- mail server: `incoming.bm23.com` at email.casper.com, from `email.casper.com MX 20 incoming.bm23.com`

## Checked and not there

- DKIM keys at t.casper.com: selectors exist but none of the 32 names asked is one
  - `_domainkey.t.casper.com TXT no record of this type`

## Not checked

- DKIM selectors at e.casper.com: 74 of 106 not asked: only the first 27 and the names its own SPF, MX or delegation backs were (cap)
- DKIM selectors at email.casper.com: 76 of 106 not asked: only the first 27 and the names its own SPF, MX or delegation backs were (cap)
- DKIM selectors at mail.casper.com: 78 of 106 not asked: only the first 27 and the names its own SPF, MX or delegation backs were (cap)
- DKIM selectors at orders.casper.com: 79 of 106 not asked: only the first 27 and the names its own SPF, MX or delegation backs were (cap)
- DKIM selectors at t.casper.com: 74 of 106 not asked: only the first 27 and the names its own SPF, MX or delegation backs were (cap)

## What was asked

- **casper.com**: 106 DKIM selectors, 23 CNAME labels, 1 page
- **e.casper.com**: 32 DKIM selectors
- **email.casper.com**: 30 DKIM selectors
- **mail.casper.com**: 28 DKIM selectors
- **orders.casper.com**: 27 DKIM selectors
- **t.casper.com**: 32 DKIM selectors

## Not run

- the website: web checks were turned off (--no-web)
- certificate transparency, crt.sh: read only with --ct (it also holds expired certificates)

## Appendix: names asked

- **casper.com**
  - Pages: `https://api.certspotter.com/v1/issuances?domain=casper.com&include_subdomains=true&expand=dns_names`
  - CNAME labels: `bounce`, `bounces`, `em`, `email`, `mail`, `send`, `mta`, `rp`, `pm-bounces`, `links`, `link`, `click`, `track`, `tracking`, `url`, `go`, `autodiscover`, `cf-bounce`, `eversrv`, `fwdkim1`, `bnc3`, `bounces.cloud.em`, `bounces.cloud2.em`
  - DKIM selectors: `google`, `gapps`, `acdkim1`, `acdkim2`, `ses`, `aweber_key_a`, `aweber_key_b`, `aweber_key_c`, `brevo`, `brevo1`, `brevo2`, `cm`, `cf2024-1`, `ctct1`, `ctct2`, `krs`, `e2ma-k1`, `e2ma-k2`, `e2ma-k3`, `everlytickey1`, `everlytickey2`, `fm2`, `fm1`, `fm3`, `mesmtp`, `secureserver1`, `secureserver2`, `gor`, `strong1`, `strong2`, `hs1`, `hs2`, `intercom`, `s1-ionos`, `s42582890`, `cka`, `kl`, `kl1`, `kl2`, `k2`, `k1`, `k3`, `litesrv`, `mg`, `mailgun`, `mg1`, `pdk1`, `pdk2`, `mailjet`, `mailpoet2`, `mailpoet1`, `mandrill`, `mte1`, `mte2`, `marketo`, `mkto`, `mkto1`, `selector1`, `selector2`, `mimecast`, `mimecast20190719`, `pepipost`, `pp1`, `protonmail`, `protonmail2`, `protonmail3`, `resend`, `sailthru`, `salesforce`, `salesforce2`, `salesforce1`, `sf`, `sf1`, `sf2`, `sfdc`, `200608`, `pardot`, `sfmc`, `s1`, `s2`, `smtpapi`, `scph0819`, `sparkpost`, `squarespace`, `zendesk1`, `zendesk2`, `zoho`, `api`, `default`, `dk`, `dkim`, `dkim1`, `dkim2`, `email`, `k`, `key`, `key1`, `key2`, `mail`, `mta`, `mx`, `pm`, `s`, `selector`, `smtp`, `sp`
- **e.casper.com**
  - DKIM selectors: `acdkim1`, `acdkim2`, `ses`, `aweber_key_a`, `aweber_key_b`, `aweber_key_c`, `brevo`, `brevo1`, `brevo2`, `cm`, `cf2024-1`, `ctct1`, `ctct2`, `krs`, `e2ma-k1`, `e2ma-k2`, `e2ma-k3`, `everlytickey1`, `everlytickey2`, `fm2`, `fm1`, `fm3`, `mesmtp`, `secureserver1`, `secureserver2`, `google`, `gapps`, `mailgun`, `mg`, `mg1`, `pdk1`, `pdk2`
- **email.casper.com**
  - DKIM selectors: `acdkim1`, `acdkim2`, `ses`, `aweber_key_a`, `aweber_key_b`, `aweber_key_c`, `brevo`, `brevo1`, `brevo2`, `cm`, `cf2024-1`, `ctct1`, `ctct2`, `krs`, `e2ma-k1`, `e2ma-k2`, `e2ma-k3`, `everlytickey1`, `everlytickey2`, `fm2`, `fm1`, `fm3`, `mesmtp`, `secureserver1`, `secureserver2`, `google`, `gapps`, `mandrill`, `mte1`, `mte2`
- **mail.casper.com**
  - DKIM selectors: `acdkim1`, `acdkim2`, `ses`, `aweber_key_a`, `aweber_key_b`, `aweber_key_c`, `brevo`, `brevo1`, `brevo2`, `cm`, `cf2024-1`, `ctct1`, `ctct2`, `krs`, `e2ma-k1`, `e2ma-k2`, `e2ma-k3`, `everlytickey1`, `everlytickey2`, `fm2`, `fm1`, `fm3`, `mesmtp`, `secureserver1`, `secureserver2`, `google`, `gapps`, `sfmc`
- **orders.casper.com**
  - DKIM selectors: `acdkim1`, `acdkim2`, `ses`, `aweber_key_a`, `aweber_key_b`, `aweber_key_c`, `brevo`, `brevo1`, `brevo2`, `cm`, `cf2024-1`, `ctct1`, `ctct2`, `krs`, `e2ma-k1`, `e2ma-k2`, `e2ma-k3`, `everlytickey1`, `everlytickey2`, `fm2`, `fm1`, `fm3`, `mesmtp`, `secureserver1`, `secureserver2`, `google`, `gapps`
- **t.casper.com**
  - DKIM selectors: `acdkim1`, `acdkim2`, `ses`, `aweber_key_a`, `aweber_key_b`, `aweber_key_c`, `brevo`, `brevo1`, `brevo2`, `cm`, `cf2024-1`, `ctct1`, `ctct2`, `krs`, `e2ma-k1`, `e2ma-k2`, `e2ma-k3`, `everlytickey1`, `everlytickey2`, `fm2`, `fm1`, `fm3`, `mesmtp`, `secureserver1`, `secureserver2`, `google`, `gapps`, `mailgun`, `mg`, `mg1`, `pdk1`, `pdk2`
