# Sendermap: casper.com

14 sending services found from public records checked 2026-10-12 01:25 UTC (728 lookups in 0.0 s over Google DNS over HTTPS).

Google Workspace receives the domain's mail and has a DKIM key in place to sign it. Eleven other services are set up to send as the domain: four marketing (Campaign Monitor, Iterable, Mailchimp, Salesforce Marketing Cloud Engagement), two commerce and apps (Docebo, Q4), four transactional (Mailgun, Mandrill, Postmark, SendGrid), one support and CRM (Salesforce); one more is likely from a DKIM key name alone (Customer.io). One service shows an account and nothing set up to send (Microsoft 365); DMARC reports go to DMARCian. Not checked: the website (turned off), DKIM selectors past the first 27 on five subdomains, and the crt.sh certificate log (read only with --ct).

## Needs attention

- **Eight DKIM keys at casper.com are 1024-bit: google, cm, k1, mandrill, salesforce, s2, smtpapi and mx** (warning). Some receivers already treat 1024-bit RSA keys as weak. Rotate to 2048-bit.
- **Google Workspace at e.casper.com has no SPF** (warning). Its documented setup needs it and the map shows it missing: the record does not authorize _spf.google.com.
- **Google Workspace at e.casper.com has no DKIM** (warning). Its documented setup needs it and the map shows it missing: no key at google._domainkey, a name that does not exist.
- **Google Workspace at mail.casper.com has no SPF** (warning). Its documented setup needs it and the map shows it missing: the record does not authorize _spf.google.com.
- **Google Workspace at mail.casper.com has no DKIM** (warning). Its documented setup needs it and the map shows it missing: no key at google._domainkey, a name that does not exist.
- **Google Workspace at orders.casper.com has no SPF** (warning). Its documented setup needs it and the map shows it missing: no SPF record.
- **The mte1 key at casper.com and the mte1 key at email.casper.com are the same key** (note). They publish one public key, fp 402b5aebde0f1c9f, so one private key signs for all of them, and replacing the key at one selector leaves it live at the others.
- **The mte2 key at casper.com and the mte2 key at email.casper.com are the same key** (note). They publish one public key, fp bd970c8868f21f9b, so one private key signs for all of them, and replacing the key at one selector leaves it live at the others.
- **Microsoft 365 shows only an account at casper.com** (note). The records name an account (a verification token, an autodiscover CNAME, or a revoked or dangling key) and nothing that sends or receives mail. Is the account still used? If not, remove its records.

## Senders

| Service | Category | How sure | Evidence | Setup |
|---|---|---|---|---|
| Google Workspace | Mailbox | In use | MX: aspmx.l.google.com, alt1.aspmx.l.google.com and 3 more; SPF: include:_spf.google.com; MX for a subdomain's mail: aspmx.l.google.com, alt1.aspmx.l.google.com and 5 more at e.casper.com, mail.casper.com and orders.casper.com; DKIM keys: google (1024 and 2048 bit, named for it) at casper.com and orders.casper.com | setup incomplete: SPF missing at e.casper.com, mail.casper.com and orders.casper.com, DKIM missing at e.casper.com and mail.casper.com |
| Campaign Monitor | Marketing | Configured | SPF: include:_spf.createsend.com; DKIM key: cm (1024 bit, named for it) | setup complete |
| Docebo | Commerce and apps | Configured | SPF: include:docebosaas.com |  |
| Iterable | Marketing | Configured | Tracking CNAME: links.casper.com |  |
| Mailchimp | Marketing | Configured | DKIM key: k1 (1024 bit, by CNAME) | setup complete |
| Mailgun | Transactional | Configured | MX for bounces: mxa.mailgun.org, mxb.mailgun.org at e.casper.com and t.casper.com; SPF: include:mailgun.org at e.casper.com and t.casper.com | setup complete |
| Mandrill | Transactional | Configured | DKIM keys: mte1, mte2 (all 2048 bit, by CNAME) at casper.com and email.casper.com; SPF: include:spf.mandrillapp.com at email.casper.com; DKIM key: mandrill (1024 bit, named for it) | setup complete |
| Postmark | Transactional | Configured | Bounce CNAME: pm-bounces.casper.com | setup complete |
| Q4 | Commerce and apps | Configured | SPF: include:_spf.q4press.com |  |
| Salesforce | Support and CRM | Configured | SPF: include:_spf.salesforce.com; DKIM key: salesforce (1024 bit, named for it) |  |
| Salesforce Marketing Cloud Engagement (mail.casper.com) | Marketing | Configured | SPF: include:cust-spf.exacttarget.com; Delegated by NS: mail.casper.com |  |
| SendGrid | Transactional | Configured | DKIM keys: s1, s2 (1024 and 2048 bit, by CNAME); DKIM key: smtpapi (1024 bit, named for it) | setup complete |
| Customer.io (e.casper.com) | Marketing | Likely | DKIM key: krs (2048 bit, named for it) | setup complete |
| Microsoft 365 | Mailbox | Account only | Verification token: MS=ms55520198 | setup incomplete: SPF missing (the record does not authorize spf.protection.outlook.com), DKIM missing (no key at selector1._domainkey or selector2._domainkey, names with no TXT record; this zone gives that answer for every name that does not exist) |

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

- DKIM selectors at e and t.casper.com: 77 of 109 not asked at each. The first 27 were asked, plus any the name's own SPF, MX or delegation points to (cap 27).
- DKIM selectors at email.casper.com: 79 of 109 not asked. The first 27 were asked, plus any the name's own SPF, MX or delegation points to (cap 27).
- DKIM selectors at mail.casper.com: 81 of 109 not asked. The first 27 were asked, plus any the name's own SPF, MX or delegation points to (cap 27).
- DKIM selectors at orders.casper.com: 82 of 109 not asked. The first 27 were asked, plus any the name's own SPF, MX or delegation points to (cap 27).

## What was asked

728 lookups at 6 names

- **casper.com**: 109 DKIM selectors, 25 CNAME labels, 1 page
- **e.casper.com**: 32 DKIM selectors
- **email.casper.com**: 30 DKIM selectors
- **mail.casper.com**: 28 DKIM selectors
- **orders.casper.com**: 27 DKIM selectors
- **t.casper.com**: 32 DKIM selectors

## Not run

- the website: web checks were turned off (--no-web)
- certificate transparency, crt.sh: read only with --ct (it also holds expired certificates)
