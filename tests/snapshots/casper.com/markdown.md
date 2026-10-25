# Sendermap: casper.com

14 services send email as this domain · 4 things to fix  
Checked 2026-10-12 01:25 UTC · 740 lookups in 0.0 s over Google DNS over HTTPS

Google Workspace receives the domain's mail and has a DKIM key in place to sign it.

Eleven other services are set up to send as the domain: four marketing (Campaign Monitor, Iterable, Mailchimp, Salesforce Marketing Cloud Engagement), two commerce and apps (Docebo, Q4), four transactional (Mailgun, Mandrill, Postmark, SendGrid), one support and CRM (Salesforce); one more is likely from a DKIM key name alone (Customer.io).

One service shows an account and nothing set up to send (Microsoft 365); DMARC reports go to DMARCian.

## At a glance

- **Google Workspace** (Mailbox): receives mail; setup incomplete
- **Campaign Monitor** (Marketing): set up to send; setup complete
- **Docebo** (Commerce and apps): set up to send
- **Iterable** (Marketing): set up to send
- **Mailchimp** (Marketing): set up to send; setup complete
- **Mailgun** (Transactional): set up to send; setup complete
- **Mandrill** (Transactional): set up to send; setup complete
- **Postmark** (Transactional): set up to send; setup complete
- **Q4** (Commerce and apps): set up to send
- **Salesforce** (Support and CRM): set up to send
- **Salesforce Marketing Cloud Engagement** (Marketing, at mail.casper.com): set up to send
- **SendGrid** (Transactional): set up to send; setup complete
- **Customer.io** (Marketing, at e.casper.com): likely; from: DKIM key
- **Microsoft 365** (Mailbox): account only; from: Verification token

Reports go to DMARCian.

## Fix these

1. **Eight DKIM keys at casper.com are 1024-bit: google (Google Workspace), cm (Campaign Monitor), k1 (Mailchimp), mandrill (Mandrill), salesforce (Salesforce), s2 (SendGrid), smtpapi (SendGrid) and mx** (warning)

   Some receivers already treat 1024-bit RSA keys as weak. Rotate to 2048-bit.

2. **Google Workspace at e.casper.com and mail.casper.com has no SPF** (warning)

   Its documented setup needs it and the map shows it missing: the record does not authorize _spf.google.com.

3. **Google Workspace at e.casper.com and mail.casper.com has no DKIM** (warning)

   Its documented setup needs it and the map shows it missing: no key at google._domainkey, a name that does not exist.

4. **Google Workspace at orders.casper.com has no SPF** (warning)

   Its documented setup needs it and the map shows it missing: no SPF record.

## Notes

- **The mte1 key at casper.com and the mte1 key at email.casper.com are the same key**. They publish one public key, fp 402b5aebde0f1c9f, so one private key signs for all of them, and replacing the key at one selector leaves it live at the others.
- **The mte2 key at casper.com and the mte2 key at email.casper.com are the same key**. They publish one public key, fp bd970c8868f21f9b, so one private key signs for all of them, and replacing the key at one selector leaves it live at the others.
- **Microsoft 365 shows only an account at casper.com**. The records name an account (a verification token, an autodiscover CNAME, or a revoked or dangling key) and nothing that sends or receives mail. Is the account still used? If not, remove its records.

## Evidence, service by service

### Google Workspace

Mailbox · receives mail

- MX: aspmx.l.google.com, alt1.aspmx.l.google.com and 3 more
- SPF: include:_spf.google.com
- MX for a subdomain's mail: aspmx.l.google.com, alt1.aspmx.l.google.com and 5 more at e.casper.com, mail.casper.com and orders.casper.com
- DKIM keys: google (1024 and 2048 bit, named for it) at casper.com and orders.casper.com
- Setup: incomplete: SPF missing at e.casper.com, mail.casper.com and orders.casper.com, DKIM missing at e.casper.com and mail.casper.com

### Campaign Monitor

Marketing · set up to send

- SPF: include:_spf.createsend.com
- DKIM key: cm (1024 bit, named for it)
- Setup: complete

### Docebo

Commerce and apps · set up to send

- SPF: include:docebosaas.com

### Iterable

Marketing · set up to send

- Tracking CNAME: links.casper.com

### Mailchimp

Marketing · set up to send

- DKIM key: k1 (1024 bit, by CNAME)
- Setup: complete

### Mailgun

Transactional · set up to send

- MX for bounces: mxa.mailgun.org, mxb.mailgun.org at e.casper.com and t.casper.com
- SPF: include:mailgun.org at e.casper.com and t.casper.com
- Setup: complete

### Mandrill

Transactional · set up to send

- DKIM keys: mte1, mte2 (all 2048 bit, by CNAME) at casper.com and email.casper.com
- SPF: include:spf.mandrillapp.com at email.casper.com
- DKIM key: mandrill (1024 bit, named for it)
- Setup: complete

### Postmark

Transactional · set up to send

- Bounce CNAME: pm-bounces.casper.com
- Setup: complete

### Q4

Commerce and apps · set up to send

- SPF: include:_spf.q4press.com

### Salesforce

Support and CRM · set up to send

- SPF: include:_spf.salesforce.com
- DKIM key: salesforce (1024 bit, named for it)

### Salesforce Marketing Cloud Engagement

Marketing · set up to send · at mail.casper.com

- SPF: include:cust-spf.exacttarget.com
- Delegated by NS: mail.casper.com

### SendGrid

Transactional · set up to send

- DKIM keys: s1 2048 bit, s2 1024 bit (by CNAME)
- DKIM key: smtpapi (1024 bit, named for it)
- Setup: complete

### Customer.io

Marketing · likely · at e.casper.com

- DKIM key: krs (2048 bit, named for it)
- Setup: complete

### Microsoft 365

Mailbox · account only

- Verification token: MS=ms55520198
- Setup: incomplete: SPF missing (the record does not authorize spf.protection.outlook.com), DKIM missing (no key at selector1._domainkey or selector2._domainkey, names with no TXT record; this zone gives that answer for every name that does not exist)

## Not recognised

- DKIM key: `mx`, from `mx._domainkey.casper.com TXT v=DKIM1; k=rsa; p=MIGfMA0GCSqG..., 1024-bit, fp 273e0630e2eb6478`
- IP address in SPF: `208.89.14.209 (AS11054, LIVEPERSON - LivePerson, Inc., US)`, from `casper.com TXT ip4:208.89.14.209`
- mail server: `incoming.bm23.com` at email.casper.com, from `email.casper.com MX 20 incoming.bm23.com`

## Checked and not there

- DKIM keys at t.casper.com: selectors exist but none of the 32 names asked is one
  - `_domainkey.t.casper.com TXT no record of this type`

## How this was checked

Asked 740 lookups at 6 names:

- casper.com: 110 DKIM selectors, 25 CNAME labels, 1 page
- e.casper.com: 32 DKIM selectors
- email.casper.com: 30 DKIM selectors
- mail.casper.com: 28 DKIM selectors
- orders.casper.com: 27 DKIM selectors
- t.casper.com: 32 DKIM selectors

Not checked:

- DKIM selectors at e and t.casper.com: 78 of 110 not asked at each. The first 27 were asked, plus any the name's own SPF, MX or delegation points to (cap 27).
- DKIM selectors at email.casper.com: 80 of 110 not asked. The first 27 were asked, plus any the name's own SPF, MX or delegation points to (cap 27).
- DKIM selectors at mail.casper.com: 82 of 110 not asked. The first 27 were asked, plus any the name's own SPF, MX or delegation points to (cap 27).
- DKIM selectors at orders.casper.com: 83 of 110 not asked. The first 27 were asked, plus any the name's own SPF, MX or delegation points to (cap 27).

Not run:

- the website: web checks were turned off (--no-web)
- certificate transparency, crt.sh: read only with --ct (it also holds expired certificates)
