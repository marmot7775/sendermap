# Who handles email for glossier.com?

**9 services handle email for glossier.com. 3 things need fixing.**

Google Workspace receives the domain's mail and has a DKIM key in place to sign it.

Six other services are set up to send as the domain: three support and CRM (Help Scout, Salesforce, Zendesk), one marketing (Klaviyo), two transactional (Postmark, SendGrid); one more is likely from a DKIM key name alone (Mandrill).

One service shows an account and nothing set up to send (Amazon SES); DMARC reports go to Valimail.

## Who handles your email

Each service below receives or sends email for glossier.com.

Receives your mail: your MX records deliver the domain's mail there.

Set up to send: its records for sending are in your DNS.

Likely sends: one clue points to it, such as a key named for it.

Account only: an account exists, with nothing set up to send.

- **Google Workspace** (Mailbox): receives your mail; setup incomplete
- **Help Scout** (Support and CRM): set up to send
- **Klaviyo** (Marketing): set up to send; setup complete
- **Postmark** (Transactional): set up to send; setup complete
- **Salesforce** (Support and CRM): set up to send
- **SendGrid** (Transactional): set up to send; setup complete
- **Zendesk** (Support and CRM): set up to send; setup complete
- **Mandrill** (Transactional): likely sends; from: DKIM key
- **Amazon SES** (Transactional): account only; from: Verification token

## What to fix

Problems found in the setup, most serious first.

1. **Two DKIM keys at glossier.com are 1024-bit: mandrill (Mandrill) and s2 (SendGrid)** (warning)

   Some receivers already treat 1024-bit RSA keys as weak. Rotate to 2048-bit.

2. **Google Workspace at receipts.glossier.com has no SPF** (warning)

   Its documented setup needs it and the map shows it missing: 209.85.220.41, one of Google Workspace's addresses, gets softfail at ~all.

3. **Google Workspace at receipts.glossier.com has no DKIM** (warning)

   Its documented setup needs it and the map shows it missing: no key at google._domainkey, a name with no TXT record; this zone gives that answer for every name that does not exist.

## Good to know

Nothing to change here. These explain what the map shows.

- **SPF at glossier.com and receipts.glossier.com is managed through Valimail**. A hosted or macro record can authorize services without naming them, so the services it covers do not show in the record itself.

## The proof, service by service

The DNS records behind each service above, for anyone who wants to check them.

MX: where the domain's mail is delivered.

SPF: the list of servers allowed to send as the domain.

DKIM: a signature key that proves mail really came from the domain.

Bounce CNAME: lets a service handle bounced mail under the domain's name.

Verification token: proves the domain owner set up an account with the service.

Tracking CNAME: links in a service's emails point here.

### Google Workspace

Mailbox · receives your mail

- MX: aspmx.l.google.com, alt1.aspmx.l.google.com and 3 more
- SPF passes its address: ip4:209.85.128.0/17
- MX for a subdomain's mail: aspmx.l.google.com, alt1.aspmx.l.google.com and 3 more at receipts.glossier.com
- DKIM key: google (2048 bit, named for it)
- Setup: incomplete: SPF missing at receipts.glossier.com, DKIM missing at receipts.glossier.com

### Help Scout

Support and CRM · set up to send

- SPF passes its address: ip4:52.0.20.102
- DKIM keys: strong1, strong2 (both 2048 bit, by CNAME)

### Klaviyo

Marketing · set up to send

- DKIM keys: kl, kl2 (both 2048 bit, by CNAME)
- Bounce CNAME: send.glossier.com
- Verification token: klaviyo-site-verification=Sn6eFZ
- Setup: complete

### Postmark

Transactional · set up to send

- Bounce CNAME: pm-bounces.glossier.com
- Setup: complete

### Salesforce

Support and CRM · set up to send

- DKIM keys: salesforce2, salesforce1 (both 2048 bit, by CNAME)

### SendGrid

Transactional · set up to send

- DKIM keys: s1 2048 bit, s2 1024 bit (by CNAME)
- Tracking CNAME: link.glossier.com
- MX for bounces: mx.sendgrid.net, mx2.sendgrid.net at marketing.glossier.com and send.glossier.com
- SPF: include:ab.sendgrid.net, include:sendgrid.net at marketing.glossier.com and send.glossier.com
- SPF ranges: ip4:208.117.48.0/20, ip4:50.31.32.0/19 and 9 more at marketing.glossier.com
- Setup: complete

### Zendesk

Support and CRM · set up to send

- SPF passes its address: ip4:103.151.192.0/23
- DKIM keys: zendesk1, zendesk2 (both 2048 bit, by CNAME)
- Setup: complete

### Mandrill

Transactional · likely sends

- DKIM key: mandrill (1024 bit, named for it)
- Setup: complete

### Amazon SES

Transactional · account only

- Verification token: amazonses:awBV5EM6W53p2/Xbg80uJ29zurZnGsMMJcLLLp6vUcY=

## Not matched to a service

These records point somewhere Sendermap does not recognise: a service it does not know yet, or your own servers.

- CNAME at go: `cname.short.io`, from `go.glossier.com CNAME cname.short.io`

## How this was checked

Checked 2026-10-12 01:25 UTC: 750 DNS lookups in 0.0 s over Google DNS over HTTPS.

- At glossier.com: 110 possible DKIM key names, 25 service record names, 1 web page.
- At marketing.glossier.com: 27 possible DKIM key names.
- At receipts.glossier.com: 27 possible DKIM key names.
- At send.glossier.com: 27 possible DKIM key names.

Not checked:

- DKIM selectors at marketing, receipts and send.glossier.com: 83 of 110 not asked at each. The first 27 were asked, plus any the name's own SPF, MX or delegation points to (cap 27).

Not run:

- the website. Web checks were turned off (--no-web).
- certificate transparency, crt.sh. Read only with --ct (it also holds expired certificates).
