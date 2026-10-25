# Sendermap: glossier.com

9 sending services found from public records checked 2026-10-12 01:25 UTC (739 lookups in 0.0 s over Google DNS over HTTPS).

Google Workspace receives the domain's mail and has a DKIM key in place to sign it. Six other services are set up to send as the domain: three support and CRM (Help Scout, Salesforce, Zendesk), one marketing (Klaviyo), two transactional (Postmark, SendGrid); one more is likely from a DKIM key name alone (Mandrill). One service shows an account and nothing set up to send (Amazon SES); DMARC reports go to Valimail. Not checked: the website (turned off), DKIM selectors past the first 27 on three subdomains, and the crt.sh certificate log (read only with --ct).

## Needs attention

- **Two DKIM keys at glossier.com are 1024-bit: mandrill (Mandrill) and s2 (SendGrid)** (warning). Some receivers already treat 1024-bit RSA keys as weak. Rotate to 2048-bit.
- **Google Workspace at receipts.glossier.com has no SPF** (warning). Its documented setup needs it and the map shows it missing: 209.85.220.41, one of Google Workspace's addresses, gets softfail at ~all.
- **Google Workspace at receipts.glossier.com has no DKIM** (warning). Its documented setup needs it and the map shows it missing: no key at google._domainkey, a name with no TXT record; this zone gives that answer for every name that does not exist.
- **SPF at glossier.com and receipts.glossier.com is managed through Valimail** (note). A hosted or macro record can authorize services without naming them, so the services it covers do not show in the record itself.

## Senders

| Service | Category | How sure | Evidence | Setup |
|---|---|---|---|---|
| Google Workspace | Mailbox | In use | MX: aspmx.l.google.com, alt1.aspmx.l.google.com and 3 more; SPF passes its address: ip4:209.85.128.0/17; MX for a subdomain's mail: aspmx.l.google.com, alt1.aspmx.l.google.com and 3 more at receipts.glossier.com; DKIM key: google (2048 bit, named for it) | setup incomplete: SPF missing at receipts.glossier.com, DKIM missing at receipts.glossier.com |
| Help Scout | Support and CRM | Configured | SPF passes its address: ip4:52.0.20.102; DKIM keys: strong1, strong2 (both 2048 bit, by CNAME) |  |
| Klaviyo | Marketing | Configured | DKIM keys: kl, kl2 (both 2048 bit, by CNAME); Bounce CNAME: send.glossier.com; Verification token: klaviyo-site-verification=Sn6eFZ | setup complete |
| Postmark | Transactional | Configured | Bounce CNAME: pm-bounces.glossier.com | setup complete |
| Salesforce | Support and CRM | Configured | DKIM keys: salesforce2, salesforce1 (both 2048 bit, by CNAME) |  |
| SendGrid | Transactional | Configured | DKIM keys: s1 2048 bit, s2 1024 bit (by CNAME); Tracking CNAME: link.glossier.com; MX for bounces: mx.sendgrid.net, mx2.sendgrid.net at marketing.glossier.com and send.glossier.com; SPF: include:ab.sendgrid.net, include:sendgrid.net at marketing.glossier.com and send.glossier.com; SPF ranges: ip4:208.117.48.0/20, ip4:50.31.32.0/19 and 9 more at marketing.glossier.com | setup complete |
| Zendesk | Support and CRM | Configured | SPF passes its address: ip4:103.151.192.0/23; DKIM keys: zendesk1, zendesk2 (both 2048 bit, by CNAME) | setup complete |
| Mandrill | Transactional | Likely | DKIM key: mandrill (1024 bit, named for it) | setup complete |
| Amazon SES | Transactional | Account only | Verification token: amazonses:awBV5EM6W53p2/Xbg80uJ29zurZnGsMMJcLLLp6vUcY= |  |

## Reports go to

Valimail

## Not recognised

- CNAME at mail: `ghs.googlehosted.com`, from `mail.glossier.com CNAME ghs.googlehosted.com`
- CNAME at go: `cname.short.io`, from `go.glossier.com CNAME cname.short.io`

## Not checked

- DKIM selectors at marketing, receipts and send.glossier.com: 82 of 109 not asked at each. The first 27 were asked, plus any the name's own SPF, MX or delegation points to (cap 27).

## What was asked

739 lookups at 4 names

- **glossier.com**: 109 DKIM selectors, 25 CNAME labels, 1 page
- **marketing.glossier.com**: 27 DKIM selectors
- **receipts.glossier.com**: 27 DKIM selectors
- **send.glossier.com**: 27 DKIM selectors

## Not run

- the website: web checks were turned off (--no-web)
- certificate transparency, crt.sh: read only with --ct (it also holds expired certificates)
