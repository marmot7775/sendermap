# Who handles email for cognifit.com?

**7 services handle email for cognifit.com. 2 things need fixing.**

The map shows one risk: SPF at cognifit.com includes ses.amazonaws.com, which publishes no SPF record.

Google Workspace receives the domain's mail and has a DKIM key in place to sign it.

Four other services are set up to send as the domain: two transactional (Amazon SES, SendGrid), one marketing (Mailchimp), one support and CRM (Salesforce); one more is likely from a DKIM key name alone (Resend).

One service shows an account and nothing set up to send (Microsoft 365).

## Who handles your email

Each service below receives or sends email for cognifit.com.

Receives your mail: your MX records deliver the domain's mail there.

Set up to send: its records for sending are in your DNS.

Likely sends: one clue points to it, such as a key named for it.

Account only: an account exists, with nothing set up to send.

- **Google Workspace** (Mailbox): receives your mail; setup complete
- **Amazon SES** (Transactional): set up to send
- **Mailchimp** (Marketing): set up to send; setup complete
- **Salesforce** (Support and CRM): set up to send
- **SendGrid** (Transactional): set up to send; setup complete
- **Resend** (Transactional): likely sends; from: DKIM key
- **Microsoft 365** (Mailbox): account only; from: Verification token

## What to fix

Problems found in the setup, most serious first.

1. **SPF at cognifit.com includes ses.amazonaws.com, which publishes no SPF record** (risk)

   cognifit.com names ses.amazonaws.com, which publishes no SPF record. A receiver that reaches it returns an error (RFC 7208, section 5.2), so SPF fails for every message no term before it matches.

2. **Four DKIM keys at cognifit.com are 1024-bit: google (Google Workspace), smtpapi (SendGrid), k1 (Mailchimp) and resend (Resend)** (warning)

   Some receivers already treat 1024-bit RSA keys as weak. Rotate to 2048-bit.

## Good to know

Nothing to change here. These explain what the map shows.

- **DNS says _domainkey.cognifit.com does not exist, but a key sits under it**. The domain's DNS servers answer no such name for _domainkey.cognifit.com, yet google._domainkey.cognifit.com has a key. Under RFC 8020 a no-such-name answer covers every name below it, so a resolver that applies the rule can fail to find the domain's DKIM keys. Most resolvers still look them up; the fault is in the DNS host and is theirs to fix. Every selector was asked.
- **Microsoft 365 shows only an account at cognifit.com**. The records name an account (a verification token, an autodiscover CNAME, or a revoked or dangling key) and nothing that sends or receives mail. Is the account still used? If not, remove its records.

## The proof, service by service

The DNS records behind each service above, for anyone who wants to check them.

MX: where the domain's mail is delivered.

SPF: the list of servers allowed to send as the domain.

DKIM: a signature key that proves mail really came from the domain.

Verification token: proves the domain owner set up an account with the service.

### Google Workspace

Mailbox · receives your mail

- MX: aspmx.l.google.com, alt1.aspmx.l.google.com and 5 more
- SPF: include:_spf.google.com
- DKIM key: google (1024 bit, named for it)
- Setup: complete

### Amazon SES

Transactional · set up to send

- SPF: include:amazonses.com at cognifit.com, messages.cognifit.com and send.cognifit.com
- MX for bounces: feedback-smtp.us-east-1.amazonses.com at messages.cognifit.com and send.cognifit.com

### Mailchimp

Marketing · set up to send

- DKIM key: k1 (1024 bit, by CNAME)
- Setup: complete

### Salesforce

Support and CRM · set up to send

- SPF: include:_spf.salesforce.com

### SendGrid

Transactional · set up to send

- SPF: include:sendgrid.net
- DKIM key: smtpapi (1024 bit, named for it)
- Setup: complete

### Resend

Transactional · likely sends

- DKIM key: resend (1024 bit, named for it)

### Microsoft 365

Mailbox · account only

- Verification token: MS=ms53236047
- Setup: incomplete: SPF missing (the record does not authorize spf.protection.outlook.com), DKIM missing (no key at selector1._domainkey or selector2._domainkey, names that do not exist)

## Not matched to a service

These records point somewhere Sendermap does not recognise: a service it does not know yet, or your own servers.

- SPF include: `ses.amazonaws.com`, from `cognifit.com TXT include:ses.amazonaws.com`

## Looked for and not found

Records Sendermap looked for and did not find.

- DKIM keys at messages.cognifit.com: no selectors exist: _domainkey.messages.cognifit.com does not exist, so the 27-name sweep was skipped; the 8 names its MX, SPF and delegations point to were asked as a check, and none exists (RFC 8020 section 5)
  - `_domainkey.messages.cognifit.com TXT no such name`
  - `sendermap-wildcard-check._domainkey.messages.cognifit.com TXT no such name`
- DKIM keys at send.cognifit.com: no selectors exist: _domainkey.send.cognifit.com does not exist, so the 27-name sweep was skipped; the 8 names its MX, SPF and delegations point to were asked as a check, and none exists (RFC 8020 section 5)
  - `_domainkey.send.cognifit.com TXT no such name`
  - `sendermap-wildcard-check._domainkey.send.cognifit.com TXT no such name`

## How this was checked

Checked 2026-10-28 12:11 UTC: 414 DNS lookups in 0.0 s over Google DNS over HTTPS.

- At cognifit.com: 114 possible DKIM key names, 25 service record names, 1 web page.
- At messages.cognifit.com: 8 possible DKIM key names.
- At send.cognifit.com: 8 possible DKIM key names.

Not run:

- the website. Web checks were turned off (--no-web).
- certificate transparency, crt.sh. Read only with --ct (it also holds expired certificates).
