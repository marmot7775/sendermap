# Who handles email for hicloudcam.com?

**3 services handle email for hicloudcam.com. Nothing needs fixing.**

Alibaba Cloud Direct Mail receives the domain's mail; Alibaba Mail receives the domain's mail.

One service shows an account and nothing set up to send (Amazon SES).

## Who handles your email

Each service below receives or sends email for hicloudcam.com.

Receives your mail: your MX records deliver the domain's mail there.

Account only: an account exists, with nothing set up to send.

- **Alibaba Cloud Direct Mail** (Transactional): receives your mail
- **Alibaba Mail** (Mailbox): receives your mail; setup complete
- **Amazon SES** (Transactional): account only; from: Verification token

## The proof, service by service

The DNS records behind each service above, for anyone who wants to check them.

MX: where the domain's mail is delivered.

SPF: the list of servers allowed to send as the domain.

Verification token: proves the domain owner set up an account with the service.

### Alibaba Cloud Direct Mail

Transactional · receives your mail

- MX: mx01.dm.aliyun.com
  - `hicloudcam.com MX 10 mx01.dm.aliyun.com`
- SPF: include:spfdm-ap-southeast-1.aliyun.com at hicloudcam.com and notify.hicloudcam.com
  - `hicloudcam.com TXT include:spfdm-ap-southeast-1.aliyun.com`
  - `notify.hicloudcam.com TXT include:spfdm-ap-southeast-1.aliyun.com`
- MX for bounces: mxdm-ap-southeast-1.aliyun.com at notify.hicloudcam.com
  - `notify.hicloudcam.com MX 10 mxdm-ap-southeast-1.aliyun.com`

### Alibaba Mail

Mailbox · receives your mail

- MX: mxn.mxhichina.com, mxw.mxhichina.com
  - `hicloudcam.com MX 5 mxn.mxhichina.com`
  - `hicloudcam.com MX 10 mxw.mxhichina.com`
- SPF: include:spf.mxhichina.com
  - `hicloudcam.com TXT include:spf.mxhichina.com`
- Setup: complete: MX present, SPF present

### Amazon SES

Transactional · account only

- Verification token: amazonses:hUp0SJqUUSLitFCvnXtq9BHr28l8RN9qKKu4lI/5YpU=
  - `hicloudcam.com TXT amazonses:hUp0SJqUUSLitFCvnXtq9BHr28l8RN9qKKu4lI/5YpU=`

## Not matched to a service

These records point somewhere Sendermap does not recognise: a service it does not know yet, or your own servers.

- DMARC reports go to: `ibesecurity.com`, from `_dmarc.hicloudcam.com TXT v=DMARC1; p=none; rua=mailto:dmarc_agg@ibesecurity.com;`
- CNAME at mail: `mail.mxhichina.com`, from `mail.hicloudcam.com CNAME mail.mxhichina.com`

## Looked for and not found

Records Sendermap looked for and did not find.

- DKIM keys at hicloudcam.com: no selectors exist: _domainkey.hicloudcam.com does not exist, so the 122-name sweep was skipped; the 8 names its MX, SPF and delegations point to were asked as a check, and none exists (RFC 8020 section 5)
  - `_domainkey.hicloudcam.com TXT no such name`
  - `sendermap-wildcard-check._domainkey.hicloudcam.com TXT no such name`
- DKIM keys at notify.hicloudcam.com: no selectors exist: _domainkey.notify.hicloudcam.com does not exist, so the 27-name sweep was skipped; the 8 names its MX, SPF and delegations point to were asked as a check, and none exists (RFC 8020 section 5)
  - `_domainkey.notify.hicloudcam.com TXT no such name`
  - `sendermap-wildcard-check._domainkey.notify.hicloudcam.com TXT no such name`

## How this was checked

Checked 2026-11-14 06:40 UTC: 233 DNS lookups in 0.0 s over Google DNS over HTTPS.

- At hicloudcam.com: 8 possible DKIM key names, 25 service record names, 1 web page.
- At notify.hicloudcam.com: 8 possible DKIM key names.

Not run:

- the website. Web checks were turned off (--no-web).
- certificate transparency, crt.sh. Read only with --ct (it also holds expired certificates).

Names asked:

- hicloudcam.com, Pages: `https://api.certspotter.com/v1/issuances?domain=hicloudcam.com&include_subdomains=true&expand=dns_names`
- hicloudcam.com, CNAME labels: `bounce`, `bounces`, `em`, `email`, `mail`, `send`, `mta`, `rp`, `pm-bounces`, `links`, `link`, `click`, `track`, `tracking`, `url`, `go`, `autodiscover`, `cf-bounce`, `eversrv`, `fwdkim1`, `bnc3`, `bounces.cloud.em`, `bounces.cloud2.em`, `outbound.intercom`, `atlassian-bounces`
- hicloudcam.com, DKIM selectors: `acdkim1`, `acdkim2`, `ses`, `ses1`, `ses2`, `aweber_key_a`, `aweber_key_b`, `aweber_key_c`
- notify.hicloudcam.com, DKIM selectors: `acdkim1`, `acdkim2`, `ses`, `ses1`, `ses2`, `aweber_key_a`, `aweber_key_b`, `aweber_key_c`
