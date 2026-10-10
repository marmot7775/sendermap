# Sendermap

Type a domain, see every service that sends email as it, and the public evidence for each one.

**Status: in development.** Not usable yet. Watch or star the repo to follow along.

## What it will show

For any domain, Sendermap builds a map of the services that send or receive its mail: mailbox
providers, marketing and transactional platforms, support desks, security gateways and the
services that receive its reports. Each one comes with:

- **The evidence**, record by record: the SPF include, MX host, DKIM key, bounce or tracking
  CNAME, verification token or report address that gave it away.
- **How sure we are**, in words, not a percentage:
  - **In use**: mail for the domain is delivered there.
  - **Configured**: set up to send as the domain.
  - **Likely**: a signing key whose name points at the service.
  - **Account only**: a trace of an account with nothing set up to send.

It looks beyond the main domain: brands often send from subdomains such as `email.`, `mg.` or
`bounce.`, which a check of the main domain never sees. It also points out what needs attention:
DKIM records that point at names that no longer exist, SPF records past the 10 lookup limit,
revoked keys, and senders nobody can name.

## How it works

Everything comes from public sources: DNS, certificate transparency logs, the domain's own
website, and public records of who owns each network. Each finding is shown with the record
that supports it, so you can check it yourself.

- **SPF** is walked as a tree, crediting only links that actually authorize senders.
- **DKIM** keys are found by scanning the names services use, and credited by where they point.
- **Raw IP ranges** in SPF are named by matching them against the ranges each service publishes,
  then by who owns the network.
- **Sending subdomains** come from the names services ask for and from certificate logs.
- **The website** shows the scripts and stylesheets it loads, the services it mentions, and the
  services its subprocessor page names.
- **Certificate transparency** (`--ct`, off by default): every name crt.sh has logged a
  certificate for is resolved now and matched like any DNS record, so a branded tracking link
  such as `link.example.com` pointing at an email platform shows up. A logged name that no
  longer resolves but still points at a service is listed as a possible past vendor, not a
  current sender. crt.sh is often slow; it is tried three times, answers are cached for a day,
  and if it never answers the map says so and finishes without it.

Run it from the command line:

```
pip install git+https://github.com/marmot7775/sendermap
sendermap example.com
sendermap example.com --evidence     # every piece of evidence
sendermap example.com --markdown     # a summary to paste
sendermap example.com --json         # everything, for scripts
sendermap example.com --ct           # add names from certificate logs (crt.sh)
```

The website keeps no record of the domains looked up.

## The vendor data

All vendor knowledge lives in one file, [`sendermap/data/vendors.json`](sendermap/data/vendors.json), one block per
service, so adding or correcting a vendor is a small pull request. The first version was imported
from the vendor tables in [dns-audit](https://github.com/marmot7775/dns-audit) (MIT).

## Contributing

Each vendor gets one block in `sendermap/data/vendors.json`, and everything known about it goes
there. Every pattern in a block (an SPF include, an MX host, a CNAME target, a report address, a
verification token, a network, a website host, a selector name, a subprocessor name) carries one
proof of its own: a live domain that publishes it, the record name or page as found, and the
date checked (a numbered series of selectors such as s1, s2 needs one for the series). A pattern without a proof
does not get merged, and Sendermap refuses to load one.

Patterns not yet proven wait in `sendermap/data/vendors_pending.json`, each block with a note of
what was checked; Sendermap never reads that file, so a record they would match shows as not
recognised. A vendor moves from pending to vendors.json with one proof per pattern, the same rule
as any new block.

Every proof is rechecked against live DNS and the web each week and on any pull request that
touches `vendors.json`. A proof that no longer holds opens an issue, so a stale pattern is caught
and fixed.

## Related

- [dns-audit.com](https://dns-audit.com): a full email security audit of a domain.

## License

MIT
