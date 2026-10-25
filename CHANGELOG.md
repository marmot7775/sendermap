# Changelog

Every release of Sendermap, newest first. The JSON a map gives keeps the `sendermap/1` contract:
it grows by addition only.

To release: rename Unreleased to the version (`## 0.1.0`), set the same version in `server.json`
(three places), commit, and push the tag `v0.1.0`.
The publish workflow builds from the tag, takes that section as the release notes, publishes to
PyPI, makes the GitHub release and lists the version in the MCP registry; a tag with no section
fails before anything is published.

## Unreleased

- The page links its stylesheet and script with the version as a query string (`/static/style.css?v=0.1.6`), so Cloudflare's cache of static files, kept for four hours, cannot serve the last release's stylesheet to this release's page. 0.1.5's page showed its new glance table unstyled until the cache expired.

## 0.1.5 (2026-10-25)

- The terminal view is laid out to be read top down. A panel gives the domain, how many services send as it and how many things need fixing. The story follows, then AT A GLANCE: one row per service with a marker, its category, a plain status (Receives mail, Set up to send, Likely, Account only) and its setup in a word or two, or what a weak tier rests on. FIX THESE numbers the risks and warnings, NOTES lists the rest, then EVIDENCE, SERVICE BY SERVICE. What was asked, not checked and not run share one dimmed block, HOW THIS WAS CHECKED, and the story's Not checked sentence is no longer said twice.
- The site's result page follows the same order. Under the domain, the service count and the count of things to fix in colour, and how the map was made on its own line. The story and ring map stay side by side; then an At a glance table (a dot, the name linking to its evidence, category, status badge, setup), Fix these as numbered cards, Notes as a plain list, Evidence, service by service, and one closed How this was checked block holding what was not checked and what was asked. On a phone each glance row stacks into a small card. The map legend and How it works use Receives mail and Set up to send.
- Findings that differ only in the name they are at are said once in every view: "SPF at glossier.com and receipts.glossier.com is managed through Valimail".
- A short DKIM key finding names the service each key belongs to: "mandrill (Mandrill) and s2 (SendGrid)".
- An MX host no pattern names is looked up by address. When every network that announces it is one service's own, it is credited to that service with the new evidence kind "mail server's address is in its network (MX)" (Configured), and it leaves Not recognised. At the domain itself, an MX at the address of a service that sends but does not receive mail is a warning: investorpass.com's MX, o1.sendgrid.investorpass.com, is SendGrid's reverse DNS name for 167.89.106.132 in AS11377. A shared cloud is never credited.
- Keys of mixed sizes give each its own size, "s1 2048 bit, s2 1024 bit", instead of "1024 and 2048 bit".

## 0.1.4 (2026-10-24)

- The site leads with the story and the ring map side by side, above Needs attention, so the findings sit above the fold. The story prints one sentence per paragraph, its Not checked sentence muted. From 900px up the map takes a fixed 340px column beside the story; below that it stacks under the story and grows to 560px.
- Every service name and sector label fits on the ring map. The rings stop inside the box to leave an outer band for names; each label sits outward along its own angle, at 10px (12px past 600px rendered), and a label that would collide is tried one line out, then one line up or down, before it is dropped. glossier.com shows 9 of 9 names and 4 of 4 sectors at 1280, 899 and 390px, where before it showed 3 and 1. The map draws after the result is shown and redraws on resize.
- The map centre is a plain hub at half its old size. The domain no longer prints in it, since it fit only sometimes and heads the page already.
- Services on the site are rows, not cards: name, category and where, tier badge, then the deciding record with the others under it, the setup clause and All records. Four columns from 900px up, two lines below. Each row keeps its `service-<slug>` id, so a tap on the map still lands on it.
- Not checked and What was asked say each reason once in all three views. Gaps of one question, kind, cap and outcome are one group listing the names together ("DKIM selectors at marketing, receipts and send.glossier.com: 82 of 109 not asked at each"), with the cap said last. What was asked leads with the lookups and names in all.
- certifi in `uv.lock` moves to 2026.10.23, past the emSign root CAs whose intermediate keys were compromised. It comes in through httpx; no code changes.

## 0.1.3 (2026-10-23)

- The terminal and Markdown views render one view model (`render/view.py`) and say each thing once: findings come first, each service shows one evidence line per kind ("DKIM keys: selector1, selector2 (both 2048 bit, by CNAME)") and its setup in one clause ("setup complete", or only what is missing), an item a finding names is said in the setup by its state alone, and What was asked gives counts. Full records and the names asked print with `--evidence`, the names in Markdown as a last section, Appendix: names asked. The Markdown senders table gains a Setup column, and its Setups section goes. Allbirds' Markdown view falls from 111 lines to 76.
- The site renders the same view as the command line. The page's HTML is rendered on the server from the one View (`render/html.py`), every string escaped there, and app.js keeps only the form, the stream, the ring map and the buttons, so the page holds no third copy of the rendering logic and no longer shows the old layout (services before findings, a setup line per record). Each service's records in full and the names asked sit inside details elements. The stream's `map` event now carries `{"map": ..., "html": ...}`, and `GET /api/map.html` returns the fragment with the same limits and cache as `/api/map`.
- The terminal view is easier to read. Each service is a block: its name and category, then one line per kind of record with the labels in a column, then its setup, coloured by whether it is complete. Wrapped lines keep their indent everywhere, so a long finding, gap or record no longer runs back to the left margin. The story prints one sentence per line.
- Short DKIM keys at one name are said once: "Six DKIM keys at goop.com are 1024-bit: selector1, s1, s2, smtpapi, mandrill and key1", not six findings with the same advice. The JSON still has one finding per key.
- Checks that are opt-in or turned off (crt.sh without `--ct`, `--no-web`, `--no-subdomains`) move out of Not checked into a short Not run section at the end, without the request they would have made. Not checked now holds only questions that were asked and got no usable answer. The story still names them.
- The absence for a zone with no DKIM selectors says it in one sentence: "_domainkey.bounce.allbirds.com does not exist, so the 27-name sweep was skipped; the 8 names its MX, SPF and delegations point to were asked as a check, and none exists".
- A subdomain that is a CNAME to the domain or to another sending subdomain is no longer mapped as a sending subdomain of its own. www.github.com, gist.github.com and shop.github.com are aliases of github.com and answer with its SPF and MX, so Microsoft 365 and Google Workspace showed at each with a missing DKIM key there: nine findings for setups no one made. An alias to a name outside the domain still counts, since its records are nowhere else in the map.
- A zone that answers no such name for `_domainkey.<domain>` while a key sits under it is now a note, not a gap. Every selector is still asked there, so nothing went unchecked, but the story read "one DKIM selector that could not be read". The note says what the DNS host does wrong: under RFC 8020 that answer covers every name below it. functionalmedicinecoaching.org, on Bluehost's nameservers, answers this way.
- A record that a likely service's setup lacks is a note, not a warning, and says to check the service still sends first. goop.com showed "Cloudflare Email Routing at goop.com has no SPF" as a warning from a DKIM key name alone, while its mail goes to Google.
- A domain that does not exist in DNS says so: a finding, "The domain does not exist in DNS", and a story that leads with it, instead of "No sending service shows in DNS" as for a real domain with no mail set up. The map stops there: one lookup, not about 210.
- A pasted value is refused unless it is a hostname: an IP address (`192.0.2.1` was mapped as a domain), a wildcard, characters a hostname cannot hold, a label of more than 63 characters or a numeric top-level domain now reads "not a domain" on the command line, the site and the MCP server alike, and a malformed name no longer raises an IDNA error.
- The MCP tool's text reply lists findings most severe first, with short keys at one name said once, as the other views do. It listed them in the order the sources raised them.
- 16 services added and 15 patterns for known ones, each with a live proof, from a run over 50 domains not mapped before (DTC brands, B2B software, universities, nonprofits, media). Marketing: Conversica, Maropost, Engaging Networks, ActionKit, Extole, Communicator, ClickDimensions, SPIRAL, FreshMail, Oracle Responsys. Transactional: SocketLabs (email-od.com). Business apps: Braintree, Tipalti, Impartner, and Wix's website host. Hosted SPF: DmarcDuty, read like Valimail. Known services: Qualtrics's qemailserver.com include and MX, Amazon SES's us-west-2 inbound, Postmark's bounce MX, Campaign Monitor's createsend.com include and inbound MX, Klaviyo's klaviyomail.com and Customer.io's customeriomail.com includes, GetResponse's _spf.getresponse.com, Freshdesk's fwdkim1 return path, Epsilon's epsl1.com, 250ok's report address under Validity Everest, Mailgun's report address and Stripe's custom email return path. Across the 50 domains, unknowns fall from 700 to 560.
- Intercom's and Atlassian's return path CNAMEs are read: `outbound.intercom` and `atlassian-bounces` join the labels every map asks. Klaviyo gains km1 and km2, IONOS s2-ionos, and Optimizely Campaign `mailing` as a backed only name, credited and asked only where SPF or MX already shows Optimizely.
- Listrak added (marketing): its `esp1.co` SPF include, bounce MX and tracking CNAME, and its network AS394396, each with a live proof. goop.com's bounce. and email. subdomains read as Listrak, not as seven unknowns.

## 0.1.2 (2026-10-15)

- 31 services added and 10 patterns for known ones, each with a live proof, from a run over 50 large domains (retail, software, universities, charities, news, government). Marketing: Oracle Eloqua, Epsilon, Adobe Campaign, Microsoft Dynamics 365 Customer Insights, Blackbaud Luminate Online, Salsa Labs, Alida, Netigate, Hivebrite. Security gateway: Trend Micro Email Security, with an MX setup from its docs. Support, alerts and business apps: Khoros, Everbridge, Greenhouse, Red Points, Trustpilot, Cvent, Kibo Commerce, Docebo, ADP, SAP SuccessFactors, Fundraise Up, Q4, Madgex, Clinch. SPF flattening: AutoSPF, read like EasyDMARC. DMARC reports: DMARCLY, Report URI, Netcraft, Inbox Monster, Validity Everest, SendForensics. Known services: Sailthru's aspmx.sailthru.com and MX, Campaign Monitor's createsend.com tracking, Mandrill's inbound MX, HubSpot's MX hosts, Amazon SES's eu-west-1 inbound and Mail Manager MX, Squarespace's squarespace-mail.com, and Oracle's spf_c.oraclecloud.com. Across the 50 domains, unknowns fall from 1,008 to 727.
- A service whose sending runs through another no longer reads as that other service. Greenhouse's, Netigate's, Trustpilot's and Blackbaud's SPF records list Mailgun, Mailjet, SendGrid or SparkPost addresses, and Sailthru's lists a Campaign Monitor range, so those were credited to the domain; with the outer service known, its record is its own, as for every named service. On asana.com, figma.com, stripe.com, spotify.com, bombas.com, utoronto.ca, everlane.com, washingtonpost.com and economist.com this removes a credit the domain's own DNS did not give.
- `tools/fill_corpus.py` adds, live, the answers a corpus case now asks for after a vendor change, without changing a recorded answer.

## 0.1.1 (2026-10-15)

- A sending subdomain the domain's own DNS servers fail to answer for (SERVFAIL, often a subdomain delegated to nameservers that no longer serve it) now says so, instead of reading as a lookup that failed here.
- HubSpot's and Mimecast's published ranges are read from the SPF records their customers include, not from the companies' own office mail records. Those records list other senders' ranges and run deeper than Sendermap reads, so every map with IP ranges in SPF carried two gaps about them, and some ranges were held as shared when only one service publishes them. A vendor block may name these hosts as `published_spf`.
- The story names a receiver's risks in one clause ("receives the domain's mail, is not in its SPF and does not sign it") and no longer repeats the missing DKIM key in the sentence after.
- A missing DKIM key reads "no key at google._domainkey, a name that does not exist", not "google no such name".
- Two services added, each pattern with a live proof: SiteGround (its automatic SPF under dnssmarthost.net, `_spf.mailspamprotection.com`, its antispam MX and outbound address) and ClickFunnels (`mailer.myclickfunnels.com`, its outbound address and its domain verification token).
- A zone with a wildcard no longer turns every label into a sending subdomain. shopify.com and gov.uk answer TXT at any name, so 30 subdomains each showed as sending, with a DKIM gap at each; a name no one would publish is now asked first, and a label that gives its answer is the wildcard.
- An SPF record that passes the limit of two lookups that find nothing (RFC 7208 section 4.6.4) for a vendor's address is a note about the record, not "SPF evaluation (an error)" under Not checked: the permerror is the record's own answer.
- Intercom's, Dotdigital's, Brevo's and UniSender's published ranges are read from the records their customers include. Their company domains include other services (Campaign Monitor, Statuspage, mail.ru), whose ranges read as theirs. Campaign Monitor gains cmail1.com and its own network, AS55819, so its ranges in a flattened record are named.
- Ten services added and eleven patterns for known ones, each with a live proof, from a run over 20 large domains: Cloudflare Email Security and Cisco Secure Email (security gateways, with setups from their docs), Oracle Email Delivery, NetSuite, Qualtrics, Recurly, Zuora, and DMARC Digests, MxToolbox and NCSC Mail Check for reports; Salesforce Marketing Cloud's cust-spf.exacttarget.com and reply MX, SparkPost's e.sparkpost.com, Mailchimp's spf1.mcsv.net, Atlassian Statuspage's stspg-customer.com, Cisco's network AS16417, and the MX hosts of Zendesk, Marketo and Amazon SES (its us-east-1 inbound and its custom MAIL FROM). On casper.com, Marketing Cloud's include no longer reads as Salesforce Account Engagement, whose own record lists the same ranges.
- The resolver is named as a reader says it: "the system resolver", "Google DNS over HTTPS".
- Each release is listed in the MCP registry as io.github.marmot7775/sendermap, by the publish workflow.

## 0.1.0 (2026-10-12)

- A map of the services that send or receive a domain's mail, each with a tier (In use, Configured, Likely, Account only) and the record behind every claim.
- SPF walked as a tree, crediting only authorizing links, with the lookup count receivers spend and loops found.
- SPF evaluated as receivers do (RFC 7208 `check_host`, held to the RFC 7208 test suite), asking hosted and flattened records about each vendor's own sending address.
- IP ranges in SPF named by the ranges services publish, then by the network that announces them, and grouped by network when nobody can be named.
- DKIM keys found by CNAME, by selector name and by the names a domain's SPF, MX or NS delegation backs, with key flags, fingerprints and shared keys.
- What was looked for and not found, with the DNS answers that show it, read by how the zone answers for a missing name.
- Sending subdomains found from a wordlist and certificate logs, each mapped on its own, including subdomains delegated to a service by NS.
- Bounce and tracking CNAMEs, verification tokens, DMARC and TLS report addresses, MTA-STS, the BIMI logo, the homepage's scripts and subprocessor page.
- Each vendor's documented setup checked item by item at every name it has claims at.
- A short story above the map, written by rules from the map alone.
- The services a client says they use held against the map: confirmed, unclaimed, unfound, unknown.
- Every gap named: each failed lookup and each cap says what was left unchecked.
- Vendor data in one file, every pattern with a live proof, rechecked weekly.
- A command line (text, Markdown, JSON, --output to a file) with exit codes for scripts and agents (0 mapped, 2 bad input, 3 the domain's own records unreadable), and a website that streams the map and keeps no record of the domains looked up.
- The JSON Schema of a map, `sendermap/1`, served by the site and returned by `sendermap.schema()`.
- Backed only selectors: `s1` and `s2` credit Klaviyo only where SPF, MX or an NS delegation already shows Klaviyo, and nobody otherwise, so the keys under a Klaviyo delegated subdomain are read.
- Each map names the resolver that answered it (`system`, `doh cloudflare` or `doh google`), in its JSON and every view, since two resolvers can disagree.
- Eight delegating email platforms: Emarsys, Mapp, Cordial, Dotdigital, Inxmail, UniSender, Sendsay and Optimizely Campaign, each pattern with a live proof.
- The server instructions and the skill say a map gives no advice about which service to use or whether a setup is good enough; a finding names a fault in a published record and the record change that clears it.
- An MCP server, `sendermap mcp` with the `mcp` extra: a map tool whose structured content is the `sendermap/1` JSON, in summary or full, and a vendor tool, with the schema and the vendor list as resources. The website mounts the same server at `/mcp` over streamable HTTP, under the API's limits per visitor and per target domain.
- An Agent Skill, `skills/sendermap/SKILL.md`, that tells an agent how to run a map, read it, and report it without going past the evidence.
- A listing for the MCP registry (`server.json`, `io.github.marmot7775/sendermap`) and an `llms.txt` on the site.
