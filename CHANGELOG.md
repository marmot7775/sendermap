# Changelog

Every release of Sendermap, newest first. The JSON a map gives keeps the `sendermap/1` contract:
it grows by addition only.

To release: rename Unreleased to the version (`## 0.1.0`), commit, and push the tag `v0.1.0`.
The publish workflow builds from the tag, takes that section as the release notes, publishes to
PyPI and makes the GitHub release; a tag with no section fails before anything is published.

## Unreleased

What 0.1.0 holds:

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
- An MCP server, `sendermap mcp` with the `mcp` extra: a map tool whose structured content is the `sendermap/1` JSON, in summary or full, and a vendor tool, with the schema and the vendor list as resources. The website mounts the same server at `/mcp` over streamable HTTP, under the API's limits per visitor and per target domain.
- An Agent Skill, `skills/sendermap/SKILL.md`, that tells an agent how to run a map, read it, and report it without going past the evidence.
