# Sendermap

## Architecture

Sendermap is a library first. All DNS lookups, SPF and DMARC parsing,
MX and DKIM evidence gathering, and the reasoning that maps evidence
to sending services live in the sendermap package and nowhere else.

The CLI, the MCP server, and any web front end are thin callers. They
accept a domain, call the package, and present the result. They hold
no DNS or parsing logic of their own.

## Do not repeat yourself

Before writing any new lookup or parsing code, check whether the
package already has it. If it does, reuse it. If dns-audit has it,
port it into the package once rather than copying it.

Design the package so dns-audit and the APRF reader can import it
later and drop their own DNS code. One engine per job.

## Code quality

This is a portfolio project. Readable names, short functions,
docstrings on public functions, type hints throughout, tests for
every parser. Keep public functions small and pure where possible.

## Working style

Show the package layout, one line per module, before writing code.
Finish one thing before starting the next. Ask when a design choice
is genuinely Neil's call; otherwise make the call and say what you
chose. Prefer the repeatable solution over the one-off.

## Writing

No em dashes anywhere. Plain directives, not rules phrased as never.
No emoji in README or docs. Lead with the point and say it once.
