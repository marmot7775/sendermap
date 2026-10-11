"""sendermap example.com"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
from rich.console import Console

from . import __version__
from .dns import DohResolver, Resolver, SystemResolver
from .engine import map_domain
from .reconcile import names, split
from .render import markdown, text
from .sources.ct import default_cache


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        args.claimed = _claimed(args)
    except OSError as e:
        print(f"sendermap: cannot read {args.claimed_file}: {e.strerror}", file=sys.stderr)
        return 2
    try:
        return asyncio.run(_run(args))
    except ValueError as e:
        print(f"sendermap: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


async def _run(args: argparse.Namespace) -> int:
    console = Console(stderr=True)
    async with httpx.AsyncClient() as http:
        resolver: Resolver = DohResolver(http) if args.doh else SystemResolver()
        with console.status(f"Mapping {args.domain}...", spinner="dots") as status:

            async def progress(step: str) -> None:
                status.update(f"{args.domain}: {step}...")

            result = await map_domain(
                args.domain,
                checked_at=datetime.now(UTC),
                resolver=resolver,
                http=http,
                use_web=not args.no_web,
                use_subdomains=not args.no_subdomains,
                use_ct=args.ct,
                ct_cache=default_cache(),
                progress=progress,
                claimed=args.claimed,
            )
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
    elif args.markdown:
        print(markdown.render(result, evidence=args.evidence), end="")
    else:
        text.render(result, Console(), evidence=args.evidence)
    return 0


def _claimed(args: argparse.Namespace) -> list[str]:
    """The names given with --claimed and the lines of --claimed-file, in that order."""
    given = split(args.claimed or "")
    if args.claimed_file:
        given += Path(args.claimed_file).read_text(encoding="utf-8").splitlines()
    return names(given)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sendermap",
        description="See every service that sends email as a domain, with the public evidence.",
    )
    p.add_argument("domain", help="a domain, a URL or an email address")
    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="print the full result as JSON")
    out.add_argument("--markdown", action="store_true", help="print a Markdown summary")
    p.add_argument("--evidence", action="store_true", help="show every piece of evidence")
    p.add_argument("--no-web", action="store_true", help="do not read the domain's website")
    p.add_argument("--no-subdomains", action="store_true", help="check the main domain only")
    p.add_argument(
        "--ct",
        action="store_true",
        help=(
            "also read crt.sh, which holds expired certificates too, and resolve every name the "
            "certificate logs hold now (slow; each log cached a day)"
        ),
    )
    p.add_argument(
        "--claimed",
        metavar="NAMES",
        help="the services the domain's owner says they use, comma separated, held against the map",
    )
    p.add_argument(
        "--claimed-file", metavar="FILE", help="the same, one name per line, from a file"
    )
    p.add_argument("--doh", action="store_true", help="look up DNS over HTTPS (Cloudflare)")
    p.add_argument("--version", action="version", version=f"sendermap {__version__}")
    return p


if __name__ == "__main__":
    raise SystemExit(main())
