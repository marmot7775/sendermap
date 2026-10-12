"""sendermap example.com

Exit codes, for scripts and agents: 0 the map was built, 2 bad input, 3 the domain's own records
could not be read, so there is no map to show.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

import httpx
from rich.console import Console

from . import __version__
from .dns import DohResolver, Resolver, Status, SystemResolver, doh_client
from .engine import map_domain
from .model import SenderMap
from .reconcile import names, split
from .render import markdown, text
from .sources.ct import default_cache

MAPPED = 0
BAD_INPUT = 2
UNREADABLE = 3


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)  # argparse exits with 2 on a bad flag
    try:
        args.claimed = _claimed(args)
    except OSError as e:
        print(f"sendermap: cannot read {args.claimed_file}: {e.strerror}", file=sys.stderr)
        return BAD_INPUT
    try:
        result = asyncio.run(_map(args))
    except ValueError as e:
        print(f"sendermap: {e}", file=sys.stderr)
        return BAD_INPUT
    except KeyboardInterrupt:
        return 130
    if unread := unreadable(result):
        print(
            f"sendermap: no map: {result.domain}'s own records could not be read ({unread})",
            file=sys.stderr,
        )
        return UNREADABLE
    try:
        with _destination(args.output) as out:
            _write(result, args, out)
    except OSError as e:
        print(f"sendermap: cannot write {args.output}: {e.strerror}", file=sys.stderr)
        return BAD_INPUT
    return MAPPED


def unreadable(result: SenderMap) -> str:
    """Why the domain's own records could not be read, or "" when they could: its TXT (where
    SPF lives) and its MX both failed to look up, so nothing in the map can be told apart from a
    resolver that is down."""
    own = {f"SPF: TXT at {result.domain}", f"mail servers: MX at {result.domain}"}
    failed = [g for g in result.gaps if g.asked in own and g.happened == Status.FAILED.value]
    return "; ".join(f"{g.asked}: {g.happened}" for g in failed) if len(failed) == len(own) else ""


async def _map(args: argparse.Namespace) -> SenderMap:
    console = Console(stderr=True)
    async with httpx.AsyncClient() as http, doh_client() as dns_http:
        resolver: Resolver = DohResolver(dns_http) if args.doh else SystemResolver()
        # The spinner goes to stderr, and only to a terminal: a pipe or a log gets nothing.
        spinner = console.status(f"Mapping {args.domain}...", spinner="dots")
        with spinner if console.is_terminal else contextlib.nullcontext():

            async def progress(step: str) -> None:
                if console.is_terminal:
                    spinner.update(f"{args.domain}: {step}...")

            return await map_domain(
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


@contextlib.contextmanager
def _destination(path: str | None) -> Iterator[TextIO]:
    if path is None:
        yield sys.stdout
        return
    with Path(path).open("w", encoding="utf-8") as file:
        yield file


def _write(result: SenderMap, args: argparse.Namespace, out: TextIO) -> None:
    if args.json:
        out.write(json.dumps(result.to_dict(), indent=2, default=str) + "\n")
    elif args.markdown:
        out.write(markdown.render(result, evidence=args.evidence))
    elif out is sys.stdout:
        text.render(result, Console(), evidence=args.evidence)
    else:  # a file gets the text view without colour or terminal codes
        text.render(result, Console(file=out, color_system=None, width=100), evidence=args.evidence)


def _claimed(args: argparse.Namespace) -> list[str]:
    """The names given with --claimed and the lines of --claimed-file, in that order."""
    given = split(args.claimed or "")
    if args.claimed_file:
        given += Path(args.claimed_file).read_text(encoding="utf-8").splitlines()
    return names(given)


EPILOG = """\
exit codes:
  0  the map was built and written.
  2  bad input: a malformed domain, an unknown flag, a --claimed-file that cannot be read, or an
     --output that cannot be written. The message on stderr says which.
  3  no map: both the TXT and the MX lookups at the domain itself failed, so the resolver, not
     the domain, decided the answer. Try again, or try --doh.

Progress shows on stderr while the map is built, and only when stderr is a terminal, so stdout
and --output hold the map alone. The JSON keeps the sendermap/1 contract (sendermap.schema()):
it grows by addition only, so ignore fields and values you do not know."""


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sendermap",
        description=(
            "See every service that sends email as a domain, with the public record behind each "
            "one. Everything comes from public sources: DNS, certificate logs and the domain's "
            "own website."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "domain",
        help=(
            "The domain to map. A URL or an email address works too: the domain is taken from it."
        ),
    )
    out = p.add_mutually_exclusive_group()
    out.add_argument(
        "--json",
        action="store_true",
        help=(
            "Write the whole map as JSON, schema sendermap/1, for scripts and agents. Every claim, "
            "gap and setup item is in it, with its evidence."
        ),
    )
    out.add_argument(
        "--markdown",
        action="store_true",
        help="Write a Markdown summary, for pasting into a ticket or a report.",
    )
    p.add_argument(
        "--output",
        metavar="PATH",
        help=(
            "Write the map to PATH instead of stdout, in the format chosen (text without colour "
            "when neither --json nor --markdown is given). The file is replaced if it exists."
        ),
    )
    p.add_argument(
        "--evidence",
        action="store_true",
        help=(
            "Show every piece of evidence under each service, not just the one that decided its "
            "tier. Applies to the text and Markdown views; JSON always has all of it."
        ),
    )
    p.add_argument(
        "--no-web",
        action="store_true",
        help=(
            "Do not read the domain's homepage or subprocessor page. The map then says the "
            "website was not checked."
        ),
    )
    p.add_argument(
        "--no-subdomains",
        action="store_true",
        help=(
            "Map the domain itself only, without searching for sending subdomains such as email. "
            "or mg. The map says they were not searched."
        ),
    )
    p.add_argument(
        "--ct",
        action="store_true",
        help=(
            "Also read crt.sh, which holds expired certificates too, and resolve every name the "
            "certificate logs hold now. Slow; each log is cached for a day."
        ),
    )
    p.add_argument(
        "--claimed",
        metavar="NAMES",
        help=(
            "The services the domain's owner says they use, comma separated. The map holds them "
            "against what it found: confirmed, unclaimed, unfound and unknown."
        ),
    )
    p.add_argument(
        "--claimed-file",
        metavar="FILE",
        help="The same as --claimed, one name per line, read from FILE.",
    )
    p.add_argument(
        "--doh",
        action="store_true",
        help=(
            "Look up DNS over HTTPS through Cloudflare instead of this machine's resolver. Use it "
            "where the local resolver cannot be trusted."
        ),
    )
    p.add_argument("--version", action="version", version=f"sendermap {__version__}")
    return p


if __name__ == "__main__":
    raise SystemExit(main())
