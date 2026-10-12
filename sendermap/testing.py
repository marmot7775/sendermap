"""Record and replay: DNS answers and web pages kept on disk, so a map can be made again offline.

`RecordingResolver` wraps any Resolver and keeps every question and Answer it gave; `save` writes
them as JSON, sorted, one object per question. `ReplayResolver` answers from that file. A
question the file does not hold raises `UnrecordedError`, naming it, so a new code path fails
loudly instead of asking the network. A recorded FAILED answer replays as FAILED, which is how
could not check is modelled.

`RecordingTransport` and `ReplayTransport` do the same for pages: method, URL, status, content
type, the redirect target and the body text, or the transport error a request ended in.

The engine runs each source behind a guard that turns an exception into a gap, so an unrecorded
question also lands in `missed` on the replayer: a test asserts it is empty, and the map's own
gaps are never the only sign.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from .dns import Answer, Resolver, Status, norm
from .engine import map_domain
from .model import SenderMap

Question = tuple[str, str]
Request = tuple[str, str]


class UnrecordedError(LookupError):
    """A question or request the recording does not hold."""


def _dump(path: Path, rows: list[dict[str, Any]]) -> None:
    """A JSON array, one object per line, in the order given."""
    lines = ",\n".join(json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows)
    path.write_text(f"[\n{lines}\n]\n" if rows else "[]\n", encoding="utf-8")


def _load(path: Path) -> list[dict[str, Any]]:
    rows = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise ValueError(f"{path}: expected a JSON array")
    return rows


# ---------------------------------------------------------------- DNS


def _answer_row(answer: Answer) -> dict[str, Any]:
    row: dict[str, Any] = {
        "name": answer.name,
        "rtype": answer.rtype,
        "status": answer.status.value,
        "records": list(answer.records),
        "chain": list(answer.chain),
    }
    if answer.servfail:  # written only when set, so files recorded before it still read
        row["servfail"] = True
    return row


class RecordingResolver:
    """Answers through `resolver` and keeps every question and Answer."""

    def __init__(self, resolver: Resolver) -> None:
        self._resolver = resolver
        self.answers: dict[Question, Answer] = {}

    @property
    def name(self) -> str:
        return self._resolver.name

    async def query(self, name: str, rtype: str) -> Answer:
        answer = await self._resolver.query(name, rtype)
        self.answers[(norm(name), rtype.upper())] = answer
        return answer

    def save(self, path: Path) -> None:
        _dump(path, [_answer_row(self.answers[q]) for q in sorted(self.answers)])


class ReplayResolver:
    """Answers from a file `RecordingResolver.save` wrote; raises UnrecordedError for any other
    question. `name` is the resolver that answered when the file was recorded."""

    def __init__(self, path: Path, name: str) -> None:
        self.name = name
        self.answers: dict[Question, Answer] = {}
        for row in _load(path):
            answer = Answer(
                row["name"],
                row["rtype"],
                Status(row["status"]),
                tuple(row["records"]),
                tuple(row["chain"]),
                servfail=row.get("servfail", False),
            )
            self.answers[(norm(answer.name), answer.rtype.upper())] = answer
        self.missed: list[Question] = []

    async def query(self, name: str, rtype: str) -> Answer:
        question = (norm(name), rtype.upper())
        if question not in self.answers:
            self.missed.append(question)
            raise UnrecordedError(f"no recorded answer for {question[1]} {question[0]}")
        return self.answers[question]


# ---------------------------------------------------------------- pages


def _response(row: dict[str, Any], request: httpx.Request) -> httpx.Response:
    """The response a recorded row stands for. Recording returns this too, so a live run and its
    replay see the same headers and the same bytes."""
    if row.get("error"):
        failure = getattr(httpx, row["error"], None)
        if not (isinstance(failure, type) and issubclass(failure, httpx.TransportError)):
            failure = httpx.TransportError
        raise failure(f"recorded failure: {row['error']}", request=request)
    headers = {}
    if row["content_type"] is not None:
        headers["content-type"] = row["content_type"]
    if row["location"] is not None:
        headers["location"] = row["location"]
    encoding = httpx.Response(200, headers=headers).charset_encoding or "utf-8"
    content = row["body"].encode(encoding, errors="replace")
    return httpx.Response(row["status"], headers=headers, content=content, request=request)


def _request_key(request: httpx.Request) -> Request:
    return request.method, str(request.url)


class RecordingTransport(httpx.AsyncBaseTransport):
    """Sends through `transport` (a real one by default) and keeps each response's method, URL,
    status, content type, redirect target and body text, or the transport error it ended in."""

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport or httpx.AsyncHTTPTransport()
        self.responses: dict[Request, dict[str, Any]] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        method, url = _request_key(request)
        row: dict[str, Any] = {"method": method, "url": url}
        try:
            response = await self._transport.handle_async_request(request)
            raw = httpx.Response(
                response.status_code,
                headers=response.headers,
                stream=response.stream,
                request=request,
            )
            await raw.aread()
        except httpx.TransportError as e:
            row["error"] = type(e).__name__
            self.responses[(method, url)] = row
            raise
        row |= {
            "status": raw.status_code,
            "content_type": raw.headers.get("content-type"),
            "location": raw.headers.get("location"),
            "body": raw.text,
        }
        self.responses[(method, url)] = row
        return _response(row, request)

    async def aclose(self) -> None:
        await self._transport.aclose()

    def save(self, path: Path) -> None:
        _dump(path, [self.responses[r] for r in sorted(self.responses)])


class ReplayTransport(httpx.MockTransport):
    """Serves the responses `RecordingTransport.save` wrote; raises UnrecordedError for any other
    request."""

    def __init__(self, path: Path | None) -> None:
        rows = _load(path) if path is not None else []
        self.responses = {(row["method"], row["url"]): row for row in rows}
        self.missed: list[Request] = []
        super().__init__(self._serve)

    @classmethod
    def empty(cls) -> ReplayTransport:
        """A transport that holds no page, for a case that requested none."""
        return cls(None)

    def _serve(self, request: httpx.Request) -> httpx.Response:
        key = _request_key(request)
        if key not in self.responses:
            self.missed.append(key)
            raise UnrecordedError(f"no recorded response for {key[0]} {key[1]}")
        return _response(self.responses[key], request)


# ---------------------------------------------------------------- a recorded case


@dataclass(frozen=True, slots=True)
class Case:
    """How a map was made: the domain, the moment it is dated by, the checks that ran and the
    resolver that answered.
    Kept in a case directory as case.json beside dns.json and, when a page was requested,
    http.json."""

    domain: str
    checked_at: datetime
    use_web: bool
    use_subdomains: bool
    # The resolver that answered the recording (Resolver.name), which its replay names too.
    resolver: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "checked_at": self.checked_at.isoformat(),
            "use_web": self.use_web,
            "use_subdomains": self.use_subdomains,
            "use_ct": False,
            "resolver": self.resolver,
        }

    @classmethod
    def load(cls, directory: Path) -> Case:
        row = json.loads((directory / "case.json").read_text(encoding="utf-8"))
        checked_at = datetime.fromisoformat(row["checked_at"])
        return cls(
            row["domain"], checked_at, row["use_web"], row["use_subdomains"], row["resolver"]
        )


def comparable(sender_map: SenderMap) -> dict[str, Any]:
    """The map's JSON without the run's elapsed time and lookup count, which are not answers,
    and without the reconciliation when nothing was claimed, since a case records no claims."""
    data = sender_map.to_dict()
    data["run"] = {k: v for k, v in data["run"].items() if k not in ("elapsed", "lookups")}
    if data["reconciliation"] is None:
        del data["reconciliation"]
    return data


@dataclass(frozen=True, slots=True)
class Replayed:
    map: SenderMap
    resolver: ReplayResolver
    transport: ReplayTransport

    @property
    def missed(self) -> list[str]:
        """Every question and request the recording did not hold, in words."""
        asked = [f"{rtype} {name}" for name, rtype in self.resolver.missed]
        return asked + [f"{method} {url}" for method, url in self.transport.missed]


async def replay(directory: Path) -> Replayed:
    """Map a recorded case again from its files, without the network."""
    case = Case.load(directory)
    resolver = ReplayResolver(directory / "dns.json", case.resolver)
    pages = directory / "http.json"
    transport = ReplayTransport(pages) if pages.exists() else ReplayTransport.empty()
    async with httpx.AsyncClient(transport=transport) as http:
        sender_map = await map_domain(
            case.domain,
            checked_at=case.checked_at,
            resolver=resolver,
            http=http,
            use_web=case.use_web,
            use_subdomains=case.use_subdomains,
            use_ct=False,
        )
    return Replayed(sender_map, resolver, transport)
