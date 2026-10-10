"""Rule 5: the names a subprocessor page is read for are data in vendors.json, each with a proof,
not a length rule in code."""

import copy
import json
from dataclasses import replace
from importlib import resources

import httpx
from conftest import Zone, context

from sendermap import catalog
from sendermap.model import Kind
from sendermap.sources import web

SHIPPED = json.loads(resources.files("sendermap").joinpath("data/vendors.json").read_text())
PROOF = {"domain": "sendgrid.com", "record": "https://sendgrid.com/", "date": "2026-10-09"}


async def named_on(page: str, loaded: catalog.Catalog | None = None) -> dict[str, str]:
    """{service: the evidence value} for each service the subprocessor page names."""
    pages = {
        "https://example.com/": '<a href="/legal/subprocessors">Subprocessors</a>',
        "https://example.com/legal/subprocessors": page,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, text=pages.get(str(request.url), ""), headers={"content-type": "text/html"}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        ctx = replace(context(Zone()), http=http, catalog=loaded or catalog.load())
        observed = await web.collect(ctx)
    return {c.service: c.evidence.value for c in observed.claims if c.kind is Kind.SUBPROCESSOR}


async def test_a_service_is_named_by_the_names_its_block_lists() -> None:
    raw = copy.deepcopy(SHIPPED)
    raw["vendors"]["SendGrid"]["subprocessor_names"].append(
        {"value": "Twilio SendGrid", "proof": PROOF}
    )
    assert await named_on("<td>Twilio SendGrid</td>", catalog.build(raw)) == {
        "SendGrid": "names Twilio SendGrid"
    }


async def test_a_service_with_no_listed_name_is_never_named() -> None:
    # Kit and Wix are ordinary words, a DMARC reporter does not send, and Google Workspace's name
    # has no proof yet: none of them lists a subprocessor name.
    page = "<td>Kit</td><td>Wix</td><td>Valimail</td><td>Google Workspace</td><td>Zendesk</td>"
    assert await named_on(page) == {"Zendesk": "names Zendesk"}
    loaded = catalog.load()
    assert not {"Kit", "Wix", "Valimail", "Google Workspace"} & set(loaded.subprocessor_names)


def test_every_listed_name_belongs_to_a_sending_service() -> None:
    loaded = catalog.load()
    assert loaded.subprocessor_names
    for name, service in loaded.subprocessor_names.items():
        assert loaded.category(service) != "DMARC reporting", name
