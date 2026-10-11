"""The DKIM scan: who holds each key, and what the keys say."""

import base64
import hashlib

import httpx
import pytest
from conftest import CHECKED, Zone, context

from sendermap import map_domain
from sendermap.model import Claim, Kind, Observed, Severity
from sendermap.sources import dkim


def der(tag: int, value: bytes) -> bytes:
    size = len(value)
    if size < 0x80:
        return bytes([tag, size]) + value
    length = size.to_bytes((size.bit_length() + 7) // 8)
    return bytes([tag, 0x80 | len(length)]) + length + value


def rsa_public_key(bits: int) -> bytes:
    """A bare RSAPublicKey whose modulus is exactly `bits` long."""
    modulus = (1 << (bits - 1)) | 1
    as_integer = b"\x00" + modulus.to_bytes(bits // 8)  # a leading zero keeps it positive
    return der(0x30, der(0x02, as_integer) + der(0x02, (65537).to_bytes(3)))


def spki(bits: int) -> bytes:
    """A SubjectPublicKeyInfo for an RSA key: the form RFC 6376 asks DKIM records to publish."""
    rsa_encryption = der(0x06, bytes.fromhex("2a864886f70d010101")) + der(0x05, b"")
    key = der(0x03, b"\x00" + rsa_public_key(bits))
    return der(0x30, der(0x30, rsa_encryption) + key)


def record(key: bytes, algorithm: str = "rsa") -> str:
    return f"v=DKIM1; k={algorithm}; p={base64.b64encode(key).decode()}"


KEY_2048 = record(spki(2048))
KEY_1024 = record(spki(1024))


async def scan(
    zone: Zone, selectors: list[str], backed: dict[str, Claim] | None = None
) -> Observed:
    return await dkim.collect(context(zone), "example.com", selectors, backed or {})


async def test_a_key_behind_a_cname_is_the_service_hosting_it() -> None:
    zone = (
        Zone()
        .alias("k2._domainkey.example.com", "dkim2.mcsv.net")
        .add("dkim2.mcsv.net", "TXT", KEY_2048)
    )
    observed = await scan(zone, ["k2"])
    assert [(c.service, c.kind) for c in observed.claims] == [("Mailchimp", Kind.DKIM_CNAME)]


async def test_a_key_known_by_name_is_only_likely() -> None:
    zone = Zone().add("mandrill._domainkey.example.com", "TXT", KEY_2048)
    observed = await scan(zone, ["mandrill"])
    assert [(c.service, c.kind) for c in observed.claims] == [("Mandrill", Kind.DKIM_NAME)]


async def test_a_key_nobody_can_name_is_listed() -> None:
    zone = Zone().add("default._domainkey.example.com", "TXT", KEY_2048)
    observed = await scan(zone, ["default"])
    assert observed.claims == ()
    assert [u.value for u in observed.unknowns] == ["default"]


async def test_a_revoked_key_is_an_account_trace() -> None:
    zone = Zone().add("mandrill._domainkey.example.com", "TXT", "v=DKIM1; p=")
    observed = await scan(zone, ["mandrill"])
    assert [c.kind for c in observed.claims] == [Kind.DKIM_REVOKED]


async def test_a_cname_to_nowhere_is_a_risk() -> None:
    zone = Zone().alias("s1._domainkey.example.com", "s1.domainkey.u1.wl1.sendgrid.net")
    observed = await scan(zone, ["s1"])
    assert [c.kind for c in observed.claims] == [Kind.DKIM_DANGLING]
    assert observed.findings[0].severity is Severity.RISK


async def test_a_wildcard_makes_every_key_meaningless() -> None:
    zone = Zone().add("*._domainkey.example.com", "TXT", KEY_2048)
    observed = await scan(zone, ["k1", "s1"])
    assert observed.claims == ()
    assert "wildcard" in observed.findings[0].detail
    assert observed.findings[0].evidence[0].name == "*._domainkey.example.com"


@pytest.mark.parametrize("bits", [512, 1024, 1536, 2048])
def test_an_rsa_key_reports_the_length_of_its_modulus(bits: int) -> None:
    key = dkim.Key("s", "s._domainkey.example.com", record(spki(bits)), ())
    assert key.bits == bits
    assert f", {bits}-bit" in key.summary()


def test_a_bare_rsa_public_key_is_read_too() -> None:
    assert dkim.Key("s", "s._domainkey.example.com", record(rsa_public_key(2048)), ()).bits == 2048


def test_an_ed25519_key_is_256_bits_by_its_type() -> None:
    key = dkim.Key("s", "s._domainkey.example.com", record(bytes(32), "ed25519"), ())
    assert key.bits == 256


@pytest.mark.parametrize("p", ["A" * 392, "not base64!", base64.b64encode(b"\x30\x05").decode()])
def test_a_key_that_does_not_parse_says_its_size_could_not_be_read(p: str) -> None:
    key = dkim.Key("s", "s._domainkey.example.com", f"v=DKIM1; k=rsa; p={p}", ())
    assert key.bits is None
    assert "could not read key size" in key.summary()


@pytest.mark.parametrize(
    ("bits", "severity"), [(512, Severity.RISK), (1024, Severity.WARNING), (1536, None)]
)
async def test_an_rsa_key_of_1024_bits_or_fewer_is_flagged(bits: int, severity: Severity) -> None:
    zone = Zone().add("mandrill._domainkey.example.com", "TXT", record(spki(bits)))
    observed = await scan(zone, ["mandrill"])
    flagged = [f.severity for f in observed.findings if f"{bits}-bit" in f.title]
    assert flagged == ([severity] if severity else [])


async def test_failed_lookups_are_a_gap() -> None:
    zone = Zone(failing={"k1._domainkey.example.com"})
    observed = await scan(zone, ["k1"])
    assert observed.gaps


def test_a_fingerprint_is_sha256_over_the_decoded_key() -> None:
    key = spki(2048)
    p = base64.b64encode(key).decode()
    assert dkim.fingerprint(p) == hashlib.sha256(key).hexdigest()[:16]
    assert dkim.fingerprint(f"{p[:40]} {p[40:]}") == dkim.fingerprint(p)  # split TXT strings
    assert dkim.fingerprint("") is None
    assert dkim.fingerprint("not base64!") is None


def test_the_summary_shows_the_flags_and_the_fingerprint() -> None:
    p = base64.b64encode(spki(2048)).decode()
    key = dkim.Key("s", "s._domainkey.example.com", f"v=DKIM1; t=y:s; h=sha256; s=email; p={p}", ())
    assert key.flags == {"y", "s"} and key.hashes == {"sha256"} and key.services == {"email"}
    summary = key.summary()
    assert "t=y:s (testing, strict)" in summary and "h=sha256" in summary and "s=email" in summary
    assert f", 2048-bit, fp {dkim.fingerprint(p)}" in summary


def test_a_revoked_key_has_no_fingerprint() -> None:
    key = dkim.Key("s", "s._domainkey.example.com", "v=DKIM1; t=y; p=", ())
    assert key.fingerprint is None and "fp " not in key.summary()


P_2048 = base64.b64encode(spki(2048)).decode()


@pytest.mark.parametrize(
    ("record", "severity"),
    [
        (f"v=DKIM1; t=y; p={P_2048}", Severity.WARNING),
        (f"v=DKIM1; h=sha1; p={P_2048}", Severity.RISK),
        (f"v=DKIM1; s=tlsrpt; p={P_2048}", Severity.WARNING),
        (f"v=DKIM1; k=dsa; p={P_2048}", Severity.WARNING),
        (record(bytes(31), "ed25519"), Severity.WARNING),
        ("v=DKIM1; k=ed25519; p=not base64!", Severity.WARNING),
    ],
)
async def test_each_flag_is_a_finding_carrying_the_key(record: str, severity: Severity) -> None:
    zone = Zone().add("mandrill._domainkey.example.com", "TXT", record)
    observed = await scan(zone, ["mandrill"])
    (finding,) = observed.findings
    assert finding.severity is severity
    (evidence,) = finding.evidence
    assert evidence == observed.claims[0].evidence


@pytest.mark.parametrize(
    "record",
    [
        f"v=DKIM1; t=s; h=sha1:sha256; s=email:tlsrpt; p={P_2048}",
        f"v=DKIM1; s=*; p={P_2048}",
        record(bytes(32), "ed25519"),
    ],
)
async def test_a_usable_key_raises_no_flag(record: str) -> None:
    zone = Zone().add("mandrill._domainkey.example.com", "TXT", record)
    assert (await scan(zone, ["mandrill"])).findings == ()


async def test_a_revoked_key_raises_no_flag() -> None:
    zone = Zone().add(
        "mandrill._domainkey.example.com", "TXT", "v=DKIM1; t=y; h=sha1; s=x; k=x; p="
    )
    observed = await scan(zone, ["mandrill"])
    assert observed.findings == () and observed.keys == ()
    assert [c.kind for c in observed.claims] == [Kind.DKIM_REVOKED]


async def test_each_key_read_is_kept_with_its_fingerprint() -> None:
    zone = (
        Zone()
        .add("k1._domainkey.example.com", "TXT", KEY_2048)
        .add("s1._domainkey.example.com", "TXT", KEY_2048)
    )
    observed = await scan(zone, ["k1", "s1"])
    assert [(k.selector, k.fingerprint) for k in observed.keys] == [
        ("k1", dkim.fingerprint(P_2048)),
        ("s1", dkim.fingerprint(P_2048)),
    ]
    assert dkim.same_keys(observed.keys)[0].evidence == tuple(k.evidence for k in observed.keys)


async def test_one_key_at_two_selectors_is_a_note_in_the_map(offline: httpx.AsyncClient) -> None:
    zone = (
        Zone()
        .add("k1._domainkey.acme.test", "TXT", KEY_2048)
        .add("s1._domainkey.acme.test", "TXT", KEY_2048)
        .add("s2._domainkey.acme.test", "TXT", KEY_1024)
    )
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False
    )
    (same,) = [f for f in result.findings if "same key" in f.title]
    assert same.severity is Severity.NOTE
    assert [e.name for e in same.evidence] == ["k1._domainkey.acme.test", "s1._domainkey.acme.test"]
