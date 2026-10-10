"""The DKIM scan: who holds each key, and what the keys say."""

import base64

import pytest
from conftest import Zone, context

from sendermap.model import Kind, Severity
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


async def scan(zone: Zone, selectors, backed=None):
    return await dkim.collect(context(zone), "example.com", selectors, backed or {})


async def test_a_key_behind_a_cname_is_the_service_hosting_it():
    zone = (
        Zone()
        .alias("k2._domainkey.example.com", "dkim2.mcsv.net")
        .add("dkim2.mcsv.net", "TXT", KEY_2048)
    )
    observed = await scan(zone, ["k2"])
    assert [(c.service, c.kind) for c in observed.claims] == [("Mailchimp", Kind.DKIM_CNAME)]


async def test_a_key_known_by_name_is_only_likely():
    zone = Zone().add("mandrill._domainkey.example.com", "TXT", KEY_2048)
    observed = await scan(zone, ["mandrill"])
    assert [(c.service, c.kind) for c in observed.claims] == [("Mandrill", Kind.DKIM_NAME)]


async def test_a_key_nobody_can_name_is_listed():
    zone = Zone().add("default._domainkey.example.com", "TXT", KEY_2048)
    observed = await scan(zone, ["default"])
    assert observed.claims == ()
    assert [u.value for u in observed.unknowns] == ["default"]


async def test_a_retired_key_is_an_account_trace():
    zone = Zone().add("mandrill._domainkey.example.com", "TXT", "v=DKIM1; p=")
    observed = await scan(zone, ["mandrill"])
    assert [c.kind for c in observed.claims] == [Kind.DKIM_RETIRED]


async def test_a_cname_to_nowhere_is_a_risk():
    zone = Zone().alias("s1._domainkey.example.com", "s1.domainkey.u1.wl1.sendgrid.net")
    observed = await scan(zone, ["s1"])
    assert [c.kind for c in observed.claims] == [Kind.DKIM_DANGLING]
    assert observed.findings[0].severity is Severity.RISK


async def test_a_wildcard_makes_every_key_meaningless():
    zone = Zone().add("*._domainkey.example.com", "TXT", KEY_2048)
    observed = await scan(zone, ["k1", "s1"])
    assert observed.claims == ()
    assert "wildcard" in observed.findings[0].detail
    assert observed.findings[0].evidence[0].name == "*._domainkey.example.com"


@pytest.mark.parametrize("bits", [512, 1024, 1536, 2048])
def test_an_rsa_key_reports_the_length_of_its_modulus(bits):
    key = dkim.Key("s", "s._domainkey.example.com", record(spki(bits)), ())
    assert key.bits == bits
    assert f", {bits}-bit" in key.summary()


def test_a_bare_rsa_public_key_is_read_too():
    assert dkim.Key("s", "s._domainkey.example.com", record(rsa_public_key(2048)), ()).bits == 2048


def test_an_ed25519_key_is_256_bits_by_its_type():
    key = dkim.Key("s", "s._domainkey.example.com", record(bytes(32), "ed25519"), ())
    assert key.bits == 256


@pytest.mark.parametrize("p", ["A" * 392, "not base64!", base64.b64encode(b"\x30\x05").decode()])
def test_a_key_that_does_not_parse_says_its_size_could_not_be_read(p):
    key = dkim.Key("s", "s._domainkey.example.com", f"v=DKIM1; k=rsa; p={p}", ())
    assert key.bits is None
    assert "could not read key size" in key.summary()


@pytest.mark.parametrize(
    ("bits", "severity"), [(512, Severity.RISK), (1024, Severity.WARNING), (1536, None)]
)
async def test_an_rsa_key_of_1024_bits_or_fewer_is_flagged(bits, severity):
    zone = Zone().add("mandrill._domainkey.example.com", "TXT", record(spki(bits)))
    observed = await scan(zone, ["mandrill"])
    flagged = [f.severity for f in observed.findings if f"{bits}-bit" in f.title]
    assert flagged == ([severity] if severity else [])


async def test_failed_lookups_are_a_gap():
    zone = Zone(failing={"k1._domainkey.example.com"})
    observed = await scan(zone, ["k1"])
    assert observed.gaps
