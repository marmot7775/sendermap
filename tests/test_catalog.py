"""The matching rules, each with the live case that taught it."""

from sendermap import catalog

C = catalog.load()


def test_patterns_match_on_label_boundaries():
    assert C.spf("sendgrid.net") == "SendGrid"
    assert C.spf("u123.wl.sendgrid.net") == "SendGrid"
    assert C.spf("sendgrid.net.evil.example") is None
    assert C.spf("notsendgrid.net") is None


def test_the_longest_pattern_wins():
    # glossier.com, kotn.com: kl and kl2 alias into Klaviyo's own SendGrid account.
    assert C.dkim_cname(["kl.domainkey.u161779.wl030.sendgrid.net"]) == "Klaviyo"
    assert C.dkim_cname(["s1.domainkey.u246655.wl156.sendgrid.net"]) == "SendGrid"


def test_a_dkim_key_belongs_to_its_cname_first():
    assert C.dkim_key("k1", ("dkim.mcsv.net",), backed="Mailgun") == "Mailchimp"


def test_selector1_names_nobody_without_the_microsoft_cname():
    assert C.dkim_key("selector1", (), backed=None) is None
    chain = ("selector1-example-com._domainkey.example.onmicrosoft.com",)
    assert C.dkim_key("selector1", chain, backed=None) == "Microsoft 365"


def test_backing_beats_the_name_table():
    # k1 on a Mailgun domain is Mailgun's key, not Mailchimp's.
    assert C.dkim_key("k1", (), backed="Mailgun") == "Mailgun"
    assert C.dkim_key("k1", (), backed=None) == "Mailchimp"


def test_generic_names_credit_nobody_on_their_own():
    for name in ("default", "mail", "s", "ab", "dkim"):
        assert C.dkim_key(name, (), backed=None) is None, name
    assert not C.is_generic("k1")  # two letters, but kept by name


def test_a_token_needs_a_value():
    assert C.token("mgverify=0123456789abcdef") == "Mailgun"
    assert C.token("mgverify=") is None
    assert C.token("ms=ms12345678") == "Microsoft 365"


def test_tracking_labels_prefer_the_tracking_table():
    assert C.label_cname("links", "links.iterable.com") == ("Iterable", "tracking")
    assert C.label_cname("bounce", "sparkpostmail.com") == ("SparkPost", "return path")
    assert C.label_cname("autodiscover", "autodiscover.outlook.com") == (
        "Microsoft 365",
        "autodiscover",
    )
    assert C.label_cname("bounce", "example.net") is None


def test_website_signatures_match_hosts_and_their_subdomains_only():
    page = '<script src="https://us1.list-manage.com/x.js"></script> notlist-manage.com'
    assert C.website_services(page) == {"Mailchimp": "list-manage.com"}
    assert C.website_services("<p>static.klaviyo.comics</p>") == {}


def test_every_service_has_a_known_category():
    data = C.services
    assert all(block.get("category") for block in data.values())
