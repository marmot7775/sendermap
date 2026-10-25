"""The matching rules, each with the live case that taught it."""

from sendermap import catalog

C = catalog.load()


def test_patterns_match_on_label_boundaries() -> None:
    assert C.spf("sendgrid.net") == "SendGrid"
    assert C.spf("u123.wl.sendgrid.net") == "SendGrid"
    assert C.spf("sendgrid.net.evil.example") is None
    assert C.spf("notsendgrid.net") is None


def test_the_longest_pattern_wins() -> None:
    # glossier.com, kotn.com: kl and kl2 alias into Klaviyo's own SendGrid account.
    assert C.dkim_cname(["kl.domainkey.u161779.wl030.sendgrid.net"]) == "Klaviyo"
    assert C.dkim_cname(["s1.domainkey.u246655.wl156.sendgrid.net"]) == "SendGrid"


def test_a_dkim_key_belongs_to_its_cname_first() -> None:
    assert C.dkim_key("k1", ("dkim.mcsv.net",), backed="Mailgun") == "Mailchimp"


def test_selector1_names_nobody_without_the_microsoft_cname() -> None:
    assert C.dkim_key("selector1", (), backed=None) is None
    chain = ("selector1-example-com._domainkey.example.onmicrosoft.com",)
    assert C.dkim_key("selector1", chain, backed=None) == "Microsoft 365"


def test_backing_beats_the_name_table() -> None:
    # k1 on a Mailgun domain is Mailgun's key, not Mailchimp's.
    assert C.dkim_key("k1", (), backed="Mailgun") == "Mailgun"
    assert C.dkim_key("k1", (), backed=None) == "Mailchimp"


def test_generic_names_credit_nobody_on_their_own() -> None:
    for name in ("default", "mail", "s", "ab", "dkim"):
        assert C.dkim_key(name, (), backed=None) is None, name
    assert not C.is_generic("k1")  # two letters, but kept by name


def test_a_token_needs_a_value() -> None:
    assert C.token("mgverify=0123456789abcdef") == "Mailgun"
    assert C.token("mgverify=") is None
    assert C.token("ms=ms12345678") == "Microsoft 365"


def test_tracking_labels_prefer_the_tracking_table() -> None:
    assert C.label_cname("links", "e.customeriomail.com") == ("Customer.io", "tracking")
    assert C.label_cname("bounce", "sparkpostmail.com") == ("SparkPost", "return path")
    assert C.label_cname("autodiscover", "autodiscover.outlook.com") == (
        "Microsoft 365",
        "autodiscover",
    )
    assert C.label_cname("bounce", "example.net") is None


def test_a_web_host_is_a_website_except_at_a_tracking_label() -> None:
    assert C.is_website("mail", "ghs.googlehosted.com")
    assert C.is_website("EM", "em.dell.com.edgekey.net")
    assert not C.is_website("link", "d15y5qe1i4b8ob.cloudfront.net")  # a CDN can serve clicks
    assert not C.is_website("mail", "mailrelay.us-west-2.elb.amazonaws.com")
    assert not C.is_website("mail", "googlehosted.com.evil.example")


def test_website_signatures_match_hosts_and_their_subdomains_only() -> None:
    page = '<script src="https://eu1.static.zdassets.com/x.js"></script> notstatic.zdassets.com'
    loaded = ["eu1.static.zdassets.com"]
    assert C.website_services(page, loaded) == {"Zendesk": ("eu1.static.zdassets.com", True)}
    assert C.website_services("<p>static.klaviyo.comics</p>", []) == {}
    assert C.website_services("", ["notstatic.zdassets.com"]) == {}


def test_a_host_the_page_does_not_load_from_is_only_mentioned() -> None:
    page = '<a href="https://cdn.shopify.com/s/files/terms.pdf">Terms</a>'
    assert C.website_services(page, []) == {"Shopify": ("cdn.shopify.com", False)}


def test_every_service_has_a_category() -> None:
    data = C.services
    assert all(block.get("category") for block in data.values())


def test_published_ranges_are_read_from_published_spf_where_a_block_names_it() -> None:
    sources = catalog.load().spf_sources()
    assert sources["HubSpot"] == ["hubspotemail.net"]
    assert sources["Mimecast"] == ["_netblocks.mimecast.com"]
    assert "sendgrid.net" in sources["SendGrid"]


def test_inbound_mx_from_the_0_1_7_benchmark() -> None:
    # eu.wxpcollaboration.hp.com and foundry.openai.com receive through SES; community.openai.com
    # and community.f5.com are Discourse forums whose replies arrive at discoursemail.com.
    assert C.mx("inbound-smtp.eu-central-1.amazonaws.com") == "Amazon SES"
    assert C.mx("inbound-smtp.us-gov-west-1.amazonaws.com") == "Amazon SES"
    assert C.mx("mx-corp1.discoursemail.com") == "Discourse"
    assert C.mx("inbound-smtp.eu-central-1.amazonaws.com.evil.example") is None
