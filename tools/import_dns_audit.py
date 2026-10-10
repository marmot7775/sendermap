"""One-time import of the vendor tables in dns-audit (MIT) into
data/vendors.json, one block per vendor. After the import, data/vendors.json
is the source; this script is kept to show where the data came from and to
compare against later dns-audit versions.

Usage: python tools/import_dns_audit.py /path/to/dns-audit > data/vendors.json
"""
import json
import subprocess
import sys

repo = sys.argv[1]
sys.path.insert(0, repo)
import vendor_patterns as vp  # noqa: E402
import comprehensive_selectors as cs  # noqa: E402

CATEGORY = {
    "Mailbox": ["Google Workspace", "Microsoft 365", "Outlook.com (consumer)", "Zoho Mail", "Fastmail",
                "Proton Mail", "Rackspace Email", "GoDaddy Professional Email", "IONOS",
                "Cloudflare Email Routing"],
    "Security gateway": ["Proofpoint", "Mimecast", "Barracuda", "Symantec MessageLabs", "DuoCircle"],
    "Marketing": ["Mailchimp", "Klaviyo", "Brevo", "Campaign Monitor", "Constant Contact", "AWeber",
                  "ActiveCampaign", "MailerLite", "Kit", "GetResponse", "Emma", "Omnisend", "MailPoet",
                  "Zoho Campaigns", "Sailthru", "Iterable", "Braze", "Customer.io", "Marketo",
                  "Salesforce Marketing Cloud Engagement", "Salesforce Account Engagement", "HubSpot",
                  "Keap", "Everlytic", "GoDaddy Websites + Marketing", "Elastic Email"],
    "Transactional": ["SendGrid", "Mailgun", "Postmark", "SparkPost", "Amazon SES", "Mandrill", "Mailjet",
                      "Resend", "Pepipost", "Omnivery", "Omnivery/Mailkit", "Firebase"],
    "Support and CRM": ["Zendesk", "Freshdesk", "Help Scout", "Intercom", "Gorgias", "Salesforce",
                        "Pipedrive"],
    "Commerce and apps": ["Shopify", "Square", "Squarespace", "Wix", "Stripe", "Calendly", "Atlassian"],
    "DMARC reporting": ["DMARCian", "Agari", "Valimail", "Red Sift OnDMARC", "EasyDMARC", "PowerDMARC",
                        "URIports", "Cloudflare DMARC Management", "Mimecast DMARC Analyzer", "GlockApps"],
}
cat_of = {v: c for c, vs in CATEGORY.items() for v in vs}

vendors = {}


def add(name, field, value):
    if name == "Generic":
        return
    v = vendors.setdefault(name, {})
    v.setdefault(field, [])
    if value not in v[field]:
        v[field].append(value)


for field, table in (("spf_includes", vp.SPF_INCLUDE_VENDORS), ("mx", vp.MX_VENDORS),
                     ("dkim_cname", vp.DKIM_CNAME_VENDORS), ("dkim_selectors", vp.DKIM_SELECTOR_VENDORS),
                     ("reporting", vp.REPORTING_VENDORS), ("return_path", vp.RETURN_PATH_VENDORS),
                     ("tracking", vp.TRACKING_VENDORS)):
    for pattern, name in table.items():
        add(name, field, pattern)
for pattern, name in vp.VERIFICATION_TXT_VENDORS:
    add(name, "verification_txt", pattern)
for label, table in vp.OTHER_CNAME_VENDORS.items():
    for pattern, name in table.items():
        add(name, "other_cname", {"label": label, "target": pattern})

missing = sorted(n for n in vendors if n not in cat_of)
if missing:
    sys.exit(f"no category for: {missing}")
for name, v in vendors.items():
    v["category"] = cat_of[name]
    for k in v:
        if isinstance(v[k], list) and all(isinstance(x, str) for x in v[k]):
            v[k] = sorted(v[k])

commit = subprocess.run(["git", "-C", repo, "rev-parse", "--short", "HEAD"],
                        capture_output=True, text=True).stdout.strip()
probe = sorted(set(vp.DKIM_SELECTOR_VENDORS) | set(cs.ESP_SELECTORS)
               | {"default", "selector1", "selector2", "google", "dkim", "mail", "s1", "s2", "k1", "k2", "k3"})
out = {
    "about": ("Email services recognisable from a domain's own DNS. One block per vendor; "
              f"imported from dns-audit (MIT) at {commit}. Hostname patterns match the host "
              "itself or any name under it, and the longest match wins."),
    "categories": list(CATEGORY),
    "rules": {
        "generic_selectors": sorted(vp.GENERIC_SELECTORS),
        "short_selectors_allowed": sorted(vp.SHORT_SELECTORS_ALLOWED),
        "cname_only_selectors": sorted(vp._CNAME_ONLY_SELECTORS),
        "hosted_spf": sorted(vp.HOSTED_SPF_VENDORS),
        "cname_labels": list(vp.VENDOR_CNAME_LABELS),
        "tracking_labels": sorted(vp.TRACKING_LABELS),
        "probe_selectors": probe,
    },
    "vendors": dict(sorted(vendors.items(), key=lambda kv: kv[0].lower())),
}
print(json.dumps(out, indent=2, ensure_ascii=False))
