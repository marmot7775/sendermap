// Vendor matching rules over data/vendors.json. Pure functions, no DNS.
//
// Hostname patterns match the host itself or any name under it, on a label
// boundary, and the longest matching pattern wins: "sendgrid.net.evil.example"
// is not SendGrid, and u161779.wl030.sendgrid.net (Klaviyo's own SendGrid
// account) beats sendgrid.net.

const FIELDS = ["spf_includes", "mx", "dkim_cname", "dkim_selectors", "reporting", "return_path", "tracking"];

export function buildIndex(data) {
  const idx = { vendors: data.vendors, rules: data.rules, verification: [], other: {} };
  for (const f of FIELDS) idx[f] = {};
  for (const [name, v] of Object.entries(data.vendors)) {
    for (const f of FIELDS) for (const p of v[f] || []) idx[f][p.toLowerCase()] = name;
    for (const re of v.verification_txt || []) idx.verification.push([new RegExp("^" + re, "i"), name]);
    for (const o of v.other_cname || []) (idx.other[o.label] ||= {})[o.target] = name;
  }
  idx.generic = new Set(data.rules.generic_selectors);
  idx.shortAllowed = new Set(data.rules.short_selectors_allowed);
  idx.cnameOnly = new Set(data.rules.cname_only_selectors);
  idx.trackingLabels = new Set(data.rules.tracking_labels);
  idx.hostedSpf = new Set(data.rules.hosted_spf);
  return idx;
}

export function normHost(h) {
  return String(h || "").trim().toLowerCase().replace(/\.$/, "");
}

export function matchHost(host, table) {
  const h = normHost(host);
  if (!h) return null;
  let best = null;
  for (const [p, v] of Object.entries(table)) {
    if ((h === p || h.endsWith("." + p)) && (!best || p.length > best[0].length)) best = [p, v];
  }
  return best ? best[1] : null;
}

export function isGenericSelector(idx, sel) {
  const s = String(sel || "").toLowerCase();
  return idx.generic.has(s) || (s.length <= 2 && !idx.shortAllowed.has(s));
}

// The first hop of a DKIM CNAME chain that names a vendor, else the target.
export function dkimCnameVendor(idx, target, chain = []) {
  for (const hop of [...chain, target]) {
    const v = matchHost(hop, idx.dkim_cname);
    if (v) return v;
  }
  return null;
}

// Who a found DKIM key belongs to:
// 1. a CNAME into the vendor's zone, always;
// 2. selector1/selector2 name nobody without that CNAME (Microsoft 365);
// 3. "backed": a vendor this domain's SPF or MX already shows, whose
//    selector list has the name (k1 on a Mailgun domain is Mailgun);
// 4. the name table, unless the name is generic.
export function dkimKeyVendor(idx, selector, target, backed, chain) {
  const byCname = dkimCnameVendor(idx, target, chain);
  if (byCname) return byCname;
  const s = String(selector || "").toLowerCase();
  if (idx.cnameOnly.has(s)) return null;
  if (backed) return backed;
  if (isGenericSelector(idx, s)) return null;
  return idx.dkim_selectors[s] || null;
}

// [vendor, kind] for a CNAME at <label>.<domain>; kind is "tracking",
// "return path" or the label itself (autodiscover).
export function labelCnameVendor(idx, label, target) {
  const l = String(label || "").toLowerCase();
  if (idx.other[l]) {
    const v = matchHost(target, idx.other[l]);
    return v ? [v, l] : [null, null];
  }
  let order = [["tracking", idx.tracking], ["return path", idx.return_path]];
  if (!idx.trackingLabels.has(l)) order = order.reverse();
  for (const [kind, table] of order) {
    const v = matchHost(target, table);
    if (v) return [v, kind];
  }
  return [null, null];
}

export function matchVerificationTxt(idx, record) {
  const r = String(record || "").trim().toLowerCase();
  for (const [re, vendor] of idx.verification) {
    const m = re.exec(r);
    // A prefix with no token after it verifies nothing.
    if (m && r.slice(m[0].length).trim().length >= 4) return vendor;
  }
  return null;
}

// Domains of the mailto: addresses in the given tags of a DMARC or TLS-RPT
// record, in order, without repeats.
export function reportAddressDomains(record, tags = ["rua"]) {
  const out = [];
  for (const part of String(record || "").split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0 || !tags.includes(part.slice(0, eq).trim().toLowerCase())) continue;
    for (let uri of part.slice(eq + 1).split(",")) {
      uri = uri.trim();
      if (!/^mailto:/i.test(uri) || !uri.includes("@")) continue;
      const rcpt = uri.slice(7).split("?")[0].split("!")[0].trim();
      const at = rcpt.indexOf("@");
      if (at < 1 || rcpt.indexOf("@", at + 1) !== -1) continue;
      const d = normHost(rcpt.slice(at + 1));
      if (d && !out.includes(d)) out.push(d);
    }
  }
  return out;
}
