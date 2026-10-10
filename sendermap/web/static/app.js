"use strict";

// Every string that came from DNS or a web page goes into the page as text, never as markup.

const TIERS = [
  { name: "In use", key: "in-use", radius: 118 },
  { name: "Configured", key: "configured", radius: 196 },
  { name: "Likely", key: "likely", radius: 258 },
  { name: "Account only", key: "account", radius: 312 },
];
const TIER = Object.fromEntries(TIERS.map((t) => [t.name, t]));
const CATEGORIES = ["Mailbox", "Security gateway", "Marketing", "Transactional",
  "Support and CRM", "Commerce and apps", "DMARC reporting", "Other"];
const SVG = "http://www.w3.org/2000/svg";
const $ = (id) => document.getElementById(id);

let current = null;
let source = null;

document.addEventListener("DOMContentLoaded", () => {
  $("lookup").addEventListener("submit", (e) => {
    e.preventDefault();
    start($("domain").value);
  });
  $("copy-link").addEventListener("click", () => copy(shareLink(), "copy-link", "Link copied"));
  $("copy-md").addEventListener("click", copyMarkdown);
  $("download").addEventListener("click", download);
  window.addEventListener("popstate", fromUrl);
  fromUrl();
});

function fromUrl() {
  const d = new URLSearchParams(location.search).get("d");
  if (d) {
    $("domain").value = d;
    start(d, false);
  }
}

function start(text, push = true) {
  const domain = text.trim();
  if (!domain) return;
  if (source) source.close();
  if (push) history.pushState(null, "", `/?d=${encodeURIComponent(domain)}`);
  show("progress"); hide("result"); hide("error");
  $("step").textContent = "Starting";
  source = new EventSource(`/api/map/stream?d=${encodeURIComponent(domain)}`);
  source.addEventListener("progress", (e) => { $("step").textContent = JSON.parse(e.data).step; });
  source.addEventListener("map", (e) => { source.close(); render(JSON.parse(e.data)); });
  source.addEventListener("failed", (e) => { source.close(); fail(JSON.parse(e.data).error); });
  source.onerror = async () => {
    source.close();
    const reply = await fetch(`/api/map?d=${encodeURIComponent(domain)}`);
    if (reply.ok) render(await reply.json());
    else fail((await reply.json().catch(() => ({}))).detail || "The map could not be built.");
  };
}

function fail(message) {
  hide("progress");
  $("error").textContent = typeof message === "string" ? message : "That does not look like a domain.";
  show("error");
}

// ------------------------------------------------------------------ the result

function render(map) {
  current = map;
  hide("progress");
  document.title = `${map.domain}: Sendermap`;
  $("result-domain").textContent = map.domain;
  const senders = map.services.filter((s) => s.role === "sender");
  const reporting = map.services.filter((s) => s.role === "reporting");
  $("summary").textContent = summary(map.domain, senders, reporting);
  const logo = $("logo");
  if (map.logo) { logo.src = map.logo; logo.hidden = false; } else { logo.hidden = true; }

  drawMap(map.domain, senders);
  renderServices(senders, map.domain);
  renderReporting(reporting, map.domain);
  renderAttention(map.findings);
  renderUnknowns(map.unknowns, map.domain);
  renderFootnote(map);
  show("result");
  $("result").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
}

function summary(domain, senders, reporting) {
  if (!senders.length) return `No sending services found in ${domain}'s public records.`;
  const n = senders.length;
  let text = `${domain} sends through ${n} service${n === 1 ? "" : "s"}`;
  const inUse = senders.filter((s) => s.tier === "In use").map((s) => s.name);
  if (inUse.length) text += `, with mail delivered to ${list(inUse)}`;
  text += ".";
  if (reporting.length) text += ` Reports go to ${list(reporting.map((s) => s.name))}.`;
  return text;
}

function list(items) {
  return items.length < 3 ? items.join(" and ") : `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`;
}

// ------------------------------------------------------------------ the map

function drawMap(domain, senders) {
  const svg = $("map");
  svg.replaceChildren();
  svg.setAttribute("aria-label", `Map of ${senders.length} services sending as ${domain}`);
  const C = 360;

  for (const tier of TIERS) svg.append(el("circle", { class: "ring", cx: C, cy: C, r: tier.radius }));

  const groups = CATEGORIES.map((c) => ({ category: c, items: senders.filter((s) => (CATEGORIES.includes(s.category) ? s.category : "Other") === c) }))
    .filter((g) => g.items.length);
  const total = groups.reduce((n, g) => n + Math.max(g.items.length, 1.5), 0);
  const gap = groups.length > 1 ? 0.1 : 0;
  let angle = -Math.PI / 2 + gap / 2;
  const nodes = [];

  for (const group of groups) {
    const width = (2 * Math.PI - gap * groups.length) * Math.max(group.items.length, 1.5) / total;
    const ordered = [...group.items].sort((a, b) => TIER[a.tier].radius - TIER[b.tier].radius || a.name.localeCompare(b.name));
    ordered.forEach((service, i) => {
      const a = angle + (width * (i + 0.5)) / ordered.length;
      nodes.push({ service, a, r: TIER[service.tier].radius });
    });
    if (groups.length > 1) {
      const edge = angle - gap / 2;
      svg.append(el("line", { class: "divider", x1: C + Math.cos(edge) * 64, y1: C + Math.sin(edge) * 64, x2: C + Math.cos(edge) * 336, y2: C + Math.sin(edge) * 336 }));
    }
    const mid = angle + width / 2;
    const lx = C + Math.cos(mid) * 350, ly = C + Math.sin(mid) * 350;
    svg.append(el("text", { class: "sector-label", x: lx, y: ly + 4, "text-anchor": anchor(mid) }, group.category));
    angle += width + gap;
  }

  for (const n of nodes) {
    svg.append(el("line", { class: "spoke", x1: C, y1: C, x2: C + Math.cos(n.a) * n.r, y2: C + Math.sin(n.a) * n.r }));
  }
  svg.append(el("circle", { class: "core", cx: C, cy: C, r: 50 }));
  svg.append(el("text", { class: "core-text", x: C, y: C + 5, "text-anchor": "middle" }, shorten(domain, 15)));

  const labels = placeLabels(nodes, C);
  nodes.forEach((n, i) => {
    const x = C + Math.cos(n.a) * n.r, y = C + Math.sin(n.a) * n.r;
    const g = el("g", { class: "node", tabindex: 0, role: "button", "aria-label": `${n.service.name}, ${n.service.tier}` });
    g.append(el("title", {}, `${n.service.name}: ${n.service.tier}, ${n.service.claims[0].kind}`));
    g.append(el("circle", { cx: x, cy: y, r: 17, class: `t-${TIER[n.service.tier].key}` }));
    g.append(el("text", { class: "initials", x, y: y + 4, "text-anchor": "middle" }, initials(n.service.name)));
    const label = labels[i];
    g.append(el("text", { class: "name", x: label.x, y: label.y, "text-anchor": label.anchor }, n.service.name));
    const go = () => focusCard(n.service.name);
    g.addEventListener("click", go);
    g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
    svg.append(g);
  });
}

// Labels sit just outside their node. Where two would overlap, the later one moves outward
// along its spoke until it clears; a few passes settle even a crowded ring.
function placeLabels(nodes, C) {
  const labels = nodes.map((n) => ({ a: n.a, out: n.r + 26, anchor: anchor(n.a), width: n.service.name.length * 7.8 + 6 }));
  const box = (l) => {
    const x = C + Math.cos(l.a) * l.out, y = C + Math.sin(l.a) * l.out + 4;
    const left = l.anchor === "start" ? x : l.anchor === "end" ? x - l.width : x - l.width / 2;
    return { x, y, left, right: left + l.width, top: y - 12, bottom: y + 4 };
  };
  const hits = (p, q) => p.left < q.right && q.left < p.right && p.top < q.bottom && q.top < p.bottom;
  for (let pass = 0; pass < 40; pass++) {
    let moved = false;
    for (let i = 0; i < labels.length; i++) {
      for (let j = i + 1; j < labels.length; j++) {
        if (hits(box(labels[i]), box(labels[j]))) { labels[j].out += 8; moved = true; }
      }
    }
    if (!moved) break;
  }
  return labels.map((l) => ({ ...box(l), anchor: l.anchor }));
}

function anchor(a) {
  const c = Math.cos(a);
  return c > 0.2 ? "start" : c < -0.2 ? "end" : "middle";
}

// Two letters that tell services apart: SendGrid SG, Mailchimp MC, Mailgun MG, Microsoft 365 M3.
function initials(name) {
  const words = name.replace(/[^A-Za-z0-9 ]/g, " ").split(/\s+/).filter(Boolean);
  if (words.length > 1) return (words[0][0] + words[1][0]).toUpperCase();
  const word = words[0] || name;
  const capital = word.slice(1).search(/[A-Z]/);
  if (capital >= 0) return (word[0] + word[capital + 1]).toUpperCase();
  const stem = word.match(/^(mail|man|send|post|spark|zen|fresh)(.)/i);
  return (stem ? word[0] + stem[2] : word.slice(0, 2)).toUpperCase();
}

function shorten(text, max) {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function focusCard(name) {
  const card = document.querySelector(`[data-service="${CSS.escape(name)}"]`);
  if (!card) return;
  card.scrollIntoView({ behavior: "smooth", block: "center" });
  card.classList.add("flash");
  setTimeout(() => card.classList.remove("flash"), 1600);
}

// ------------------------------------------------------------------ the evidence

function renderServices(senders, domain) {
  const box = $("services");
  box.replaceChildren();
  for (const tier of TIERS) {
    const group = senders.filter((s) => s.tier === tier.name);
    if (!group.length) continue;
    box.append(h("h3", { class: "section-title" }, tier.name));
    const cards = h("div", { class: "cards" });
    group.forEach((s) => cards.append(card(s, domain, `b-${tier.key}`, tier.name)));
    box.append(cards);
  }
}

function renderReporting(reporting, domain) {
  const box = $("reporting");
  box.replaceChildren();
  if (!reporting.length) return;
  box.append(h("h3", { class: "section-title" }, "Reports go to"));
  const cards = h("div", { class: "cards" });
  reporting.forEach((s) => cards.append(card(s, domain, "b-reporting", "Reporting")));
  box.append(cards);
}

function card(service, domain, badgeClass, badgeText) {
  const c = h("article", { class: "card", "data-service": service.name });
  const head = h("div", { class: "card-head" }, h("h3", {}, service.name), h("span", { class: `badge ${badgeClass}` }, badgeText));
  c.append(head, h("p", { class: "meta" }, service.category));
  const where = [...new Set(service.claims.map((cl) => cl.where))].filter((w) => w !== domain);
  if (where.length) {
    const chips = h("p", { class: "meta" }, "Also at ");
    where.forEach((w) => chips.append(h("span", { class: "chip mono" }, w)));
    c.append(chips);
  }
  const ul = h("ul", { class: "claims" });
  service.claims.forEach((claim, i) => {
    const at = claim.where === domain ? "" : ` at ${claim.where}`;
    const li = h("li", { class: i === 0 ? "decider" : "" },
      h("span", { class: "kind" }, claim.kind + at),
      h("span", { class: "ev mono" }, evidence(claim.evidence)));
    if (i >= 3) li.hidden = true;
    ul.append(li);
  });
  c.append(ul);
  if (service.claims.length > 3) {
    const more = h("button", { class: "more", type: "button" }, `Show all ${service.claims.length}`);
    more.addEventListener("click", () => { ul.querySelectorAll("li").forEach((li) => { li.hidden = false; }); more.remove(); });
    c.append(more);
  }
  return c;
}

function evidence(e) {
  return `${e.name} ${e.rtype} ${e.value}`;
}

function renderAttention(findings) {
  const box = $("attention");
  box.replaceChildren();
  if (!findings.length) return;
  box.append(h("h3", { class: "section-title" }, "Needs attention"));
  for (const f of findings) {
    const body = h("div", {}, h("h3", {}, f.title), h("p", {}, f.detail));
    f.evidence.slice(0, 2).forEach((e) => body.append(h("span", { class: "ev mono" }, evidence(e))));
    box.append(h("div", { class: `finding ${f.severity}` }, body));
  }
}

function renderUnknowns(unknowns, domain) {
  const box = $("unknowns");
  box.replaceChildren();
  if (!unknowns.length) return;
  box.append(h("h3", { class: "section-title" }, "Not recognised"));
  const d = h("details", { class: "unknowns" }, h("summary", {}, `${unknowns.length} record${unknowns.length === 1 ? "" : "s"} that point at a sender nobody can name yet`));
  const ul = h("ul");
  unknowns.forEach((u) => ul.append(h("li", {}, `${u.what}: `, h("span", { class: "mono" }, u.value), u.where === domain ? "" : ` at ${u.where}`)));
  d.append(ul);
  box.append(d);
}

function renderFootnote(map) {
  const subs = map.subdomains_checked.length;
  let text = `${map.run.lookups} DNS lookups in ${map.run.elapsed.toFixed(1)} s. Checked ${map.domain}`;
  text += subs ? ` and ${subs} sending subdomain${subs === 1 ? "" : "s"}.` : ".";
  for (const gap of map.gaps) text += ` Not checked: ${gap.what} (${gap.why}).`;
  $("footnote").textContent = text;
}

// ------------------------------------------------------------------ sharing

function shareLink() {
  return `${location.origin}/?d=${encodeURIComponent(current ? current.domain : "")}`;
}

async function copyMarkdown() {
  if (!current) return;
  const reply = await fetch(`/api/map.md?d=${encodeURIComponent(current.domain)}`);
  if (reply.ok) copy(await reply.text(), "copy-md", "Markdown copied");
}

function download() {
  if (!current) return;
  const blob = new Blob([JSON.stringify(current, null, 2)], { type: "application/json" });
  const a = h("a", { href: URL.createObjectURL(blob), download: `sendermap-${current.domain}.json` });
  a.click();
  URL.revokeObjectURL(a.href);
}

async function copy(text, id, done) {
  const button = $(id);
  const label = button.textContent;
  try { await navigator.clipboard.writeText(text); button.textContent = done; } catch { button.textContent = "Copy failed"; }
  setTimeout(() => { button.textContent = label; }, 1600);
}

// ------------------------------------------------------------------ helpers

function el(tag, attrs = {}, text) {
  const node = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (text !== undefined) node.textContent = text;
  return node;
}

function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== "") node.setAttribute(k, v);
  for (const child of children) node.append(child);
  return node;
}

function show(id) { $(id).hidden = false; }
function hide(id) { $(id).hidden = true; }
