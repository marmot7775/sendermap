"use strict";

// Strings from DNS or a web page reach the page as HTML the server escaped (render/html.py),
// set as it came. The page adds nothing from the map as markup of its own: the ring map's
// labels go in as textContent.

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
// The ring map's figure, kept here because each new result replaces the fragment it sits in.
let figure = null;
// The services the domain's owner says they use, from the page's own ?claimed=, comma
// separated. The API reconciles them with the map; the page only passes them on.
let claimed = "";

document.addEventListener("DOMContentLoaded", () => {
  figure = $("map-wrap");
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
  const params = new URLSearchParams(location.search);
  const d = params.get("d");
  if (d) {
    $("domain").value = d;
    start(d, false, params.get("claimed") || "");
  }
}

// A domain typed into the form starts afresh: a claimed list belongs to the link that carried it.
function start(text, push = true, names = "") {
  const domain = text.trim();
  if (!domain) return;
  if (source) source.close();
  claimed = names;
  if (push) history.pushState(null, "", `/?${query(domain)}`);
  show("progress"); hide("result"); hide("error");
  $("step").textContent = "Starting";
  source = new EventSource(`/api/map/stream?${query(domain)}`);
  source.addEventListener("progress", (e) => { $("step").textContent = JSON.parse(e.data).step; });
  source.addEventListener("map", (e) => {
    source.close();
    const done = JSON.parse(e.data);
    render(done.map, done.html);
  });
  source.addEventListener("failed", (e) => { source.close(); fail(JSON.parse(e.data).error); });
  source.onerror = async () => {
    source.close();
    const reply = await fetch(`/api/map?${query(domain)}`);
    if (!reply.ok) return fail(await reason(reply));
    const map = await reply.json();
    const page = await fetch(`/api/map.html?${query(domain)}`);
    if (page.ok) render(map, await page.text());
    else fail(await reason(page));
  };
}

async function reason(reply) {
  return (await reply.json().catch(() => ({}))).detail || "The map could not be built.";
}

function query(domain) {
  return `d=${encodeURIComponent(domain)}${claimed ? `&claimed=${encodeURIComponent(claimed)}` : ""}`;
}

function fail(message) {
  hide("progress");
  $("error").textContent = typeof message === "string" ? message : "That does not look like a domain.";
  show("error");
}

// ------------------------------------------------------------------ the result

// The fragment is the View the command line shows. Its head moves into the result head beside
// the actions, and the ring map goes into the lead block beside the story, above Needs
// attention. A map with no story gets a lead block of its own for the figure.
function render(map, fragment) {
  current = map;
  hide("progress");
  document.title = `${map.domain}: Sendermap`;
  const logo = $("logo");
  if (map.logo) { logo.src = map.logo; logo.hidden = false; } else { logo.hidden = true; }
  const view = $("view");
  view.innerHTML = fragment;
  $("head").replaceChildren(...view.querySelectorAll(".view-head"));
  let lead = view.querySelector(".lead");
  if (!lead) { lead = document.createElement("div"); lead.className = "lead"; view.prepend(lead); }
  lead.append(figure);
  drawMap(map.domain, map.services.filter((s) => s.role === "sender"));
  show("result");
  $("result").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
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

// A card's id is service- and the name lowercased, anything outside a to z and 0 to 9 a hyphen,
// as render/html.py writes it.
function focusCard(name) {
  const target = document.getElementById(`service-${name.toLowerCase().replace(/[^a-z0-9]/g, "-")}`);
  if (!target) return;
  target.scrollIntoView({ behavior: "smooth", block: "center" });
  target.classList.add("flash");
  setTimeout(() => target.classList.remove("flash"), 1600);
}

// ------------------------------------------------------------------ sharing

function shareLink() {
  return `${location.origin}/?${query(current ? current.domain : "")}`;
}

async function copyMarkdown() {
  if (!current) return;
  const reply = await fetch(`/api/map.md?${query(current.domain)}`);
  if (reply.ok) copy(await reply.text(), "copy-md", "Markdown copied");
}

function download() {
  if (!current) return;
  const blob = new Blob([JSON.stringify(current, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `sendermap-${current.domain}.json`;
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

function show(id) { $(id).hidden = false; }
function hide(id) { $(id).hidden = true; }
