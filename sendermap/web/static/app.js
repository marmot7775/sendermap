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
  let scale = 0;
  new ResizeObserver(() => {
    const now = $("map").getBoundingClientRect().width;
    if (drawn && now && Math.abs(now - scale) > 1) { scale = now; drawMap(drawn.domain, drawn.senders); }
  }).observe($("map"));
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
  show("result");
  drawMap(map.domain, map.services.filter((s) => s.role === "sender"));
  $("result").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
}

// ------------------------------------------------------------------ the map

// The map is drawn in a 720 by 720 box that the page shows at whatever size the column allows:
// 340px beside the story on a desktop, up to 560px square when stacked under it. The rings stop
// BAND units inside the box so the names and sector labels have room beyond the outer ring.
// Names render at 10px, or 12px once the map is drawn wider than 600px. Each label sits outward
// from its point along its own angle; one that collides moves out a line and, failing that, is
// dropped, and the legend and the cards carry it instead.
const BOX = 720;
const BAND = 90;
const INSET = 2; // keeps the halo behind a name inside the box
const FIT = (BOX / 2 - BAND) / TIERS[TIERS.length - 1].radius;
let drawn = null;

function drawMap(domain, senders) {
  drawn = { domain, senders };
  const svg = $("map");
  svg.replaceChildren();
  svg.setAttribute("aria-label", `Map of ${senders.length} services sending as ${domain}`);
  const ctm = svg.getScreenCTM();
  if (!ctm || !ctm.a) return; // not on screen yet: the resize observer draws it once it is
  const units = (px) => Math.max(px / ctm.a, 1);
  const text = units(BOX * ctm.a > 600 ? 12 : 10);
  const nodeR = Math.max(17, units(13)) * FIT;
  const C = BOX / 2;
  const ring = (tier) => TIER[tier].radius * FIT;

  for (const tier of TIERS) svg.append(el("circle", { class: "ring", cx: C, cy: C, r: ring(tier.name) }));

  const groups = CATEGORIES.map((c) => ({ category: c, items: senders.filter((s) => (CATEGORIES.includes(s.category) ? s.category : "Other") === c) }))
    .filter((g) => g.items.length);
  const total = groups.reduce((n, g) => n + Math.max(g.items.length, 1.5), 0);
  const gap = groups.length > 1 ? 0.1 : 0;
  let angle = -Math.PI / 2 + gap / 2;
  const nodes = [];
  const sectors = [];

  for (const group of groups) {
    const width = (2 * Math.PI - gap * groups.length) * Math.max(group.items.length, 1.5) / total;
    const ordered = [...group.items].sort((a, b) => TIER[a.tier].radius - TIER[b.tier].radius || a.name.localeCompare(b.name));
    ordered.forEach((service, i) => {
      const a = angle + (width * (i + 0.5)) / ordered.length;
      nodes.push({ service, a, r: ring(service.tier) });
    });
    if (groups.length > 1) {
      const edge = angle - gap / 2;
      svg.append(el("line", { class: "divider", x1: C + Math.cos(edge) * 64 * FIT, y1: C + Math.sin(edge) * 64 * FIT, x2: C + Math.cos(edge) * 336 * FIT, y2: C + Math.sin(edge) * 336 * FIT }));
    }
    sectors.push({ category: group.category, mid: angle + width / 2 });
    angle += width + gap;
  }

  for (const n of nodes) {
    svg.append(el("line", { class: "spoke", x1: C, y1: C, x2: C + Math.cos(n.a) * n.r, y2: C + Math.sin(n.a) * n.r }));
  }
  svg.append(el("circle", { class: "core", cx: C, cy: C, r: 25 * FIT })); // a plain hub: the domain heads the page

  const taken = [];
  const named = nodes.map((n) => {
    const x = C + Math.cos(n.a) * n.r, y = C + Math.sin(n.a) * n.r;
    taken.push({ left: x - nodeR, right: x + nodeR, top: y - nodeR, bottom: y + nodeR });
    const g = el("g", { class: "node", tabindex: 0, role: "button", "aria-label": `${n.service.name}, ${n.service.tier}` });
    g.append(el("title", {}, `${n.service.name}: ${n.service.tier}, ${n.service.claims[0].kind}`));
    g.append(el("circle", { cx: x, cy: y, r: nodeR, class: `t-${TIER[n.service.tier].key}` }));
    g.append(el("text", { class: "initials", x, y: y + text * 0.35, "text-anchor": "middle", "font-size": text }, initials(n.service.name)));
    const go = () => focusCard(n.service.name);
    g.addEventListener("click", go);
    g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
    svg.append(g);
    const label = el("text", { class: "name", "font-size": text }, n.service.name);
    g.append(label);
    return { label, a: n.a, out: n.r + nodeR + units(4) };
  });

  const sectorOut = C - BAND / 2;
  const labelled = sectors.map((s) => {
    const label = el("text", { class: "sector-label", "font-size": text }, s.category);
    svg.append(label);
    return { label, a: s.mid, out: sectorOut };
  });

  for (const l of [...named, ...labelled]) {
    placeRadially(l.label, l.a, l.out, C, text);
    keepIfClear(l.label, l.a, text, taken);
  }
}

// A label sits at distance out from the centre along angle a, anchored away from the centre:
// start on the right half, end on the left, middle within 15 degrees of straight up or down.
function placeRadially(label, a, out, C, height) {
  const cos = Math.cos(a), sin = Math.sin(a);
  const anchor = Math.abs(cos) < Math.sin(Math.PI / 12) ? "middle" : cos > 0 ? "start" : "end";
  const lift = anchor !== "middle" ? height * 0.35 : sin > 0 ? height * 0.8 : -height * 0.2;
  label.setAttribute("text-anchor", anchor);
  label.setAttribute("x", C + cos * out);
  label.setAttribute("y", C + sin * out + lift);
}

// A label stays when it sits inside the box and clear of everything kept before it. A label
// that would leave the box slides back inside it. One that collides is tried one line height
// further out along its angle, then one line up or down, the side away from the centre first,
// since at the left and right edges the box stops it moving out. Dropping is the last resort.
function keepIfClear(label, a, height, taken) {
  const x = Number(label.getAttribute("x")), y = Number(label.getAttribute("y"));
  const away = Math.sin(a) < 0 ? -height : height;
  const tries = [[0, 0], [Math.cos(a) * height, Math.sin(a) * height], [0, away], [0, -away]];
  for (const [dx, dy] of tries) {
    label.setAttribute("x", x + dx);
    label.setAttribute("y", y + dy);
    const box = boxOf(label);
    move(label, Math.max(INSET - box.left, 0) + Math.min(BOX - INSET - box.right, 0), Math.max(INSET - box.top, 0) + Math.min(BOX - INSET - box.bottom, 0));
    const kept = boxOf(label);
    if (!taken.some((t) => overlaps(kept, t))) { taken.push(kept); return; }
  }
  label.remove();
}

function boxOf(label) {
  const b = label.getBBox();
  return { left: b.x, right: b.x + b.width, top: b.y, bottom: b.y + b.height };
}

function move(label, dx, dy) {
  label.setAttribute("x", Number(label.getAttribute("x")) + dx);
  label.setAttribute("y", Number(label.getAttribute("y")) + dy);
}

function overlaps(p, q) {
  return p.left < q.right && q.left < p.right && p.top < q.bottom && q.top < p.bottom;
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
