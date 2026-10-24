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

// The map is drawn in a 720 by 720 box that the page shows at whatever size the column allows,
// near 340px on a desktop and a phone alike. Text is sized from that scale so none renders under
// MIN_TEXT pixels, and every label is measured once drawn: one that would leave the box or cover
// a node or another label is dropped, and the legend and the cards carry it instead.
const BOX = 720;
const MIN_TEXT = 11;
let drawn = null;

function drawMap(domain, senders) {
  drawn = { domain, senders };
  const svg = $("map");
  svg.replaceChildren();
  svg.setAttribute("aria-label", `Map of ${senders.length} services sending as ${domain}`);
  const ctm = svg.getScreenCTM();
  if (!ctm || !ctm.a) return; // not on screen yet: the resize observer draws it once it is
  const units = (px) => Math.max(px / ctm.a, 1);
  const text = units(MIN_TEXT);
  const nodeR = Math.max(17, units(13));
  const C = BOX / 2;

  for (const tier of TIERS) svg.append(el("circle", { class: "ring", cx: C, cy: C, r: tier.radius }));

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
      nodes.push({ service, a, r: TIER[service.tier].radius });
    });
    if (groups.length > 1) {
      const edge = angle - gap / 2;
      svg.append(el("line", { class: "divider", x1: C + Math.cos(edge) * 64, y1: C + Math.sin(edge) * 64, x2: C + Math.cos(edge) * 336, y2: C + Math.sin(edge) * 336 }));
    }
    sectors.push({ category: group.category, mid: angle + width / 2 });
    angle += width + gap;
  }

  for (const n of nodes) {
    svg.append(el("line", { class: "spoke", x1: C, y1: C, x2: C + Math.cos(n.a) * n.r, y2: C + Math.sin(n.a) * n.r }));
  }
  svg.append(el("circle", { class: "core", cx: C, cy: C, r: 50 }));
  const core = el("text", { class: "core-text", x: C, y: C + text * 0.35, "text-anchor": "middle", "font-size": text }, domain);
  svg.append(core);
  if (core.getComputedTextLength() > 100 - units(8)) core.remove(); // the domain heads the page anyway

  const taken = [];
  const groupsDrawn = nodes.map((n) => {
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
    return g;
  });

  for (const sector of sectors) {
    const label = el("text", { class: "sector-label", x: C + Math.cos(sector.mid) * 350, y: C + Math.sin(sector.mid) * 350 + text * 0.35, "text-anchor": anchor(sector.mid), "font-size": text }, sector.category);
    svg.append(label);
    keepIfClear(label, taken);
  }

  const labels = nodes.map((n, i) => {
    const label = el("text", { class: "name", "text-anchor": anchor(n.a), "font-size": text }, n.service.name);
    groupsDrawn[i].append(label);
    return { a: n.a, out: n.r + nodeR + units(6), anchor: anchor(n.a), width: label.getComputedTextLength(), height: text, label };
  });
  for (const l of placeLabels(labels, C)) {
    l.label.setAttribute("x", l.x);
    l.label.setAttribute("y", l.y);
    keepIfClear(l.label, taken);
  }
}

// A label stays when it sits inside the box and clear of everything kept before it.
function keepIfClear(label, taken) {
  const b = label.getBBox();
  const box = { left: b.x, right: b.x + b.width, top: b.y, bottom: b.y + b.height };
  const inside = box.left >= 0 && box.top >= 0 && box.right <= BOX && box.bottom <= BOX;
  if (inside && !taken.some((t) => overlaps(box, t))) taken.push(box);
  else label.remove();
}

function overlaps(p, q) {
  return p.left < q.right && q.left < p.right && p.top < q.bottom && q.top < p.bottom;
}

// Labels sit just outside their node. Where two would overlap, the later one moves outward
// along its spoke until it clears; a few passes settle even a crowded ring. A label pushed
// out of the box is dropped afterwards.
function placeLabels(labels, C) {
  const box = (l) => {
    const x = C + Math.cos(l.a) * l.out, y = C + Math.sin(l.a) * l.out + l.height * 0.35;
    const left = l.anchor === "start" ? x : l.anchor === "end" ? x - l.width : x - l.width / 2;
    return { x, y, left, right: left + l.width, top: y - l.height, bottom: y + l.height * 0.3 };
  };
  for (let pass = 0; pass < 40; pass++) {
    let moved = false;
    for (let i = 0; i < labels.length; i++) {
      for (let j = i + 1; j < labels.length; j++) {
        if (overlaps(box(labels[i]), box(labels[j]))) { labels[j].out += labels[j].height * 0.6; moved = true; }
      }
    }
    if (!moved) break;
  }
  return labels.map((l) => ({ ...box(l), label: l.label }));
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
