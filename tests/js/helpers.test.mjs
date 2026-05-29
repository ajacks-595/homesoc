// Node assertions for the security-critical pure helpers in static/js/main.js.
// We evaluate the REAL source (not a copy) in a vm context, injecting a single
// line that exposes the closure-private helpers so they can be tested. A tiny
// DOM shim covers linkifyIpsInEl (DFS over text nodes is equivalent to a
// SHOW_TEXT TreeWalker for our purposes).
import fs from "node:fs";
import vm from "node:vm";
import assert from "node:assert/strict";

const srcPath = new URL("../../static/js/main.js", import.meta.url);
let src = fs.readFileSync(srcPath, "utf8");

const marker = "  // ===== expose";
assert.ok(src.includes(marker), "expose marker not found — did main.js change?");
src = src.replace(
  marker,
  "  globalThis.__h = { escapeHtml, safeUrl, linkifyIpsInEl };\n" + marker,
);

// ---- minimal DOM shim (enough for el() + linkifyIpsInEl) ------------------
class TextNode {
  constructor(v) { this.nodeType = 3; this.nodeName = "#text"; this.nodeValue = v; this.parentNode = null; }
  get textContent() { return this.nodeValue; }
}
class Frag {
  constructor() { this.nodeType = 11; this.childNodes = []; }
  appendChild(c) { c.parentNode = this; this.childNodes.push(c); return c; }
}
class El {
  constructor(tag) { this.nodeType = 1; this.nodeName = tag.toUpperCase(); this.childNodes = []; this.parentNode = null; this.attributes = {}; this.className = ""; }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  getAttribute(k) { return this.attributes[k]; }
  appendChild(c) {
    if (c.nodeType === 11) { for (const ch of [...c.childNodes]) { ch.parentNode = this; this.childNodes.push(ch); } c.childNodes = []; }
    else { c.parentNode = this; this.childNodes.push(c); }
    return c;
  }
  replaceChild(newNode, oldNode) {
    const i = this.childNodes.indexOf(oldNode);
    if (i < 0) return;
    const ins = newNode.nodeType === 11 ? [...newNode.childNodes] : [newNode];
    ins.forEach(n => (n.parentNode = this));
    this.childNodes.splice(i, 1, ...ins);
    if (newNode.nodeType === 11) newNode.childNodes = [];
  }
  get textContent() { return this.childNodes.map(c => c.textContent).join(""); }
}
function createTreeWalker(root, _show, filter) {
  const order = [];
  (function rec(n) {
    for (const c of n.childNodes || []) {
      if (c.nodeType === 3) { if (filter.acceptNode(c) === 1) order.push(c); }
      else rec(c);
    }
  })(root);
  let i = -1;
  return { nextNode() { i += 1; return i < order.length ? order[i] : null; } };
}
const NodeFilter = { SHOW_TEXT: 4, FILTER_ACCEPT: 1, FILTER_REJECT: 2, FILTER_SKIP: 3 };
const document = {
  createElement: t => new El(t),
  createTextNode: v => new TextNode(v),
  createDocumentFragment: () => new Frag(),
  createTreeWalker,
};

const sandbox = { document, NodeFilter, window: {}, console,
  localStorage: { getItem() {}, setItem() {} }, fetch: () => {},
  URLSearchParams, setTimeout, Chart: function () {}, navigator: {} };
vm.createContext(sandbox);
vm.runInContext(src, sandbox);
const { escapeHtml, safeUrl, linkifyIpsInEl } = sandbox.__h;

let failures = 0;
function check(name, fn) {
  try { fn(); console.log("  ok  " + name); }
  catch (e) { failures += 1; console.error("FAIL  " + name + " — " + e.message); }
}

// ---- escapeHtml -----------------------------------------------------------
check("escapeHtml encodes the five HTML-significant chars", () => {
  assert.equal(escapeHtml(`<a href="x" id='y'>&</a>`),
    "&lt;a href=&quot;x&quot; id=&#39;y&#39;&gt;&amp;&lt;/a&gt;");
});
check("escapeHtml neutralizes attribute breakout", () => {
  // value="${escapeHtml(payload)}" must not allow closing the attribute
  const out = `value="${escapeHtml('" onmouseover="alert(1)')}"`;
  assert.ok(!out.includes('" onmouseover'), out);
  assert.ok(out.includes("&quot; onmouseover"));
});
check("escapeHtml handles null/undefined/number", () => {
  assert.equal(escapeHtml(null), "");
  assert.equal(escapeHtml(undefined), "");
  assert.equal(escapeHtml(42), "42");
});

// ---- safeUrl --------------------------------------------------------------
check("safeUrl allows http(s) and mailto", () => {
  assert.equal(safeUrl("https://urlscan.io/x"), "https://urlscan.io/x");
  assert.equal(safeUrl("http://10.0.0.1/x"), "http://10.0.0.1/x");
  assert.equal(safeUrl("mailto:a@b.com"), "mailto:a@b.com");
});
check("safeUrl allows same-origin relative paths", () => {
  assert.equal(safeUrl("/osint?ioc=1.2.3.4"), "/osint?ioc=1.2.3.4");
  assert.equal(safeUrl("#frag"), "#frag");
});
check("safeUrl rejects javascript:/data:/vbscript:", () => {
  assert.equal(safeUrl("javascript:alert(1)"), "");
  assert.equal(safeUrl("JaVaScRiPt:alert(1)"), "");
  assert.equal(safeUrl("data:text/html,<script>"), "");
  assert.equal(safeUrl("vbscript:msgbox(1)"), "");
});
check("safeUrl rejects protocol-relative //evil", () => {
  assert.equal(safeUrl("//evil.example.com/x"), "");
});

// ---- linkifyIpsInEl -------------------------------------------------------
check("linkifyIpsInEl wraps IPs and preserves surrounding text", () => {
  const root = new El("div");
  root.appendChild(new TextNode("connect from 8.8.8.8 ok"));
  linkifyIpsInEl(root);
  const a = root.childNodes.find(n => n.nodeName === "A");
  assert.ok(a, "expected an anchor");
  assert.equal(a.textContent, "8.8.8.8");
  assert.ok(a.getAttribute("href").includes("ioc=8.8.8.8"));
  assert.equal(root.textContent, "connect from 8.8.8.8 ok");
});
check("linkifyIpsInEl does not double-link inside an existing <a>", () => {
  const root = new El("div");
  const a = new El("a"); a.setAttribute("href", "/x");
  a.appendChild(new TextNode("1.1.1.1"));
  root.appendChild(a);
  linkifyIpsInEl(root);
  // the anchor's text child stays a single text node — no nested anchor
  assert.equal(a.childNodes.length, 1);
  assert.equal(a.childNodes[0].nodeType, 3);
});

if (failures) { console.error(`\n${failures} JS helper assertion(s) failed`); process.exit(1); }
console.log("\nall JS helper assertions passed");
