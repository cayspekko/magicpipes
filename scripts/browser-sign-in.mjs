// Drives a fresh headless Chrome (a new profile, like a private window) through signing in to
// private tunnels, the way a person would: open the tunnel, get sent to the sign-in page, submit
// the form, and land on the application. Then opens a second private tunnel, which should need
// no form at all. Used by the ignored e2e test `browser_signs_in_to_private_tunnels`; plain
// HTTP clients don't apply CSP or cookie rules, which is where sign-in flows break.
//
//   node scripts/browser-sign-in.mjs '{"chrome": "...", "first": "https://…", "second": "https://…",
//     "email": "…", "password": "…", "resolve": "MAP *.t.test 127.0.0.1", "profile": "/tmp/…"}'
//
// Prints one JSON document: {"first": {url, text}, "second": {url, text}, "errors": [...]}.
// Needs Node 22 or newer (built-in fetch and WebSocket) and Chrome; nothing to install.

import { spawn } from "node:child_process";

const opts = JSON.parse(process.argv[2]);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const port = 9300 + Math.floor(Math.random() * 600);
const chrome = spawn(opts.chrome, [
  "--headless=new", `--remote-debugging-port=${port}`, `--user-data-dir=${opts.profile}`,
  "--ignore-certificate-errors", "--no-first-run", "--no-default-browser-check",
  `--host-resolver-rules=${opts.resolve}`, "about:blank",
], { stdio: "ignore" });

const errors = [];
try {
  let version;
  for (let i = 0; i < 100 && !version; i++) {
    try { version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json(); } catch { await sleep(100); }
  }
  if (!version) throw new Error("Chrome did not start");
  const ws = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise((r, j) => { ws.addEventListener("open", r, { once: true }); ws.addEventListener("error", j, { once: true }); });
  let id = 0;
  const pending = new Map();
  ws.addEventListener("message", (e) => {
    const m = JSON.parse(e.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); return; }
    // CSP violations, blocked navigations and the like.
    // Browsers ask every site for a favicon; the test application has none.
    const entry = m.method === "Log.entryAdded" ? m.params.entry : null;
    if (entry?.level === "error" && !entry.url?.endsWith("/favicon.ico")) errors.push(`${entry.text}${entry.url ? ` (${entry.url})` : ""}`);
    if (m.method === "Network.loadingFailed" && m.params.type === "Document") errors.push(`navigation failed: ${m.params.errorText}`);
  });
  const send = (method, params = {}, sessionId) =>
    new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params, sessionId })); });
  const { result: { targetId } } = await send("Target.createTarget", { url: "about:blank" });
  const { result: { sessionId } } = await send("Target.attachToTarget", { targetId, flatten: true });
  const page = (method, params) => send(method, params, sessionId);
  await page("Page.enable");
  await page("Network.enable");
  await page("Log.enable");
  const evaluate = async (expression) => (await page("Runtime.evaluate", { expression, returnByValue: true })).result.result?.value;

  // Waits until the page has been on `origin` with a complete document for a moment.
  const settle = async (origin) => {
    for (let i = 0; i < 150; i++) {
      await sleep(100);
      const [href, ready] = [await evaluate("location.href"), await evaluate("document.readyState")];
      if (href?.startsWith(origin) && !href.includes("/.magicpipes/") && ready === "complete") return;
    }
  };
  const state = async () => ({ url: await evaluate("location.href"), text: (await evaluate("document.body?.innerText ?? ''")).replace(/\s+/g, " ").trim().slice(0, 300) });

  await page("Page.navigate", { url: opts.first });
  const mgmt = new URL(opts.management).origin;
  await settle(mgmt);
  await evaluate(`(() => {
    const f = document.querySelector('form[action="/login"]');
    if (!f) return false;
    f.querySelector('[name=email]').value = ${JSON.stringify(opts.email)};
    f.querySelector('[name=password]').value = ${JSON.stringify(opts.password)};
    f.submit();
    return true;
  })()`);
  await settle(new URL(opts.first).origin);
  const first = await state();

  await page("Page.navigate", { url: opts.second });
  await settle(new URL(opts.second).origin);
  const second = await state();

  console.log(JSON.stringify({ first, second, errors }));
  ws.close();
} catch (e) {
  console.log(JSON.stringify({ errors: [...errors, String(e)] }));
} finally {
  chrome.kill();
}
