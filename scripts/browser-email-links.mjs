// Drives a fresh headless Chrome through what only a browser does with an emailed link: moving the
// code from the address's fragment into the form and out of the address, and leaving for a sign-in
// provider from a form, which `form-action 'self'` would stop if it were a redirect. Used by the
// ignored e2e test `browser_signs_in_with_emailed_links`.
//
//   node scripts/browser-email-links.mjs '{"chrome": "...", "sign_in_link": "https://…/login/link#code=…",
//     "invitation": "https://…/invite#code=…", "provider": "Continue with …", "resolve": "MAP …", "profile": "/tmp/…"}'
//
// Prints one JSON document with what each step saw, and `errors`.
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

  // Waits until the page is at `path` on `origin`, with a complete document, for a moment.
  const settle = async (origin, path) => {
    for (let i = 0; i < 150; i++) {
      await sleep(100);
      const [href, ready] = [await evaluate("location.href"), await evaluate("document.readyState")];
      if (href?.startsWith(origin) && new URL(href).pathname === path && ready === "complete") return;
    }
  };
  const state = async () => ({
    url: await evaluate("location.href"),
    path: await evaluate("location.pathname"),
    text: (await evaluate("document.body?.innerText ?? ''")).replace(/\s+/g, " ").trim().slice(0, 300),
  });
  // What the script did to the page a link opens. The value is read once and not repeated elsewhere.
  const linkPage = async () => ({
    hash: await evaluate("location.hash"),
    field_value: await evaluate("document.querySelector('input[data-code]')?.value"),
    field_hidden: await evaluate("document.querySelector('[data-code-field]')?.hidden"),
  });
  const press = (selector) => evaluate(`document.querySelector(${JSON.stringify(selector)})?.click()`);

  const origin = new URL(opts.sign_in_link).origin;
  await page("Page.navigate", { url: opts.sign_in_link });
  await settle(origin, "/login/link");
  const sign_in_page = await linkPage();
  await press('form[action="/login/link"] button');
  await settle(origin, "/");
  const signed_in = await state();

  await page("Network.clearBrowserCookies");
  await page("Page.navigate", { url: opts.invitation });
  await settle(origin, "/invite");
  const invitation_page = await linkPage();
  await press('form[action="/invite"] button');
  for (let i = 0; i < 100 && !(await evaluate("document.body?.innerText?.includes('invited')")); i++) await sleep(100);
  const invitation_opened = await state();
  await evaluate(`[...document.querySelectorAll('button')].find((b) => b.textContent === ${JSON.stringify(opts.provider)})?.click()`);
  await settle(origin, "/");
  const joined = await state();

  console.log(JSON.stringify({ sign_in_page, signed_in, invitation_page, invitation_opened, joined, errors }));
  ws.close();
} catch (e) {
  console.log(JSON.stringify({ errors: [...errors, String(e)] }));
} finally {
  chrome.kill();
}
