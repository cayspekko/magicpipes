// Drives a fresh headless Chrome through a browser SSH terminal, the way a person would: sign in on
// the management host, open the terminal, type a user name and press Enter, then type a command
// and read it back from the screen. Used by the ignored e2e test `browser_opens_an_ssh_terminal`;
// a plain WebSocket client doesn't load the page's modules or apply its CSP.
//
//   node scripts/browser-terminal.mjs '{"chrome": "...", "management": "https://localhost:…",
//     "terminal": "/terminal/dev-box", "email": "…", "password": "…", "login": "…",
//     "command": "echo hello-$((6*7))", "want": "hello-42", "profile": "/tmp/…"}'
//
// Prints one JSON document: {"screen": "...", "status": "...", "errors": [...]}. Needs Node 22 or
// newer (built-in fetch and WebSocket) and Chrome; nothing to install.

import { spawn } from "node:child_process";

const opts = JSON.parse(process.argv[2]);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const port = 9300 + Math.floor(Math.random() * 600);
const chrome = spawn(opts.chrome, [
  "--headless=new", `--remote-debugging-port=${port}`, `--user-data-dir=${opts.profile}`,
  "--ignore-certificate-errors", "--no-first-run", "--no-default-browser-check", "about:blank",
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
    const entry = m.method === "Log.entryAdded" ? m.params.entry : null;
    if (entry?.level === "error" && !entry.url?.endsWith("/favicon.ico")) errors.push(`${entry.text}${entry.url ? ` (${entry.url})` : ""}`);
    if (m.method === "Runtime.exceptionThrown") errors.push(`exception: ${m.params.exceptionDetails?.exception?.description ?? m.params.exceptionDetails?.text}`);
    if (m.method === "Network.loadingFailed" && !m.params.canceled) errors.push(`load failed: ${m.params.errorText} (${m.params.type})`);
  });
  const send = (method, params = {}, sessionId) =>
    new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params, sessionId })); });
  const { result: { targetId } } = await send("Target.createTarget", { url: "about:blank" });
  const { result: { sessionId } } = await send("Target.attachToTarget", { targetId, flatten: true });
  const page = (method, params) => send(method, params, sessionId);
  await page("Page.enable");
  await page("Network.enable");
  await page("Log.enable");
  await page("Runtime.enable");
  const evaluate = async (expression) => (await page("Runtime.evaluate", { expression, returnByValue: true })).result.result?.value;
  const until = async (expression, ms = 15000) => {
    for (let i = 0; i < ms / 100; i++) {
      if (await evaluate(expression)) return true;
      await sleep(100);
    }
    return false;
  };
  // Real key presses: Chrome's own input, as a person typing.
  const type = async (text) => page("Input.insertText", { text });
  const enter = async () => {
    await page("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
    await page("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  };
  const screen = () => evaluate("document.querySelector('.xterm-rows')?.innerText ?? ''");

  await page("Page.navigate", { url: `${opts.management}/login` });
  await until("document.readyState === 'complete' && !!document.querySelector('form[action=\"/login\"]')");
  await evaluate(`(() => {
    const f = document.querySelector('form[action="/login"]');
    f.querySelector('[name=email]').value = ${JSON.stringify(opts.email)};
    f.querySelector('[name=password]').value = ${JSON.stringify(opts.password)};
    f.submit();
  })()`);
  await until("location.pathname === '/' && document.readyState === 'complete'");

  await page("Page.navigate", { url: `${opts.management}${opts.terminal}` });
  await until("document.readyState === 'complete' && !!document.querySelector('.xterm')");
  // The name field has the focus on a first visit.
  if (!(await until("document.activeElement?.id === 'ln'", 5000))) errors.push("the name field didn't have the focus");
  await type(opts.login);
  await enter();
  if (!(await until("document.getElementById('st')?.textContent === 'Running'"))) errors.push(`never connected: ${await evaluate("document.body.innerText")}`);
  // The terminal has the focus once it's connected.
  await until("document.activeElement?.classList.contains('xterm-helper-textarea')", 5000);
  await type(opts.command);
  await enter();
  if (!(await until(`(document.querySelector('.xterm-rows')?.innerText ?? '').includes(${JSON.stringify(opts.want)})`))) errors.push("never saw the command's output");
  const result = { screen: (await screen()).slice(-600), status: await evaluate("document.getElementById('st')?.textContent"), errors };
  // Optional: screenshots of pages to look at, [{path, url, width, dark}]; `url` defaults to the terminal.
  for (const shot of opts.shots ?? []) {
    await page("Emulation.setDeviceMetricsOverride", { width: shot.width, height: shot.height ?? 760, deviceScaleFactor: 1, mobile: shot.width < 600 });
    await page("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: shot.dark ? "dark" : "light" }] });
    if (shot.url) {
      await page("Page.navigate", { url: `${opts.management}${shot.url}` });
      await until("document.readyState === 'complete'");
    }
    await sleep(400);
    const { result: { data } } = await page("Page.captureScreenshot", { format: "png", captureBeyondViewport: !!shot.full });
    (await import("node:fs")).writeFileSync(shot.path, Buffer.from(data, "base64"));
    result.measured = result.measured ?? [];
    result.measured.push(`${shot.width} ${shot.url ?? "terminal"} page=${await evaluate("document.documentElement.scrollWidth")}/${await evaluate("document.documentElement.clientWidth")} tables=${await evaluate("[...document.querySelectorAll('table')].map(t => t.scrollWidth + '/' + t.parentElement.clientWidth).join(',')")}`);
  }
  console.log(JSON.stringify(result));
  ws.close();
} catch (e) {
  console.log(JSON.stringify({ errors: [...errors, String(e)] }));
} finally {
  chrome.kill();
}
