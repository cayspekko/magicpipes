// The remote desktop page: IronRDP's web component, started from the form above it. The client
// speaks RDCleanPath to this server's WebSocket, which reaches the machine through its tunnel
// (`data::desktop`); the password goes to the client here, and on to Windows inside its sign-in.
import "./iron-remote-desktop.js";
import { Backend, displayControl, init } from "./iron-remote-desktop-rdp.js";

const $ = (id) => document.getElementById(id);
const name = document.body.dataset.name;
const address = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}${document.body.dataset.ws}`;
const form = $("login");
const keys = $("keys");
const status = $("st");
const screen = $("screen");
const desktop = $("rd");

/// Shows `text` over the screen, or hides the notice; a problem is announced as an alert.
function say(text, problem = false) {
  $("nt-text").textContent = text || "";
  $("nt").hidden = !text;
  $("nt").setAttribute("role", problem ? "alert" : "status");
}

/// Why a desktop didn't open or ended. The server says it as an HTTP status; Windows, as a kind.
function why(error) {
  const kind = typeof error?.kind === "function" ? error.kind() : undefined;
  const details = typeof error?.rdcleanpathDetails === "function" ? error.rdcleanpathDetails() : undefined;
  switch (details?.httpStatusCode) {
    case 403:
      return `${name}'s certificate isn't the one it showed before. If the machine was reinstalled, its owner can forget the old one on the tunnel's page.`;
    case 404:
      return "You can't reach this desktop, or it no longer exists.";
    case 429:
      return "You have the most remote desktops open already. Close one first.";
    case 502:
      return `${name} didn't answer as a remote desktop. Is Remote Desktop turned on there?`;
    case 503:
      return `${name} is offline.`;
  }
  switch (kind) {
    case 1: // WrongPassword
    case 2: // LogonFailure
      return "Windows didn't accept that user name and password.";
    case 3: // AccessDenied
      return "Windows didn't let that account sign in remotely.";
    case 6: // NegotiationFailure
      return `${name} refused the connection's security settings.`;
  }
  return "The remote desktop couldn't connect. Reload the page to try again.";
}

const ready = new Promise((resolve) => desktop.addEventListener("ready", (e) => resolve(e.detail.irgUserInteraction), { once: true }));
desktop.module = Backend;
await init("WARN");
const ui = await ready;
let connected = false;

function ended(text, problem = false) {
  connected = false;
  keys.hidden = true;
  form.hidden = false;
  status.textContent = "Not connected";
  say(text, problem);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (connected) return;
  const data = new FormData(form);
  const size = screen.getBoundingClientRect();
  const config = ui
    .configBuilder()
    .withUsername(String(data.get("user")))
    .withPassword(String(data.get("password")))
    .withServerDomain(String(data.get("domain") || ""))
    // The tunnel decides where this goes; the client uses it as the machine's name for Windows.
    .withDestination(name)
    .withProxyAddress(address)
    .withAuthToken("magicpipes")
    .withDesktopSize({ width: Math.max(640, Math.round(size.width)), height: Math.max(480, Math.round(size.height)) })
    .withExtension(displayControl(true))
    .build();
  form.elements.password.value = "";
  connected = true;
  form.hidden = true;
  status.textContent = "Connecting…";
  say("");
  try {
    const session = await ui.connect(config);
    ui.setVisibility(true);
    status.textContent = "Connected";
    keys.hidden = false;
    session.run().then(
      () => ended("The remote desktop ended."),
      (error) => ended(why(error), true),
    );
  } catch (error) {
    ended(why(error), true);
  }
});

$("cad").addEventListener("click", () => ui.ctrlAltDel());
$("win").addEventListener("click", () => ui.metaKey());
$("bye").addEventListener("click", () => ui.shutdown());
