// The VNC desktop page: noVNC, connected through this server's WebSocket to the tunnel's machine
// (`data::desktop::relay`), which carries its bytes and nothing else. The page opens the socket
// itself to read why the server closed it. If the VNC server asks for a password, it goes to noVNC
// here and on to that server.
import RFB from "./novnc/core/rfb.js";

const $ = (id) => document.getElementById(id);
const name = document.body.dataset.name;
const address = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}${document.body.dataset.ws}`;
const go = $("go");
const login = $("login");
const keys = $("keys");
const status = $("st");
let rfb = null;
/// The person pressed Disconnect: however the socket closes, that's an end, not a loss.
let leaving = false;

/// The header's dot and word: "ok" is green, "warn" amber, "bad" red, "" grey.
function state(kind, label) {
  status.className = `status ${kind}`.trim();
  status.textContent = label;
}

/// Shows `text` over the screen, or hides the notice; a problem is announced as an alert.
function say(text, problem = false) {
  $("nt-text").textContent = text || "";
  $("nt").hidden = !text;
  $("nt").setAttribute("role", problem ? "alert" : "status");
}

/// Why the server closed the desktop's socket: 4000 and an HTTP status (`data::desktop::Refusal`).
function refused(code) {
  switch (code) {
    case 4404:
      return "You can't reach this desktop, or it no longer exists.";
    case 4429:
      return "You have the most remote desktops open already. Close one first.";
    case 4502:
      return `${name} didn't answer as a VNC server. Is screen sharing turned on there?`;
    case 4503:
      return `${name} is offline.`;
  }
  return "";
}

function ended(text, problem = false) {
  rfb = null;
  keys.hidden = true;
  login.hidden = true;
  login.elements.password.value = "";
  go.hidden = false;
  state(problem ? "bad" : "", "Not connected");
  say(text, problem);
}

go.addEventListener("submit", (event) => {
  event.preventDefault();
  if (rfb) return;
  go.hidden = true;
  leaving = false;
  state("warn", "Connecting…");
  say("");
  let code = 0;
  let connected = false;
  let failure = "";
  const socket = new WebSocket(address);
  socket.addEventListener("close", (e) => (code = e.code));
  rfb = new RFB($("vnc"), socket, { shared: true });
  rfb.scaleViewport = true;
  rfb.addEventListener("connect", () => {
    connected = true;
    login.hidden = true;
    keys.hidden = false;
    state("ok", "Connected");
    rfb.focus();
  });
  // What the VNC server asks for: a password, or a user name and password (macOS, VeNCrypt).
  rfb.addEventListener("credentialsrequired", (e) => {
    const user = e.detail.types.includes("username");
    $("f-user").hidden = !user;
    login.elements.user.required = user;
    login.hidden = false;
    say("");
    (user ? login.elements.user : login.elements.password).focus();
  });
  rfb.addEventListener("securityfailure", (e) => {
    failure = e.detail.reason ? `${name} refused the sign-in: ${e.detail.reason}` : `${name} didn't accept that password.`;
  });
  // noVNC calls any end the server's side started clean; a socket cut off (1006) wasn't.
  rfb.addEventListener("disconnect", (e) => {
    const why = refused(code) || failure;
    if (why) ended(why, true);
    else if (connected && (leaving || (e.detail.clean && code !== 1006))) ended("The remote desktop ended.");
    else if (connected) ended("The connection to the remote desktop was lost.", true);
    else ended("The remote desktop couldn't connect. Try again.", true);
  });
});

login.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!rfb) return;
  const data = new FormData(login);
  rfb.sendCredentials({ username: String(data.get("user") || ""), password: String(data.get("password") || "") });
  login.elements.password.value = "";
  login.hidden = true;
});

$("cad").addEventListener("click", () => rfb?.sendCtrlAltDel());
$("bye").addEventListener("click", () => {
  leaving = true;
  rfb?.disconnect();
});
