// (c) Javier Fernandez @ JotaSoft 2026
// The browser half of the two WebAuthn ceremonies. The server sends options as JSON with
// binary fields in base64url; navigator.credentials wants ArrayBuffers, and the answer
// goes back as JSON again. Everything security-relevant is checked on the server.

const b64urlToBytes = (s) => {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

const bytesToB64url = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const withIds = (list) => (list || []).map((c) => ({ ...c, id: b64urlToBytes(c.id) }));

function creationOptions(json) {
  const o = json.publicKey;
  return {
    ...o,
    challenge: b64urlToBytes(o.challenge),
    user: { ...o.user, id: b64urlToBytes(o.user.id) },
    excludeCredentials: withIds(o.excludeCredentials),
  };
}

function requestOptions(json) {
  const o = json.publicKey;
  return { ...o, challenge: b64urlToBytes(o.challenge), allowCredentials: withIds(o.allowCredentials) };
}

const registrationJson = (cred) => ({
  id: cred.id,
  rawId: bytesToB64url(cred.rawId),
  type: cred.type,
  response: {
    attestationObject: bytesToB64url(cred.response.attestationObject),
    clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
    transports: cred.response.getTransports ? cred.response.getTransports() : [],
  },
  clientExtensionResults: cred.getClientExtensionResults(),
});

const assertionJson = (cred) => ({
  id: cred.id,
  rawId: bytesToB64url(cred.rawId),
  type: cred.type,
  response: {
    authenticatorData: bytesToB64url(cred.response.authenticatorData),
    clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
    signature: bytesToB64url(cred.response.signature),
    userHandle: cred.response.userHandle ? bytesToB64url(cred.response.userHandle) : null,
  },
  clientExtensionResults: cred.getClientExtensionResults(),
});

async function post(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  const reply = await res.json();
  if (!reply.ok) throw new Error(reply.error);
  return reply;
}

const status = (text, kind = "") => {
  const el = document.getElementById("status");
  el.textContent = text;
  el.className = kind;
};

function username(button) {
  const input = document.getElementById("username");
  return button.dataset.username || (input ? input.value.trim() : "");
}

// A button with data-pin registers a key that must verify the user (its PIN) at every sign-in.
async function register(button) {
  const pin = "pin" in button.dataset;
  const start = await post("/api/register/start", { username: username(button), pin });
  status(pin ? "Enter your key's PIN, then touch it to register it…" : "Touch your key to register it…");
  const cred = await navigator.credentials.create({ publicKey: creationOptions(start.options) });
  const done = await post("/api/register/finish", { ceremony: start.ceremony, credential: registrationJson(cred) });
  const withPin = pin ? ", PIN required" : "";
  const registered = `Registered key ${done.keys} (${done.model}${withPin}) for ${done.username}. Now sign in with it.`;
  // The key registered, but Jotakey's strict CBOR decoder could not read the browser's
  // attestation object: say so rather than hide it.
  status(done.warning ? `${done.warning} ${registered}` : registered, done.warning ? "warning" : "ok");
}

async function login(button) {
  const start = await post("/api/login/start", { username: username(button) });
  const uv = start.options.publicKey.userVerification;
  status(uv === "discouraged" ? "Touch your key to sign in…" : "Enter your key's PIN if asked, then touch it to sign in…");
  const cred = await navigator.credentials.get({ publicKey: requestOptions(start.options) });
  await post("/api/login/finish", { ceremony: start.ceremony, credential: assertionJson(cred) });
  location.reload();
}

// Unregister a key. The server forgets it; the key itself stored nothing (its credentials
// are not discoverable), so there is nothing to delete on it.
async function remove(button) {
  const question = button.dataset.last === "yes"
    ? "Remove your only key? That deletes the account and signs you out, and anyone may then register the username."
    : "Remove this key? It will no longer sign in to this account.";
  if (!confirm(question)) return;
  await post("/api/keys/remove", { credential: button.dataset.credential });
  location.reload();
}

const all = (selector) => [...document.querySelectorAll(selector)];
const actions = [
  [all("#register, #register-pin"), register],
  // The sign-in button, and each name in the list of registered users.
  [all("#login, button.user"), login],
  [all("button.remove"), remove],
];

for (const [button, action] of actions.flatMap(([buttons, action]) => buttons.map((b) => [b, action]))) {
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      await action(button);
    } catch (e) {
      console.error(e);
      // NotAllowedError covers a timeout, a cancelled prompt, an unknown key and a page
      // without focus; the browser's message says which.
      status(e.name === "NotAllowedError" ? `Not completed: ${e.message}` : e.message, "error");
    } finally {
      button.disabled = false;
    }
  });
}
