const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const vm = require("node:vm");

const serverSource = fs.readFileSync(path.join(__dirname, "../server.js"), "utf8");
const appSource = fs.readFileSync(path.join(__dirname, "../app.js"), "utf8");

async function startServer(t, env = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "palaco-auth-test-"));
  let server;
  let githubUnavailable = false;
  const context = vm.createContext({
    require(name) {
      if (name !== "node:http") return require(name);
      return { ...http, createServer(handler) {
        server = http.createServer(handler);
        server.listen = () => server;
        return server;
      } };
    },
    __dirname: directory,
    process: { env: { HOST: "127.0.0.1", GITHUB_TOKEN: "test-only-token", ...env } },
    console: { log() {} }, Buffer, URL,
    async fetch() {
      if (githubUnavailable) throw new Error("offline");
      return { ok: true, json: async () => [
        { name: "public-project", private: false, owner: { login: "Maurits-pixe" }, html_url: "https://github.com/Maurits-pixe/public-project" },
        { name: "private-project", private: true, description: "private-description", owner: { login: "Maurits-pixe" }, html_url: "https://github.com/Maurits-pixe/private-project" },
        { name: "unknown-visibility", owner: { login: "Maurits-pixe" } },
      ] };
    },
  });
  vm.runInContext(serverSource, context, { filename: "server.js" });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    http.Server.prototype.listen.call(server, 0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    vm.runInContext("database.close()", context);
    fs.rmSync(directory, { recursive: true, force: true });
  });
  return { url: `http://127.0.0.1:${server.address().port}`, offline() { githubUnavailable = true; } };
}

function browser(server) {
  let cookie = "";
  let failLogout = false;
  const requests = [];
  return {
    requests,
    failLogout(value) { failLogout = value; },
    async fetch(url, options = {}) {
      requests.push({ url, options });
      if (url === "/api/auth/logout" && failLogout === "csrf") {
        return new Response(JSON.stringify({ error: "Invalid CSRF token." }), { status: 403 });
      }
      if (url === "/api/auth/logout" && failLogout) throw new Error("network unavailable");
      const response = await fetch(server.url + url, {
        ...options, headers: { ...options.headers, ...(cookie ? { cookie } : {}) },
      });
      const setCookie = response.headers.get("set-cookie");
      if (setCookie) cookie = /Max-Age=0(?:;|$)/.test(setCookie) ? "" : setCookie.split(";")[0];
      return response;
    },
  };
}

async function signup(client) {
  const response = await client.fetch("/api/auth/signup", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Tester", email: "tester@example.test", password: "long-test-password", language: "English" }),
  });
  assert.equal(response.status, 201);
  return response;
}

function loadApp(client) {
  const elements = new Map();
  function element() {
    return {
      value: "", textContent: "", innerHTML: "", disabled: false, dataset: {}, options: [], listeners: {},
      classList: { toggle() {} }, querySelectorAll() { return []; },
      appendChild(child) { this.options.push(child); },
      addEventListener(event, handler) { this.listeners[event] = handler; },
      reset() {}, focus() {},
    };
  }
  const document = {
    getElementById(id) { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); },
    createElement: element,
  };
  const context = vm.createContext({ document, fetch: client.fetch.bind(client), console });
  vm.runInContext(appSource, context, { filename: "app.js" });
  return { context, get: document.getElementById, async ready() {
    const deadline = Date.now() + 5000;
    while (document.getElementById("account-name").textContent !== "Tester") {
      if (Date.now() > deadline) throw new Error("Session restoration timed out");
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  } };
}

test("reload restores CSRF for writes and server-confirmed logout", async (t) => {
  const server = await startServer(t);
  const client = browser(server);
  await signup(client);
  const app = loadApp(client);
  await app.ready();
  const write = await vm.runInContext('requestJson("/api/messages", { method: "POST", body: { text: "After reload" } })', app.context);
  assert.ok(write.messages.some((message) => message.text === "After reload"));
  const sent = client.requests.find((request) => request.url === "/api/messages" && request.options.method === "POST");
  assert.ok(sent.options.headers["X-CSRF-Token"]);
  await app.get("signout-button").listeners.click();
  assert.equal(app.get("session-status").textContent, "You have signed out.");
  assert.equal((await client.fetch("/api/auth/session")).status, 401);
});

test("logout failure keeps identity visible and allows a retry", async (t) => {
  const server = await startServer(t);
  const client = browser(server);
  await signup(client);
  const app = loadApp(client);
  await app.ready();
  for (const failure of [true, "csrf"]) {
    client.failLogout(failure);
    await app.get("signout-button").listeners.click();
    assert.equal(app.get("account-name").textContent, "Tester");
    assert.equal(app.get("signout-button").disabled, false);
    assert.match(app.get("session-status").textContent, /could not be confirmed/);
    assert.equal((await client.fetch("/api/auth/session")).status, 200);
  }
  client.failLogout(false);
  await app.get("signout-button").listeners.click();
  assert.equal((await client.fetch("/api/auth/session")).status, 401);
});

test("write and logout still reject absent or incorrect CSRF tokens", async (t) => {
  const server = await startServer(t);
  const client = browser(server);
  await signup(client);
  for (const token of [undefined, "incorrect"]) {
    for (const [url, method] of [["/api/messages", "POST"], ["/api/citadel", "PUT"], ["/api/auth/logout", "POST"]]) {
      const response = await client.fetch(url, { method, headers: token ? { "X-CSRF-Token": token } : {} });
      assert.equal(response.status, 403);
    }
  }
  assert.equal((await client.fetch("/api/auth/session")).status, 200);
});

test("public repository responses exclude private/unknown metadata on fresh, cached and fallback paths", async (t) => {
  const server = await startServer(t);
  for (const query of ["?refresh=1", ""]) {
    const response = await fetch(server.url + "/api/repositories" + query);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.deepEqual(body.repositories.map((repo) => repo.name), ["public-project"]);
    assert.doesNotMatch(JSON.stringify(body), /private-project|private-description|unknown-visibility/);
  }
  server.offline();
  const fallback = await (await fetch(server.url + "/api/repositories?refresh=1")).json();
  assert.equal(fallback.source, "fallback");
  assert.deepEqual(fallback.repositories.map((repo) => repo.name), ["PALACO"]);
  assert.ok(fallback.repositories.every((repo) => repo.visibility === "public"));
});

for (const [name, env, secure] of [
  ["local HTTP", {}, false],
  ["production HTTPS", { NODE_ENV: "production", SESSION_COOKIE_SECURE: "false" }, true],
  ["configured HTTPS", { SESSION_COOKIE_SECURE: "true" }, true],
]) {
  test(`${name}: session and clearing cookies have matching security flags`, async (t) => {
    const server = await startServer(t, env);
    const client = browser(server);
    const response = await signup(client);
    const body = await response.json();
    const logout = await client.fetch("/api/auth/logout", { method: "POST", headers: { "X-CSRF-Token": body.csrfToken } });
    assert.equal(logout.status, 200);
    for (const result of [response, logout]) {
      const cookie = result.headers.get("set-cookie");
      assert.match(cookie, /HttpOnly/);
      assert.match(cookie, /SameSite=Strict/);
      assert.equal(/(?:^|; )Secure(?:;|$)/.test(cookie), secure);
    }
  });
}
