const http = require("node:http");
const fs = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");

const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT || 3000);
const ROOT_DIR = __dirname;
const DATA_DIR = path.join(ROOT_DIR, "data");
const STORE_PATH = path.join(DATA_DIR, "palaco-store.json");
const sessions = new Map();
const REPOSITORY_CATALOG = [
  {
    key: "palaco",
    name: "PALACO",
    url: "https://github.com/Maurits-pixe/PALACO",
    description: "The broader PALACO repository and public project space.",
  },
  {
    key: "palaco-industrie",
    name: "PALACO-INDUSTRIE",
    url: "https://github.com/Maurits-pixe/PALACO-INDUSTRIE",
    description: "The implementation repository for the PALACO-INDUSTRIE prototype.",
  },
];

const STATIC_FILES = {
  "/": "index.html",
  "/index.html": "index.html",
  "/styles.css": "styles.css",
  "/app.js": "app.js",
};

const CONTENT_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
};

const defaultMessages = (name = "there") => [
  {
    role: "rio",
    text: `Welcome ${name}. I am RIO. I can help you create your Citadel and guide you through PALACO.`,
  },
];

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": CONTENT_TYPES[".json"],
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(payload));
}

function sendError(response, statusCode, message) {
  sendJson(response, statusCode, { error: message });
}

async function ensureStore() {
  await fs.mkdir(DATA_DIR, { recursive: true });

  try {
    await fs.access(STORE_PATH);
  } catch {
    await fs.writeFile(STORE_PATH, JSON.stringify({ users: [] }, null, 2));
  }
}

async function loadStore() {
  await ensureStore();
  const raw = await fs.readFile(STORE_PATH, "utf8");
  const store = JSON.parse(raw);
  return Array.isArray(store.users) ? store : { users: [] };
}

async function saveStore(store) {
  await ensureStore();
  await fs.writeFile(STORE_PATH, JSON.stringify(store, null, 2));
}

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    let data = "";

    request.on("data", (chunk) => {
      data += chunk;

      if (data.length > 1_000_000) {
        reject(new Error("Request body is too large."));
        request.destroy();
      }
    });

    request.on("end", () => {
      if (!data) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error("Request body must be valid JSON."));
      }
    });

    request.on("error", reject);
  });
}

function normaliseEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function cleanText(value, maxLength) {
  return String(value || "").trim().slice(0, maxLength);
}

function buildPublicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    language: user.language,
    createdAt: user.createdAt,
  };
}

function buildCitadel(user) {
  return {
    ownerName: user.citadel?.ownerName || user.name,
    citadelName: user.citadel?.citadelName || "",
    citadelTheme: user.citadel?.citadelTheme || "light",
    citadelDescription: user.citadel?.citadelDescription || "",
  };
}

function buildRioReply(text, user) {
  const message = text.toLowerCase();
  const citadel = buildCitadel(user);

  if (message.includes("citadel") || message.includes("space")) {
    return citadel.citadelName
      ? `Your Citadel is ${citadel.citadelName}. You can continue shaping it whenever you want.`
      : "You do not have a saved Citadel yet. Start by giving it a name and short description.";
  }

  if (message.includes("world") || message.includes("logo")) {
    return "Open L.O.G.O. to explore the guided PALACO destinations in this first version.";
  }

  if (message.includes("hello") || message.includes("hi")) {
    return `Hello ${user.name}. Tell me what you want your Citadel to become.`;
  }

  return "I can help with your account, your Citadel, RIO, or the guided L.O.G.O. experience.";
}

function createSession(userId) {
  const token = crypto.randomBytes(24).toString("hex");
  sessions.set(token, userId);
  return token;
}

function getSessionToken(request) {
  const header = request.headers.authorization || "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

async function getAuthenticatedUser(request) {
  const token = getSessionToken(request);

  if (!token || !sessions.has(token)) {
    return null;
  }

  const userId = sessions.get(token);
  const store = await loadStore();
  const user = store.users.find((candidate) => candidate.id === userId);

  if (!user) {
    sessions.delete(token);
    return null;
  }

  return { token, store, user };
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = await new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, result) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(result);
    });
  });

  return `${salt}:${derivedKey.toString("hex")}`;
}

async function verifyPassword(password, storedValue) {
  const [salt, hash] = String(storedValue).split(":");

  if (!salt || !hash) {
    return false;
  }

  const derivedKey = await new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, result) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(result);
    });
  });

  const storedBuffer = Buffer.from(hash, "hex");
  return (
    storedBuffer.length === derivedKey.length &&
    crypto.timingSafeEqual(storedBuffer, derivedKey)
  );
}

async function handleSignup(request, response) {
  const body = await readRequestBody(request);
  const name = cleanText(body.name, 60);
  const email = normaliseEmail(body.email);
  const password = String(body.password || "");
  const language = cleanText(body.language || "English", 40) || "English";

  if (!name || !email || !password) {
    sendError(response, 400, "Name, email, and password are required.");
    return;
  }

  if (password.length < 8) {
    sendError(response, 400, "Password must be at least 8 characters.");
    return;
  }

  const store = await loadStore();
  const exists = store.users.some((user) => user.email === email);

  if (exists) {
    sendError(response, 409, "An account with that email already exists.");
    return;
  }

  const user = {
    id: crypto.randomUUID(),
    name,
    email,
    language,
    passwordHash: await hashPassword(password),
    createdAt: new Date().toISOString(),
    citadel: {
      ownerName: name,
      citadelName: "",
      citadelTheme: "light",
      citadelDescription: "",
    },
    messages: defaultMessages(name),
  };

  store.users.push(user);
  await saveStore(store);

  const token = createSession(user.id);
  sendJson(response, 201, {
    token,
    user: buildPublicUser(user),
    citadel: buildCitadel(user),
    messages: user.messages,
  });
}

async function handleLogin(request, response) {
  const body = await readRequestBody(request);
  const email = normaliseEmail(body.email);
  const password = String(body.password || "");

  if (!email || !password) {
    sendError(response, 400, "Email and password are required.");
    return;
  }

  const store = await loadStore();
  const user = store.users.find((candidate) => candidate.email === email);

  if (!user || !(await verifyPassword(password, user.passwordHash))) {
    sendError(response, 401, "Incorrect email or password.");
    return;
  }

  const token = createSession(user.id);
  sendJson(response, 200, {
    token,
    user: buildPublicUser(user),
    citadel: buildCitadel(user),
    messages: Array.isArray(user.messages) ? user.messages : defaultMessages(user.name),
  });
}

async function handleSession(request, response) {
  const auth = await getAuthenticatedUser(request);

  if (!auth) {
    sendError(response, 401, "Sign in to continue.");
    return;
  }

  sendJson(response, 200, { user: buildPublicUser(auth.user) });
}

function handleLogout(request, response) {
  const token = getSessionToken(request);

  if (token) {
    sessions.delete(token);
  }

  sendJson(response, 200, { ok: true });
}

async function handleGetCitadel(request, response) {
  const auth = await getAuthenticatedUser(request);

  if (!auth) {
    sendError(response, 401, "Sign in to load your Citadel.");
    return;
  }

  sendJson(response, 200, { citadel: buildCitadel(auth.user) });
}

async function handleSaveCitadel(request, response) {
  const auth = await getAuthenticatedUser(request);

  if (!auth) {
    sendError(response, 401, "Sign in to save your Citadel.");
    return;
  }

  const body = await readRequestBody(request);
  const ownerName = cleanText(body.ownerName || auth.user.name, 60) || auth.user.name;
  const citadelName = cleanText(body.citadelName, 80);
  const citadelTheme = ["light", "sunrise", "forest", "midnight"].includes(body.citadelTheme)
    ? body.citadelTheme
    : "light";
  const citadelDescription = cleanText(body.citadelDescription, 220);

  if (!citadelName) {
    sendError(response, 400, "Please choose a Citadel name.");
    return;
  }

  auth.user.citadel = {
    ownerName,
    citadelName,
    citadelTheme,
    citadelDescription,
  };

  await saveStore(auth.store);
  sendJson(response, 200, { citadel: buildCitadel(auth.user) });
}

async function handleGetMessages(request, response) {
  const auth = await getAuthenticatedUser(request);

  if (!auth) {
    sendError(response, 401, "Sign in to load RIO history.");
    return;
  }

  if (!Array.isArray(auth.user.messages) || auth.user.messages.length === 0) {
    auth.user.messages = defaultMessages(auth.user.name);
    await saveStore(auth.store);
  }

  sendJson(response, 200, { messages: auth.user.messages });
}

async function handlePostMessage(request, response) {
  const auth = await getAuthenticatedUser(request);

  if (!auth) {
    sendError(response, 401, "Sign in to talk with RIO.");
    return;
  }

  const body = await readRequestBody(request);
  const text = cleanText(body.text, 200);

  if (!text) {
    sendError(response, 400, "Please write a message first.");
    return;
  }

  const messages = Array.isArray(auth.user.messages)
    ? auth.user.messages
    : defaultMessages(auth.user.name);

  messages.push({ role: "user", text });
  messages.push({ role: "rio", text: buildRioReply(text, auth.user) });
  auth.user.messages = messages;

  await saveStore(auth.store);
  sendJson(response, 201, { messages: auth.user.messages });
}

async function serveStaticAsset(request, response, pathname) {
  const fileName = STATIC_FILES[pathname];

  if (!fileName) {
    sendError(response, 404, "Not found.");
    return;
  }

  const filePath = path.join(ROOT_DIR, fileName);
  const extension = path.extname(filePath);
  const content = await fs.readFile(filePath);

  response.writeHead(200, {
    "Content-Type": CONTENT_TYPES[extension] || "application/octet-stream",
  });
  response.end(content);
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    const { pathname } = url;

    if (request.method === "GET" && pathname === "/api/health") {
      sendJson(response, 200, { ok: true });
      return;
    }

    if (request.method === "POST" && pathname === "/api/auth/signup") {
      await handleSignup(request, response);
      return;
    }

    if (request.method === "POST" && pathname === "/api/auth/login") {
      await handleLogin(request, response);
      return;
    }

    if (request.method === "GET" && pathname === "/api/auth/session") {
      await handleSession(request, response);
      return;
    }

    if (request.method === "POST" && pathname === "/api/auth/logout") {
      handleLogout(request, response);
      return;
    }

    if (request.method === "GET" && pathname === "/api/repositories") {
      sendJson(response, 200, { repositories: REPOSITORY_CATALOG });
      return;
    }

    if (request.method === "GET" && pathname === "/api/citadel") {
      await handleGetCitadel(request, response);
      return;
    }

    if (request.method === "PUT" && pathname === "/api/citadel") {
      await handleSaveCitadel(request, response);
      return;
    }

    if (request.method === "GET" && pathname === "/api/messages") {
      await handleGetMessages(request, response);
      return;
    }

    if (request.method === "POST" && pathname === "/api/messages") {
      await handlePostMessage(request, response);
      return;
    }

    if (request.method === "GET" && STATIC_FILES[pathname]) {
      await serveStaticAsset(request, response, pathname);
      return;
    }

    sendError(response, 404, "Not found.");
  } catch (error) {
    const statusCode = error.message.includes("JSON") ? 400 : 500;
    sendError(response, statusCode, error.message || "Unexpected server error.");
  }
});

server.listen(PORT, HOST, () => {
  console.log(`PALACO server running on http://${HOST}:${PORT}`);
});
