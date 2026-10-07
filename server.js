const http = require("node:http");
const fs = require("node:fs");
const fsPromises = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");

const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT || 3000);
const GITHUB_OWNER = process.env.GITHUB_OWNER || "Maurits-pixe";
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || "";
const SESSION_TTL_DAYS = Number(process.env.SESSION_TTL_DAYS || 30);
const SESSION_COOKIE_NAME = "palaco_session";
const SESSION_COOKIE_SECURE = process.env.NODE_ENV === "production" || process.env.SESSION_COOKIE_SECURE === "true";
const ROOT_DIR = __dirname;
const DATA_DIR = path.join(ROOT_DIR, "data");
const DATABASE_PATH = path.join(DATA_DIR, "palaco.db");
const LEGACY_STORE_PATH = path.join(DATA_DIR, "palaco-store.json");

const DEFAULT_REPOSITORY_CATALOG = [
  {
    key: "palaco",
    name: "PALACO",
    url: "https://github.com/Maurits-pixe/PALACO",
    description: "The broader PALACO repository and public project space.",
    visibility: "public",
  },
];

let repositoryCache = {
  owner: GITHUB_OWNER,
  repositories: DEFAULT_REPOSITORY_CATALOG,
  fetchedAt: 0,
  source: "fallback",
};

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

const THEMES = new Set(["light", "sunrise", "forest", "midnight"]);

let database;

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

function sendJsonWithHeaders(response, statusCode, payload, headers) {
  response.writeHead(statusCode, {
    "Content-Type": CONTENT_TYPES[".json"],
    "Cache-Control": "no-store",
    ...headers,
  });
  response.end(JSON.stringify(payload));
}

function sendError(response, statusCode, message) {
  sendJson(response, statusCode, { error: message });
}

function cleanText(value, maxLength) {
  return String(value || "").trim().slice(0, maxLength);
}

function normaliseEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function repositoryKey(name) {
  return String(name || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
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

function mapUserRow(row) {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    name: row.name,
    email: row.email,
    language: row.language,
    passwordHash: row.password_hash,
    createdAt: row.created_at,
  };
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

function buildCitadel(user, row = null) {
  return {
    ownerName: row?.owner_name || user.name,
    citadelName: row?.citadel_name || "",
    citadelTheme: row?.citadel_theme || "light",
    citadelDescription: row?.citadel_description || "",
  };
}

function buildRioReply(text, user, citadel) {
  const message = text.toLowerCase();

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

function openDatabase() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  database = new DatabaseSync(DATABASE_PATH);
  database.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      language TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS citadels (
      user_id TEXT PRIMARY KEY,
      owner_name TEXT NOT NULL,
      citadel_name TEXT NOT NULL,
      citadel_theme TEXT NOT NULL,
      citadel_description TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      role TEXT NOT NULL,
      text TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      csrf_token TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS mutation_tickets (
      id TEXT PRIMARY KEY,
      action_type TEXT NOT NULL,
      payload TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      is_consumed INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_tickets_expires ON mutation_tickets(expires_at);
    CREATE INDEX IF NOT EXISTS idx_tickets_owner ON mutation_tickets(owner_id);
  `);
}

function databaseHasUsers() {
  const row = database.prepare("SELECT COUNT(*) AS count FROM users").get();
  return Number(row?.count || 0) > 0;
}

function runInTransaction(callback) {
  database.exec("BEGIN");

  try {
    const result = callback();
    database.exec("COMMIT");
    return result;
  } catch (error) {
    database.exec("ROLLBACK");
    throw error;
  }
}

function nowIso() {
  return new Date().toISOString();
}

function buildSessionExpiry() {
  return new Date(Date.now() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString();
}

function createCsrfToken() {
  return crypto.randomBytes(24).toString("hex");
}

function sessionMaxAgeSeconds() {
  return Math.max(1, Math.floor(SESSION_TTL_DAYS * 24 * 60 * 60));
}

function hashSessionToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

function parseCookies(request) {
  const raw = request.headers.cookie || "";
  const cookies = {};

  for (const part of raw.split(";")) {
    const trimmed = part.trim();

    if (!trimmed) {
      continue;
    }

    const separatorIndex = trimmed.indexOf("=");
    const key = separatorIndex >= 0 ? trimmed.slice(0, separatorIndex) : trimmed;
    const value = separatorIndex >= 0 ? trimmed.slice(separatorIndex + 1) : "";
    cookies[key] = decodeURIComponent(value);
  }

  return cookies;
}

function buildSessionCookie(token) {
  return [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
    "HttpOnly",
    "Path=/",
    "SameSite=Strict",
    ...(SESSION_COOKIE_SECURE ? ["Secure"] : []),
    `Max-Age=${sessionMaxAgeSeconds()}`,
  ].join("; ");
}

function clearSessionCookie() {
  return [
    `${SESSION_COOKIE_NAME}=`,
    "HttpOnly",
    "Path=/",
    "SameSite=Strict",
    ...(SESSION_COOKIE_SECURE ? ["Secure"] : []),
    "Max-Age=0",
  ].join("; ");
}

function getUserById(userId) {
  return mapUserRow(
    database
      .prepare(
        "SELECT id, name, email, language, password_hash, created_at FROM users WHERE id = ?"
      )
      .get(userId)
  );
}

function getUserByEmail(email) {
  return mapUserRow(
    database
      .prepare(
        "SELECT id, name, email, language, password_hash, created_at FROM users WHERE email = ?"
      )
      .get(email)
  );
}

function getCitadelRowByUserId(userId) {
  return (
    database
      .prepare(
        "SELECT owner_name, citadel_name, citadel_theme, citadel_description FROM citadels WHERE user_id = ?"
      )
      .get(userId) || null
  );
}

function getMessagesByUserId(userId) {
  const rows = database
    .prepare("SELECT role, text FROM messages WHERE user_id = ? ORDER BY id ASC")
    .all(userId);

  return rows.map((row) => ({
    role: row.role,
    text: row.text,
  }));
}

function insertMessages(userId, messages) {
  const statement = database.prepare(
    "INSERT INTO messages (user_id, role, text, created_at) VALUES (?, ?, ?, ?)"
  );
  const timestamp = new Date().toISOString();

  for (const message of messages) {
    statement.run(userId, message.role, cleanText(message.text, 500), timestamp);
  }
}

function ensureMessagesForUser(user) {
  const messages = getMessagesByUserId(user.id);

  if (messages.length > 0) {
    return messages;
  }

  insertMessages(user.id, defaultMessages(user.name));
  return getMessagesByUserId(user.id);
}

function ensureSessionSchema() {
  const columns = database.prepare("PRAGMA table_info(sessions)").all();
  const hasToken = columns.some((column) => column.name === "token");
  const hasCsrfToken = columns.some((column) => column.name === "csrf_token");

  if (hasToken) {
    const legacySessions = database
      .prepare("SELECT token, user_id, created_at, last_seen_at, expires_at FROM sessions")
      .all();

    runInTransaction(() => {
      database.exec("ALTER TABLE sessions RENAME TO sessions_legacy");
      database.exec(`
        CREATE TABLE sessions (
          token_hash TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          csrf_token TEXT NOT NULL,
          created_at TEXT NOT NULL,
          last_seen_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);

      const insert = database.prepare(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
      );

      for (const session of legacySessions) {
        insert.run(
          hashSessionToken(session.token),
          session.user_id,
          createCsrfToken(),
          session.created_at,
          session.last_seen_at,
          session.expires_at
        );
      }

      database.exec("DROP TABLE sessions_legacy");
    });
    return;
  }

  if (!hasCsrfToken) {
    runInTransaction(() => {
      database.exec("ALTER TABLE sessions ADD COLUMN csrf_token TEXT");
      const rows = database
        .prepare("SELECT token_hash FROM sessions WHERE csrf_token IS NULL OR csrf_token = ''")
        .all();
      const update = database.prepare("UPDATE sessions SET csrf_token = ? WHERE token_hash = ?");

      for (const row of rows) {
        update.run(createCsrfToken(), row.token_hash);
      }
    });
  }
}

function createUserRecord({ name, email, language, passwordHash }) {
  const user = {
    id: crypto.randomUUID(),
    name,
    email,
    language,
    passwordHash,
    createdAt: new Date().toISOString(),
  };

  runInTransaction(() => {
    database
      .prepare(
        "INSERT INTO users (id, name, email, language, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)"
      )
      .run(
        user.id,
        user.name,
        user.email,
        user.language,
        user.passwordHash,
        user.createdAt
      );

    database
      .prepare(
        "INSERT INTO citadels (user_id, owner_name, citadel_name, citadel_theme, citadel_description) VALUES (?, ?, ?, ?, ?)"
      )
      .run(user.id, user.name, "", "light", "");

    insertMessages(user.id, defaultMessages(user.name));
  });

  return user;
}

function saveCitadelForUser(user, citadel) {
  database
    .prepare(
      `INSERT INTO citadels (user_id, owner_name, citadel_name, citadel_theme, citadel_description)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET
         owner_name = excluded.owner_name,
         citadel_name = excluded.citadel_name,
         citadel_theme = excluded.citadel_theme,
         citadel_description = excluded.citadel_description`
    )
    .run(
      user.id,
      citadel.ownerName,
      citadel.citadelName,
      citadel.citadelTheme,
      citadel.citadelDescription
    );

  return buildCitadel(user, getCitadelRowByUserId(user.id));
}

function deleteSession(token) {
  database.prepare("DELETE FROM sessions WHERE token_hash = ?").run(hashSessionToken(token));
}

function cleanupExpiredSessions() {
  database.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(nowIso());
}

function persistSession(userId) {
  const token = crypto.randomBytes(24).toString("hex");
  const createdAt = nowIso();
  const csrfToken = createCsrfToken();

  database
    .prepare(
      "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .run(hashSessionToken(token), userId, csrfToken, createdAt, createdAt, buildSessionExpiry());

  return { token, csrfToken };
}

function getSessionRecord(token) {
  return (
    database
      .prepare(
        `SELECT token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at
         FROM sessions
         WHERE token_hash = ?`
      )
      .get(hashSessionToken(token)) || null
  );
}

function touchSession(token) {
  database
    .prepare("UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE token_hash = ?")
    .run(nowIso(), buildSessionExpiry(), hashSessionToken(token));
}

function appendConversation(user, userMessage, rioMessage) {
  runInTransaction(() => {
    insertMessages(user.id, [
      { role: "user", text: userMessage },
      { role: "rio", text: rioMessage },
    ]);
  });

  return getMessagesByUserId(user.id);
}

function migrateLegacyStore() {
  if (databaseHasUsers() || !fs.existsSync(LEGACY_STORE_PATH)) {
    return;
  }

  let parsed;

  try {
    parsed = JSON.parse(fs.readFileSync(LEGACY_STORE_PATH, "utf8"));
  } catch {
    return;
  }

  const users = Array.isArray(parsed?.users) ? parsed.users : [];

  if (users.length === 0) {
    return;
  }

  runInTransaction(() => {
    for (const legacyUser of users) {
      const id = cleanText(legacyUser.id || crypto.randomUUID(), 80);
      const name = cleanText(legacyUser.name, 60);
      const email = normaliseEmail(legacyUser.email);
      const language = cleanText(legacyUser.language || "English", 40) || "English";
      const passwordHash = cleanText(legacyUser.passwordHash, 255);
      const createdAt = cleanText(legacyUser.createdAt, 64) || new Date().toISOString();

      if (!id || !name || !email || !passwordHash) {
        continue;
      }

      database
        .prepare(
          "INSERT OR IGNORE INTO users (id, name, email, language, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .run(id, name, email, language, passwordHash, createdAt);

      const legacyCitadel = legacyUser.citadel || {};
      database
        .prepare(
          `INSERT OR REPLACE INTO citadels (user_id, owner_name, citadel_name, citadel_theme, citadel_description)
           VALUES (?, ?, ?, ?, ?)`
        )
        .run(
          id,
          cleanText(legacyCitadel.ownerName || name, 60) || name,
          cleanText(legacyCitadel.citadelName, 80),
          THEMES.has(legacyCitadel.citadelTheme) ? legacyCitadel.citadelTheme : "light",
          cleanText(legacyCitadel.citadelDescription, 220)
        );

      database.prepare("DELETE FROM messages WHERE user_id = ?").run(id);
      const legacyMessages =
        Array.isArray(legacyUser.messages) && legacyUser.messages.length > 0
          ? legacyUser.messages
          : defaultMessages(name);
      insertMessages(id, legacyMessages);
    }
  });
}

async function fetchGitHubRepositories() {
  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "PALACO-INDUSTRIE",
  };

  if (GITHUB_TOKEN) {
    headers.Authorization = "Bearer " + GITHUB_TOKEN;
  }

  const repositories = [];
  let page = 1;

  while (page <= 10) {
    const endpoint = GITHUB_TOKEN
      ? `https://api.github.com/user/repos?affiliation=owner&sort=updated&per_page=100&page=${page}`
      : `https://api.github.com/users/${encodeURIComponent(
          GITHUB_OWNER
        )}/repos?sort=updated&per_page=100&page=${page}`;
    const response = await fetch(endpoint, { headers });

    if (!response.ok) {
      throw new Error(`GitHub sync failed with status ${response.status}.`);
    }

    const payload = await response.json();
    const pageItems = Array.isArray(payload) ? payload : [];
    const ownedItems = pageItems.filter(
      (repository) => repository?.owner?.login?.toLowerCase() === GITHUB_OWNER.toLowerCase()
        && repository.private === false
    );

    repositories.push(
      ...ownedItems.map((repository) => ({
        key: repositoryKey(repository.name),
        name: repository.name,
        url: repository.html_url,
        description:
          cleanText(repository.description, 200) ||
          `Repository from ${GITHUB_OWNER}'s PALACO network.`,
        visibility: repository.private ? "private" : "public",
      }))
    );

    if (pageItems.length < 100) {
      break;
    }

    page += 1;
  }

  if (repositories.length === 0) {
    throw new Error("GitHub sync returned no repositories.");
  }

  return repositories;
}

async function getRepositoryCatalog(forceRefresh = false) {
  const cacheIsFresh = Date.now() - repositoryCache.fetchedAt < 5 * 60 * 1000;

  if (!forceRefresh && cacheIsFresh && repositoryCache.repositories.length > 0) {
    return repositoryCache;
  }

  try {
    const repositories = await fetchGitHubRepositories();
    repositoryCache = {
      owner: GITHUB_OWNER,
      repositories,
      fetchedAt: Date.now(),
      source: GITHUB_TOKEN ? "github-authenticated" : "github-public",
    };
  } catch {
    repositoryCache = {
      owner: GITHUB_OWNER,
      repositories: DEFAULT_REPOSITORY_CATALOG,
      fetchedAt: Date.now(),
      source: "fallback",
    };
  }

  return repositoryCache;
}

function createSession(userId) {
  cleanupExpiredSessions();
  return persistSession(userId);
}

function verifyCsrfToken(request, session) {
  const headerToken = request.headers["x-csrf-token"];
  return typeof headerToken === "string" && headerToken === session.csrf_token;
}

function getSessionToken(request) {
  const cookies = parseCookies(request);

  if (cookies[SESSION_COOKIE_NAME]) {
    return cookies[SESSION_COOKIE_NAME];
  }

  const header = request.headers.authorization || "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

function getAuthenticatedUser(request) {
  const token = getSessionToken(request);

  if (!token) {
    return null;
  }

  cleanupExpiredSessions();
  const session = getSessionRecord(token);

  if (!session) {
    return null;
  }

  const user = getUserById(session.user_id);

  if (!user) {
    deleteSession(token);
    return null;
  }

  touchSession(token);
  return { token, user, session: getSessionRecord(token) };
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

  if (getUserByEmail(email)) {
    sendError(response, 409, "An account with that email already exists.");
    return;
  }

  const user = createUserRecord({
    name,
    email,
    language,
    passwordHash: await hashPassword(password),
  });
  const { token, csrfToken } = createSession(user.id);

  sendJsonWithHeaders(
    response,
    201,
    {
      user: buildPublicUser(user),
      citadel: buildCitadel(user, getCitadelRowByUserId(user.id)),
      messages: getMessagesByUserId(user.id),
      csrfToken,
    },
    { "Set-Cookie": buildSessionCookie(token) }
  );
}

async function handleLogin(request, response) {
  const body = await readRequestBody(request);
  const email = normaliseEmail(body.email);
  const password = String(body.password || "");

  if (!email || !password) {
    sendError(response, 400, "Email and password are required.");
    return;
  }

  const user = getUserByEmail(email);

  if (!user || !(await verifyPassword(password, user.passwordHash))) {
    sendError(response, 401, "Incorrect email or password.");
    return;
  }

  const { token, csrfToken } = createSession(user.id);
  sendJsonWithHeaders(
    response,
    200,
    {
      user: buildPublicUser(user),
      citadel: buildCitadel(user, getCitadelRowByUserId(user.id)),
      messages: ensureMessagesForUser(user),
      csrfToken,
    },
    { "Set-Cookie": buildSessionCookie(token) }
  );
}

async function handleSession(request, response) {
  const auth = getAuthenticatedUser(request);

  if (!auth) {
    sendError(response, 401, "Sign in to continue.");
    return;
  }

  sendJson(response, 200, { user: buildPublicUser(auth.user), csrfToken: auth.session.csrf_token });
}

function handleLogout(request, response) {
  const auth = getAuthenticatedUser(request);

  if (!auth) {
    sendJsonWithHeaders(response, 200, { ok: true }, { "Set-Cookie": clearSessionCookie() });
    return;
  }

  if (!verifyCsrfToken(request, auth.session)) {
    sendError(response, 403, "Invalid CSRF token.");
    return;
  }

  deleteSession(auth.token);

  sendJsonWithHeaders(response, 200, { ok: true }, { "Set-Cookie": clearSessionCookie() });
}

async function handleGetCitadel(request, response) {
  const auth = getAuthenticatedUser(request);

  if (!auth) {
    sendError(response, 401, "Sign in to load your Citadel.");
    return;
  }

  sendJson(response, 200, {
    citadel: buildCitadel(auth.user, getCitadelRowByUserId(auth.user.id)),
  });
}

async function handleSaveCitadel(request, response) {
  const auth = getAuthenticatedUser(request);

  if (!auth) {
    sendError(response, 401, "Sign in to save your Citadel.");
    return;
  }

  if (!verifyCsrfToken(request, auth.session)) {
    sendError(response, 403, "Invalid CSRF token.");
    return;
  }

  const body = await readRequestBody(request);
  const citadel = {
    ownerName: cleanText(body.ownerName || auth.user.name, 60) || auth.user.name,
    citadelName: cleanText(body.citadelName, 80),
    citadelTheme: THEMES.has(body.citadelTheme) ? body.citadelTheme : "light",
    citadelDescription: cleanText(body.citadelDescription, 220),
  };

  if (!citadel.citadelName) {
    sendError(response, 400, "Please choose a Citadel name.");
    return;
  }

  sendJson(response, 200, {
    citadel: saveCitadelForUser(auth.user, citadel),
  });
}

async function handleGetMessages(request, response) {
  const auth = getAuthenticatedUser(request);

  if (!auth) {
    sendError(response, 401, "Sign in to load RIO history.");
    return;
  }

  sendJson(response, 200, { messages: ensureMessagesForUser(auth.user) });
}

async function handlePostMessage(request, response) {
  const auth = getAuthenticatedUser(request);

  if (!auth) {
    sendError(response, 401, "Sign in to talk with RIO.");
    return;
  }

  if (!verifyCsrfToken(request, auth.session)) {
    sendError(response, 403, "Invalid CSRF token.");
    return;
  }

  const body = await readRequestBody(request);
  const text = cleanText(body.text, 200);

  if (!text) {
    sendError(response, 400, "Please write a message first.");
    return;
  }

  const citadel = buildCitadel(auth.user, getCitadelRowByUserId(auth.user.id));
  const reply = buildRioReply(text, auth.user, citadel);
  const messages = appendConversation(auth.user, text, reply);

  sendJson(response, 201, { messages });
}

async function handlePrepareMutation(request, response) {
  const auth = getAuthenticatedUser(request);

  if (!auth) {
    sendError(response, 401, "Sign in to prepare a mutation.");
    return;
  }

  if (!verifyCsrfToken(request, auth.session)) {
    sendError(response, 403, "Invalid CSRF token.");
    return;
  }

  const body = await readRequestBody(request);
  const action = cleanText(body.action, 40);
  const payload = body.payload && typeof body.payload === "object" ? body.payload : null;

  if (!action || !payload) {
    sendError(response, 400, "Action and payload are required.");
    return;
  }

  const ticketId = crypto.randomUUID();
  const createdAt = Date.now();
  const expiresAt = createdAt + 30_000;

  database
    .prepare(
      `INSERT INTO mutation_tickets (id, action_type, payload, owner_id, created_at, expires_at, is_consumed)
       VALUES (?, ?, ?, ?, ?, ?, 0)`
    )
    .run(ticketId, action, JSON.stringify(payload), auth.user.id, nowIso(), expiresAt);

  sendJson(response, 201, {
    ticketId,
    expiresAt,
    message: "Mutatie voorbereid. Bevestig binnen 30 seconden.",
  });
}

async function handleExecuteMutation(request, response) {
  const auth = getAuthenticatedUser(request);

  if (!auth) {
    sendError(response, 401, "Sign in to execute a mutation.");
    return;
  }

  if (!verifyCsrfToken(request, auth.session)) {
    sendError(response, 403, "Invalid CSRF token.");
    return;
  }

  const body = await readRequestBody(request);
  const ticketId = cleanText(body.ticketId, 80);

  if (!ticketId) {
    sendError(response, 400, "Missing ticketId");
    return;
  }

  const runMutation = database.transaction(() => {
    const ticket = database.prepare("SELECT * FROM mutation_tickets WHERE id = ?").get(ticketId);

    if (!ticket) {
      throw new Error("TICKET_NOT_FOUND");
    }

    if (ticket.owner_id !== auth.user.id) {
      throw new Error("TICKET_OWNER_MISMATCH");
    }

    if (ticket.is_consumed) {
      throw new Error("TICKET_ALREADY_USED");
    }

    const now = Date.now();
    if (now >= ticket.expires_at) {
      throw new Error("CONSENT_EXPIRED_D013");
    }

    const payload = JSON.parse(ticket.payload);
    let result;

    if (ticket.action_type === "COMPLETE") {
      result = database
        .prepare("UPDATE citadels SET citadel_description = citadel_description WHERE user_id = ?")
        .run(auth.user.id);
    } else if (ticket.action_type === "ESCALATE") {
      result = database
        .prepare("UPDATE citadels SET citadel_theme = citadel_theme WHERE user_id = ?")
        .run(auth.user.id);
    } else {
      throw new Error("UNKNOWN_ACTION");
    }

    if (!payload.taskId) {
      throw new Error("INVALID_PAYLOAD");
    }

    if (result.changes === 0) {
      throw new Error("NO_MUTATION_APPLIED");
    }

    database
      .prepare("UPDATE mutation_tickets SET is_consumed = 1 WHERE id = ?")
      .run(ticketId);

    return {
      success: true,
      mutatedAt: now,
      changes: result.changes,
    };
  });

  try {
    const result = runMutation.immediate();
    sendJson(response, 200, result);
  } catch (error) {
    if (error.message === "CONSENT_EXPIRED_D013") {
      sendJson(response, 403, {
        success: false,
        error: "CONSENT_EXPIRED",
        code: "D013_VIOLATION",
        message: "Toestemming verlopen vóór opslag. Wijziging NIET doorgevoerd.",
      });
      return;
    }

    if (error.message === "TICKET_NOT_FOUND") {
      sendJson(response, 404, { success: false, error: "TICKET_NOT_FOUND" });
      return;
    }

    if (error.message === "TICKET_OWNER_MISMATCH") {
      sendJson(response, 403, { success: false, error: "TICKET_OWNER_MISMATCH" });
      return;
    }

    sendJson(response, 400, { success: false, error: error.message });
  }
}

async function serveStaticAsset(response, pathname) {
  const fileName = STATIC_FILES[pathname];

  if (!fileName) {
    sendError(response, 404, "Not found.");
    return;
  }

  const filePath = path.join(ROOT_DIR, fileName);
  const extension = path.extname(filePath);
  const content = await fsPromises.readFile(filePath);

  response.writeHead(200, {
    "Content-Type": CONTENT_TYPES[extension] || "application/octet-stream",
  });
  response.end(content);
}

openDatabase();
ensureSessionSchema();
migrateLegacyStore();
cleanupExpiredSessions();

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
      const forceRefresh = url.searchParams.get("refresh") === "1";
      const catalog = await getRepositoryCatalog(forceRefresh);
      sendJson(response, 200, {
        ...catalog,
        repositories: catalog.repositories.filter((repository) => repository.visibility === "public"),
      });
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

    if (request.method === "POST" && pathname === "/api/mutations/prepare") {
      await handlePrepareMutation(request, response);
      return;
    }

    if (request.method === "POST" && pathname === "/api/mutations/execute") {
      await handleExecuteMutation(request, response);
      return;
    }

    if (request.method === "GET" && STATIC_FILES[pathname]) {
      await serveStaticAsset(response, pathname);
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
