const defaultCitadel = {
  ownerName: "",
  citadelName: "",
  citadelTheme: "light",
  citadelDescription: "",
};

const defaultMessages = [
  {
    role: "rio",
    text: "Welcome. I am RIO. Sign in to save your Citadel and your conversation.",
  },
];

const logoPages = {
  home: {
    label: "PALACO Welcome",
    path: "palaco://welcome",
    render: () => `
      <article class="logo-page">
        <h1>Welcome to PALACO</h1>
        <p>PALACO begins with clarity, calm language, and space you can shape yourself.</p>
        <ul>
          <li>Create your Citadel</li>
          <li>Talk with RIO</li>
          <li>Browse guided destinations</li>
        </ul>
      </article>
    `,
  },
  citadel: {
    label: "My Citadel",
    path: "palaco://citadel",
    render: (citadel) => `
      <article class="logo-page">
        <h1>${escapeHtml(citadel.citadelName || "Your Citadel")}</h1>
        <p><strong>Owner:</strong> ${escapeHtml(citadel.ownerName || "You")}</p>
        <p><strong>Theme:</strong> ${escapeHtml(formatTheme(citadel.citadelTheme))}</p>
        <p>${escapeHtml(
          citadel.citadelDescription || "Create your Citadel in the form to personalise this space."
        )}</p>
      </article>
    `,
  },
  learn: {
    label: "Learn & Explore",
    path: "palaco://learn",
    render: () => `
      <article class="logo-page">
        <h1>Learn & Explore</h1>
        <p>In future versions, this area can connect people to trusted knowledge, creative tools, and PALACO worlds.</p>
        <p>This first build keeps exploration simple and guided.</p>
      </article>
    `,
  },
  create: {
    label: "Build a World",
    path: "palaco://world-builder",
    render: () => `
      <article class="logo-page">
        <h1>Build a World</h1>
        <p>PALACO'S WORLD can grow into spaces for creativity, learning, and connection.</p>
        <p>Version 1 starts with one Citadel and a small set of guided destinations.</p>
      </article>
    `,
  },
};

const state = {
  user: null,
  csrfToken: "",
  citadel: { ...defaultCitadel },
  messages: [...defaultMessages],
  repositories: [],
  logoHistory: ["home"],
  logoHistoryIndex: 0,
};

const signupForm = document.getElementById("signup-form");
const loginForm = document.getElementById("login-form");
const signupStatus = document.getElementById("signup-status");
const loginStatus = document.getElementById("login-status");
const sessionStatus = document.getElementById("session-status");
const signoutButton = document.getElementById("signout-button");
const citadelForm = document.getElementById("citadel-form");
const resetCitadelButton = document.getElementById("reset-citadel");
const citadelStatus = document.getElementById("citadel-status");
const citadelAuthHint = document.getElementById("citadel-auth-hint");
const rioForm = document.getElementById("rio-form");
const rioInput = document.getElementById("rio-input");
const rioMessages = document.getElementById("rio-messages");
const rioAuthHint = document.getElementById("rio-auth-hint");
const logoDestination = document.getElementById("logo-destination");
const logoOpenButton = document.getElementById("logo-open");
const logoBackButton = document.getElementById("logo-back");
const logoForwardButton = document.getElementById("logo-forward");
const logoRefreshButton = document.getElementById("logo-refresh");
const logoAddress = document.getElementById("logo-address");
const logoFrame = document.getElementById("logo-frame");
const repoList = document.getElementById("repo-list");
const repoCount = document.getElementById("repo-count");
const repoRefreshButton = document.getElementById("repo-refresh");

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatTheme(theme) {
  return theme.charAt(0).toUpperCase() + theme.slice(1);
}

async function requestJson(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };

  if (!["GET", "HEAD"].includes((options.method || "GET").toUpperCase()) && state.csrfToken) {
    headers["X-CSRF-Token"] = state.csrfToken;
  }

  const response = await fetch(path, {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    credentials: "same-origin",
  });

  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    if (response.status === 401 && options.auth !== false) {
      clearSession(payload.error || "Your session expired.");
    }

    throw new Error(payload.error || "Something went wrong.");
  }

  return payload;
}

function setStatus(element, message, isError = false) {
  element.textContent = message;
  element.classList.toggle("is-error", isError);
}

function setFormBusy(form, busy) {
  form.querySelectorAll("input, select, textarea, button").forEach((element) => {
    element.disabled = busy;
  });
}

function setInteractiveState(authenticated) {
  citadelForm.querySelectorAll("input, select, textarea, button").forEach((element) => {
    element.disabled = !authenticated;
  });

  rioForm.querySelectorAll("input, button").forEach((element) => {
    element.disabled = !authenticated;
  });

  citadelAuthHint.textContent = authenticated
    ? "Your Citadel changes are saved to your PALACO account."
    : "Sign in first to save your Citadel on the server.";
  rioAuthHint.textContent = authenticated
    ? "RIO will reload your saved conversation whenever you return."
    : "Sign in to load your saved RIO conversation.";
}

function renderAccount(user) {
  document.getElementById("account-name").textContent = user ? user.name : "Not signed in";
  document.getElementById("account-email").textContent = user
    ? user.email
    : "Create an account to save your Citadel and RIO history.";
  document.getElementById("account-language").textContent = `Preferred language: ${
    user?.language || "-"
  }`;
  signoutButton.disabled = !user;
}

function renderRepositories() {
  if (state.repositories.length === 0) {
    repoCount.textContent = "No repositories are available yet.";
    repoList.innerHTML = "";
    return;
  }

  repoCount.textContent = `${state.repositories.length} repositories are available in this PALACO build.`;
  repoList.innerHTML = state.repositories
    .map(
      (repository) => `
        <article class="repository-card">
          <h3>${escapeHtml(repository.name)}</h3>
          <p class="repository-card__meta">Visibility: ${escapeHtml(
            repository.visibility || "unknown"
          )}</p>
          <p>${escapeHtml(repository.description)}</p>
          <div class="repository-card__actions">
            <button class="button button--secondary" type="button" data-logo-repo="${escapeHtml(
              repository.key
            )}">
              Open in L.O.G.O.
            </button>
            <a class="button button--ghost" href="${escapeHtml(
              repository.url
            )}" target="_blank" rel="noreferrer">
              View on GitHub
            </a>
          </div>
        </article>
      `
    )
    .join("");
}

function renderCitadel() {
  const citadel = state.citadel;
  document.getElementById("ownerName").value = citadel.ownerName;
  document.getElementById("citadelName").value = citadel.citadelName;
  document.getElementById("citadelTheme").value = citadel.citadelTheme;
  document.getElementById("citadelDescription").value = citadel.citadelDescription;
  document.getElementById("citadel-owner-preview").textContent = citadel.ownerName
    ? `Created for ${citadel.ownerName}.`
    : "Created for you.";
  document.getElementById("citadel-theme-preview").textContent = formatTheme(
    citadel.citadelTheme
  );
  document.getElementById("citadel-name-preview").textContent =
    citadel.citadelName || "No Citadel created yet";
  document.getElementById("citadel-description-preview").textContent =
    citadel.citadelDescription || "Save your first Citadel to see it appear here.";
}

function renderMessages() {
  rioMessages.innerHTML = "";

  state.messages.forEach((message) => {
    const element = document.createElement("article");
    element.className = `message message--${message.role}`;
    element.innerHTML = `<strong>${message.role === "rio" ? "RIO" : "You"}</strong><span>${escapeHtml(
      message.text
    )}</span>`;
    rioMessages.appendChild(element);
  });

  rioMessages.scrollTop = rioMessages.scrollHeight;
}

function buildDynamicLogoPage(pageKey) {
  if (!pageKey.startsWith("repo:")) {
    return null;
  }

  const repository = state.repositories.find((entry) => entry.key === pageKey.replace("repo:", ""));

  if (!repository) {
    return null;
  }

  return {
    path: `palaco://repository/${repository.key}`,
    render: () => `
      <article class="logo-page">
        <h1>${escapeHtml(repository.name)}</h1>
        <p>${escapeHtml(repository.description)}</p>
        <p><a href="${escapeHtml(
          repository.url
        )}" target="_blank" rel="noreferrer">Open this repository on GitHub</a></p>
      </article>
    `,
  };
}

function initLogoDestinations() {
  const currentValue = logoDestination.value;
  logoDestination.innerHTML = "";

  Object.entries(logoPages).forEach(([key, page]) => {
    const option = document.createElement("option");
    option.value = key;
    option.textContent = page.label;
    logoDestination.appendChild(option);
  });

  state.repositories.forEach((repository) => {
    const option = document.createElement("option");
    option.value = `repo:${repository.key}`;
    option.textContent = `Repository: ${repository.name}`;
    logoDestination.appendChild(option);
  });

  const hasCurrentValue = [...logoDestination.options].some((option) => option.value === currentValue);
  logoDestination.value = hasCurrentValue ? currentValue : "home";
}

function currentLogoPageKey() {
  return state.logoHistory[state.logoHistoryIndex] || "home";
}

function logoDocument(content) {
  return `<!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <style>
        body {
          margin: 0;
          padding: 1.5rem;
          font-family: Inter, system-ui, sans-serif;
          background: #ffffff;
          color: #10233d;
          line-height: 1.6;
        }
        .logo-page {
          max-width: 48rem;
          margin: 0 auto;
        }
        h1 {
          margin-top: 0;
          font-size: 2rem;
        }
      </style>
    </head>
    <body>${content}</body>
  </html>`;
}

function renderLogoPage(pageKey, replace = true) {
  const page = buildDynamicLogoPage(pageKey) || logoPages[pageKey] || logoPages.home;

  if (!replace) {
    state.logoHistory = state.logoHistory.slice(0, state.logoHistoryIndex + 1);
    state.logoHistory.push(pageKey);
    state.logoHistoryIndex = state.logoHistory.length - 1;
  }

  logoDestination.value = pageKey;
  logoAddress.textContent = page.path;
  logoFrame.srcdoc = logoDocument(page.render(state.citadel));
  logoBackButton.disabled = state.logoHistoryIndex === 0;
  logoForwardButton.disabled = state.logoHistoryIndex === state.logoHistory.length - 1;
}

function applySignedInState(payload, successMessage) {
  state.user = payload.user;
  state.csrfToken = payload.csrfToken || state.csrfToken;
  state.citadel = payload.citadel || { ...defaultCitadel, ownerName: payload.user.name };
  state.messages = Array.isArray(payload.messages) ? payload.messages : [...defaultMessages];
  renderAccount(state.user);
  renderCitadel();
  renderMessages();
  renderLogoPage(currentLogoPageKey());
  setInteractiveState(true);
  setStatus(sessionStatus, successMessage);
}

function clearSession(message = "Create an account or sign in to unlock saved progress.") {
  state.user = null;
  state.csrfToken = "";
  state.citadel = { ...defaultCitadel };
  state.messages = [...defaultMessages];
  renderAccount(null);
  renderCitadel();
  renderMessages();
  renderLogoPage(currentLogoPageKey());
  setInteractiveState(false);
  setStatus(sessionStatus, message);
}

async function restoreSession() {
  try {
    const session = await requestJson("/api/auth/session");
    const [citadel, messages] = await Promise.all([
      requestJson("/api/citadel"),
      requestJson("/api/messages"),
    ]);

    applySignedInState(
      { user: session.user, citadel: citadel.citadel, messages: messages.messages },
      `Welcome back ${session.user.name}.`
    );
  } catch (error) {
    clearSession(error.message);
  }
}

async function loadRepositories() {
  try {
    repoRefreshButton.disabled = true;
    repoCount.textContent = "Loading your repositories...";
    const payload = await requestJson(
      `/api/repositories${repoRefreshButton.dataset.refresh === "1" ? "?refresh=1" : ""}`,
      { auth: false }
    );
    state.repositories = Array.isArray(payload.repositories) ? payload.repositories : [];
    renderRepositories();
    repoCount.textContent = `${state.repositories.length} repositories loaded from ${payload.source}.`;
    initLogoDestinations();
    renderLogoPage(currentLogoPageKey());
  } catch (error) {
    repoCount.textContent = error.message;
  } finally {
    repoRefreshButton.disabled = false;
    repoRefreshButton.dataset.refresh = "0";
  }
}

signupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus(signupStatus, "");
  setStatus(loginStatus, "");
  setFormBusy(signupForm, true);

  try {
    const payload = await requestJson("/api/auth/signup", {
      method: "POST",
      body: {
        name: document.getElementById("signup-name").value.trim(),
        email: document.getElementById("signup-email").value.trim(),
        password: document.getElementById("signup-password").value,
        language: document.getElementById("signup-language").value,
      },
    });

    signupForm.reset();
    document.getElementById("signup-language").value = "English";
    applySignedInState(payload, `Account created for ${payload.user.name}.`);
    setStatus(signupStatus, "Account created.");
  } catch (error) {
    setStatus(signupStatus, error.message, true);
  } finally {
    setFormBusy(signupForm, false);
  }
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus(signupStatus, "");
  setStatus(loginStatus, "");
  setFormBusy(loginForm, true);

  try {
    const payload = await requestJson("/api/auth/login", {
      method: "POST",
      body: {
        email: document.getElementById("login-email").value.trim(),
        password: document.getElementById("login-password").value,
      },
    });

    loginForm.reset();
    applySignedInState(payload, `Signed in as ${payload.user.name}.`);
    setStatus(loginStatus, "Sign-in successful.");
  } catch (error) {
    setStatus(loginStatus, error.message, true);
  } finally {
    setFormBusy(loginForm, false);
  }
});

signoutButton.addEventListener("click", async () => {
  signoutButton.disabled = true;

  try {
    await requestJson("/api/auth/logout", { method: "POST" });
  } catch {
    // ignore logout errors and still clear the local session
  } finally {
    clearSession("You have signed out.");
  }
});

citadelForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  if (!state.user) {
    setStatus(citadelStatus, "Please sign in first.", true);
    return;
  }

  setStatus(citadelStatus, "");

  try {
    const formData = new FormData(citadelForm);
    const payload = await requestJson("/api/citadel", {
      method: "PUT",
      body: {
        ownerName: formData.get("ownerName").toString().trim(),
        citadelName: formData.get("citadelName").toString().trim(),
        citadelTheme: formData.get("citadelTheme").toString(),
        citadelDescription: formData.get("citadelDescription").toString().trim(),
      },
    });

    state.citadel = payload.citadel;
    renderCitadel();
    renderLogoPage(currentLogoPageKey());
    setStatus(citadelStatus, `${payload.citadel.citadelName} is saved.`);
  } catch (error) {
    setStatus(citadelStatus, error.message, true);
  }
});

resetCitadelButton.addEventListener("click", () => {
  renderCitadel();
  setStatus(citadelStatus, state.user ? "Restored your saved Citadel details." : "");
});

rioForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  if (!state.user) {
    setStatus(sessionStatus, "Please sign in before using RIO.", true);
    return;
  }

  const text = rioInput.value.trim();

  if (!text) {
    return;
  }

  try {
    const payload = await requestJson("/api/messages", {
      method: "POST",
      body: { text },
    });

    state.messages = payload.messages;
    renderMessages();
    rioInput.value = "";
    rioInput.focus();
    setStatus(sessionStatus, `RIO is active for ${state.user.name}.`);
  } catch (error) {
    setStatus(sessionStatus, error.message, true);
  }
});

logoOpenButton.addEventListener("click", () => {
  renderLogoPage(logoDestination.value, false);
});

logoBackButton.addEventListener("click", () => {
  if (state.logoHistoryIndex > 0) {
    state.logoHistoryIndex -= 1;
    renderLogoPage(currentLogoPageKey());
  }
});

logoForwardButton.addEventListener("click", () => {
  if (state.logoHistoryIndex < state.logoHistory.length - 1) {
    state.logoHistoryIndex += 1;
    renderLogoPage(currentLogoPageKey());
  }
});

logoRefreshButton.addEventListener("click", () => {
  renderLogoPage(currentLogoPageKey());
});

repoList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-logo-repo]");

  if (!button) {
    return;
  }

  const pageKey = `repo:${button.dataset.logoRepo}`;
  logoDestination.value = pageKey;
  renderLogoPage(pageKey, false);
  document.getElementById("logo-browser").scrollIntoView({ behavior: "smooth", block: "start" });
});

repoRefreshButton.addEventListener("click", () => {
  repoRefreshButton.dataset.refresh = "1";
  loadRepositories();
});

renderAccount(null);
renderCitadel();
renderMessages();
renderRepositories();
initLogoDestinations();
renderLogoPage("home");
setInteractiveState(false);
loadRepositories();
restoreSession();
