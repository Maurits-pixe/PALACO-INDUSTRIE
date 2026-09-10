const STORAGE_KEYS = {
  citadel: "palaco-citadel",
  messages: "palaco-rio-messages",
};

const defaultCitadel = {
  ownerName: "",
  citadelName: "",
  citadelTheme: "light",
  citadelDescription: "",
};

const defaultMessages = [
  {
    role: "rio",
    text: "Welcome. I am RIO. I can help you create your Citadel and guide you through PALACO.",
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

const citadelForm = document.getElementById("citadel-form");
const resetCitadelButton = document.getElementById("reset-citadel");
const citadelStatus = document.getElementById("citadel-status");
const rioForm = document.getElementById("rio-form");
const rioInput = document.getElementById("rio-input");
const rioMessages = document.getElementById("rio-messages");
const logoDestination = document.getElementById("logo-destination");
const logoOpenButton = document.getElementById("logo-open");
const logoBackButton = document.getElementById("logo-back");
const logoForwardButton = document.getElementById("logo-forward");
const logoRefreshButton = document.getElementById("logo-refresh");
const logoAddress = document.getElementById("logo-address");
const logoFrame = document.getElementById("logo-frame");

let logoHistory = ["home"];
let logoHistoryIndex = 0;

function readStorage(key, fallback) {
  try {
    const value = window.localStorage.getItem(key);
    return value ? JSON.parse(value) : fallback;
  } catch {
    return fallback;
  }
}

function writeStorage(key, value) {
  window.localStorage.setItem(key, JSON.stringify(value));
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatTheme(theme) {
  return theme.charAt(0).toUpperCase() + theme.slice(1);
}

function getCitadel() {
  return { ...defaultCitadel, ...readStorage(STORAGE_KEYS.citadel, defaultCitadel) };
}

function setCitadel(citadel) {
  writeStorage(STORAGE_KEYS.citadel, citadel);
  renderCitadel(citadel);
  renderLogoPage(currentLogoPageKey());
}

function getMessages() {
  const messages = readStorage(STORAGE_KEYS.messages, defaultMessages);
  return Array.isArray(messages) ? messages.map((message) => ({ ...message })) : [...defaultMessages];
}

function setMessages(messages) {
  writeStorage(STORAGE_KEYS.messages, messages);
  renderMessages(messages);
}

function renderCitadel(citadel) {
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

function renderMessages(messages) {
  rioMessages.innerHTML = "";

  messages.forEach((message) => {
    const element = document.createElement("article");
    element.className = `message message--${message.role}`;
    element.innerHTML = `<strong>${message.role === "rio" ? "RIO" : "You"}</strong><span>${escapeHtml(
      message.text
    )}</span>`;
    rioMessages.appendChild(element);
  });

  rioMessages.scrollTop = rioMessages.scrollHeight;
}

function rioReply(text, citadel) {
  const normalised = text.toLowerCase();

  if (normalised.includes("citadel") || normalised.includes("space")) {
    return citadel.citadelName
      ? `Your Citadel is ${citadel.citadelName}. You can keep shaping it by updating its name, theme, or description.`
      : "You have not created a Citadel yet. Start with your name, a Citadel name, and a short description.";
  }

  if (normalised.includes("world") || normalised.includes("logo")) {
    return "Open L.O.G.O. to explore guided destinations. This first build keeps browsing simple and safe.";
  }

  if (normalised.includes("hello") || normalised.includes("hi")) {
    return "Hello. I am glad you are here. Tell me what you want your PALACO space to become.";
  }

  return "I can help you create your Citadel, explain RIO, or guide you to L.O.G.O.";
}

function initLogoDestinations() {
  Object.entries(logoPages).forEach(([key, page]) => {
    const option = document.createElement("option");
    option.value = key;
    option.textContent = page.label;
    logoDestination.appendChild(option);
  });

  logoDestination.value = "home";
}

function currentLogoPageKey() {
  return logoHistory[logoHistoryIndex] || "home";
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
  const page = logoPages[pageKey] || logoPages.home;
  const citadel = getCitadel();

  if (!replace) {
    logoHistory = logoHistory.slice(0, logoHistoryIndex + 1);
    logoHistory.push(pageKey);
    logoHistoryIndex = logoHistory.length - 1;
  }

  logoDestination.value = pageKey;
  logoAddress.textContent = page.path;
  logoFrame.srcdoc = logoDocument(page.render(citadel));
  logoBackButton.disabled = logoHistoryIndex === 0;
  logoForwardButton.disabled = logoHistoryIndex === logoHistory.length - 1;
}

citadelForm.addEventListener("submit", (event) => {
  event.preventDefault();

  const formData = new FormData(citadelForm);
  const citadel = {
    ownerName: formData.get("ownerName").toString().trim(),
    citadelName: formData.get("citadelName").toString().trim(),
    citadelTheme: formData.get("citadelTheme").toString(),
    citadelDescription: formData.get("citadelDescription").toString().trim(),
  };

  if (!citadel.ownerName || !citadel.citadelName) {
    citadelStatus.textContent = "Please add your name and a Citadel name first.";
    return;
  }

  setCitadel(citadel);
  citadelStatus.textContent = `${citadel.citadelName} is ready.`;
});

resetCitadelButton.addEventListener("click", () => {
  setCitadel(defaultCitadel);
  citadelStatus.textContent = "Your Citadel form has been reset.";
});

rioForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const text = rioInput.value.trim();

  if (!text) {
    return;
  }

  const citadel = getCitadel();
  const messages = getMessages();
  messages.push({ role: "user", text });
  messages.push({ role: "rio", text: rioReply(text, citadel) });
  setMessages(messages);
  rioInput.value = "";
  rioInput.focus();
});

logoOpenButton.addEventListener("click", () => {
  renderLogoPage(logoDestination.value, false);
});

logoBackButton.addEventListener("click", () => {
  if (logoHistoryIndex > 0) {
    logoHistoryIndex -= 1;
    renderLogoPage(currentLogoPageKey());
  }
});

logoForwardButton.addEventListener("click", () => {
  if (logoHistoryIndex < logoHistory.length - 1) {
    logoHistoryIndex += 1;
    renderLogoPage(currentLogoPageKey());
  }
});

logoRefreshButton.addEventListener("click", () => {
  renderLogoPage(currentLogoPageKey());
});

renderCitadel(getCitadel());
setMessages(getMessages());
initLogoDestinations();
renderLogoPage("home");
