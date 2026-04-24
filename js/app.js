// ========== State ==========
const state = {
  filters: { category: [], phase: [], os: [], tool: [] },
  search: "",
  bookmarks: JSON.parse(localStorage.getItem("4n6-bookmarks") || "[]")
};

// ========== Variable Fields ==========
const VAR_MAP = {
  "{DUMP_FILE}": "var-dump",
  "{IMAGE}": "var-image",
  "{PCAP}": "var-pcap",
  "{TARGET_IP}": "var-target",
  "{FILE}": "var-file"
};

function replaceVariables(text) {
  let result = text;
  for (const [placeholder, inputId] of Object.entries(VAR_MAP)) {
    const val = document.getElementById(inputId).value.trim();
    if (val) result = result.replaceAll(placeholder, val);
  }
  return result;
}

function highlightVariables(text) {
  let result = escapeHtml(text);
  for (const [placeholder, inputId] of Object.entries(VAR_MAP)) {
    const val = document.getElementById(inputId).value.trim();
    const escaped = escapeHtml(placeholder);
    if (val) {
      result = result.replaceAll(escaped, `<span class="var-highlight">${escapeHtml(val)}</span>`);
    } else {
      result = result.replaceAll(escaped, `<span class="var-highlight">${escaped}</span>`);
    }
  }
  return result;
}

// ========== Helpers ==========
function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function getUniqueValues(key) {
  const values = new Set();
  ENTRIES.forEach(e => {
    if (Array.isArray(e[key])) e[key].forEach(v => values.add(v));
  });
  const sorted = [...values].sort();
  // Push "References" to the end if present
  const refIdx = sorted.indexOf("References");
  if (refIdx !== -1) {
    sorted.splice(refIdx, 1);
    sorted.push("References");
  }
  return sorted;
}

// ========== Build Filter Chips ==========
// Static filters: OS, Phase, Category — built once
function buildStaticFilters() {
  [
    { key: "os", containerId: "filter-os" },
    { key: "phase", containerId: "filter-phase" },
    { key: "category", containerId: "filter-category" }
  ].forEach(({ key, containerId }) => {
    const container = document.getElementById(containerId);
    const sk = key;
    getUniqueValues(key).forEach(value => {
      const chip = document.createElement("button");
      chip.className = "chip";
      chip.textContent = value;
      chip.addEventListener("click", () => {
        const arr = state.filters[sk];
        const idx = arr.indexOf(value);
        if (idx === -1) { arr.push(value); chip.classList.add("active"); }
        else { arr.splice(idx, 1); chip.classList.remove("active"); }
        rebuildToolChips();
        renderEntries();
        scrollToTop();
      });
      container.appendChild(chip);
    });
  });
}

// Dynamic filter: Tool — rebuilt when OS/Phase/Category change
function rebuildToolChips() {
  const container = document.getElementById("filter-tool");
  container.innerHTML = "";

  // Get entries matching current OS/Phase/Category filters (ignore tool filter)
  const preFiltered = ENTRIES.filter(entry => {
    if (state.filters.os.length && !state.filters.os.some(o => entry.os.includes(o))) return false;
    if (state.filters.phase.length && !state.filters.phase.some(p => entry.phase.includes(p))) return false;
    if (state.filters.category.length && !state.filters.category.some(c => entry.category.includes(c))) return false;
    if (state.search) {
      const q = state.search.toLowerCase();
      const s = [entry.title, entry.description, ...entry.category, ...entry.phase, ...entry.os, ...entry.tools,
        ...entry.commands.map(c => c.label + " " + c.cmd)].join(" ").toLowerCase();
      if (!s.includes(q)) return false;
    }
    return true;
  });

  // Collect tools from pre-filtered entries
  const availableTools = new Set();
  preFiltered.forEach(e => e.tools.forEach(t => availableTools.add(t)));

  // Remove any selected tools that are no longer available
  state.filters.tool = state.filters.tool.filter(t => availableTools.has(t));

  // Build chips
  [...availableTools].sort().forEach(value => {
    const chip = document.createElement("button");
    chip.className = "chip" + (state.filters.tool.includes(value) ? " active" : "");
    chip.textContent = value;
    chip.addEventListener("click", () => {
      const arr = state.filters.tool;
      const idx = arr.indexOf(value);
      if (idx === -1) { arr.push(value); chip.classList.add("active"); }
      else { arr.splice(idx, 1); chip.classList.remove("active"); }
      renderEntries();
      scrollToTop();
    });
    container.appendChild(chip);
  });
}

// ========== Scroll to Top ==========
function scrollToTop() {
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ========== Clear Filters ==========
function clearAllFilters() {
  state.filters = { category: [], phase: [], os: [], tool: [] };
  state.search = "";
  document.getElementById("search-input").value = "";
  document.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
  rebuildToolChips();
  renderEntries();
  scrollToTop();
}

// ========== Filter Entries ==========
function filterEntries() {
  return ENTRIES.filter(entry => {
    if (state.filters.category.length && !state.filters.category.some(c => entry.category.includes(c))) return false;
    if (state.filters.phase.length && !state.filters.phase.some(p => entry.phase.includes(p))) return false;
    if (state.filters.os.length && !state.filters.os.some(o => entry.os.includes(o))) return false;
    if (state.filters.tool.length && !state.filters.tool.some(t => entry.tools.includes(t))) return false;
    if (state.search) {
      const q = state.search.toLowerCase();
      const s = [entry.title, entry.description, ...entry.category, ...entry.phase, ...entry.os, ...entry.tools,
        ...entry.commands.map(c => c.label + " " + c.cmd)].join(" ").toLowerCase();
      if (!s.includes(q)) return false;
    }
    return true;
  });
}

// ========== Bookmarks ==========
function isBookmarked(title) {
  return state.bookmarks.includes(title);
}

function toggleBookmark(title) {
  const idx = state.bookmarks.indexOf(title);
  if (idx === -1) state.bookmarks.push(title);
  else state.bookmarks.splice(idx, 1);
  localStorage.setItem("4n6-bookmarks", JSON.stringify(state.bookmarks));
  renderBookmarks();
  // Update bookmark button states
  document.querySelectorAll(".bookmark-btn").forEach(btn => {
    const t = btn.getAttribute("data-title");
    btn.classList.toggle("bookmarked", isBookmarked(t));
    btn.innerHTML = isBookmarked(t) ? "&#9733;" : "&#9734;";
  });
}

function renderBookmarks() {
  const container = document.getElementById("bookmarks-list");
  if (state.bookmarks.length === 0) {
    container.innerHTML = '<p class="empty-state">No bookmarks yet. Click the star on any entry.</p>';
    return;
  }
  container.innerHTML = state.bookmarks.map(title => `
    <div class="bookmark-item" onclick="scrollToEntry('${escapeHtml(title).replace(/'/g, "\\'")}')">
      <span class="bm-title">${escapeHtml(title)}</span>
      <button class="bookmark-remove" onclick="event.stopPropagation(); toggleBookmark('${escapeHtml(title).replace(/'/g, "\\'")}')" title="Remove">&times;</button>
    </div>
  `).join("");
}

function scrollToEntry(title) {
  const cards = document.querySelectorAll(".entry-card");
  for (const card of cards) {
    const t = card.querySelector(".entry-title").textContent;
    if (t === title) {
      card.scrollIntoView({ behavior: "smooth", block: "center" });
      // Open it
      const body = card.querySelector(".entry-body");
      const toggle = card.querySelector(".entry-toggle");
      if (!body.classList.contains("open")) {
        body.classList.add("open");
        toggle.classList.add("open");
      }
      // Flash highlight
      card.style.borderColor = "var(--accent)";
      setTimeout(() => { card.style.borderColor = ""; }, 1500);
      break;
    }
  }
}

// ========== Render Entries ==========
function renderEntries() {
  const container = document.getElementById("entries-container");
  const filtered = filterEntries();

  document.getElementById("entry-count").textContent = `${filtered.length}/${ENTRIES.length}`;

  if (filtered.length === 0) {
    container.innerHTML = '<div class="no-results"><span class="big">&#8709;</span>No entries match your filters.</div>';
    return;
  }

  container.innerHTML = filtered.map((entry, idx) => {
    const tags = [
      ...entry.category.map(c => `<span class="tag tag-category">${c}</span>`),
      ...entry.phase.map(p => `<span class="tag tag-phase">${p}</span>`),
      ...entry.os.map(o => `<span class="tag tag-os">${o}</span>`),
      ...entry.tools.map(t => `<span class="tag tag-tool">${t}</span>`)
    ].join("");

    const commands = entry.commands.map((cmd, ci) => {
      const cmdId = `cmd-${idx}-${ci}`;
      return `
        <div class="command-block">
          <div class="command-label">${escapeHtml(cmd.label)}</div>
          <div class="command-wrapper">
            <code class="command-code" id="${cmdId}" data-raw="${encodeURIComponent(cmd.cmd)}">${highlightVariables(cmd.cmd)}</code>
            <button class="copy-btn" onclick="copyCommand('${cmdId}', this)">copy</button>
          </div>
        </div>`;
    }).join("");

    const refs = entry.references
      ? `<div class="entry-refs"><span>ref </span>${entry.references.map(r => `<a href="${r}" target="_blank">${r}</a>`).join(", ")}</div>`
      : "";

    const bm = isBookmarked(entry.title);
    const safeTitle = escapeHtml(entry.title).replace(/'/g, "\\'");

    return `
      <div class="entry-card" data-entry-title="${escapeHtml(entry.title)}">
        <div class="entry-header" onclick="toggleEntry(this)">
          <button class="bookmark-btn ${bm ? 'bookmarked' : ''}" data-title="${escapeHtml(entry.title)}" onclick="event.stopPropagation(); toggleBookmark('${safeTitle}')">${bm ? '&#9733;' : '&#9734;'}</button>
          <span class="entry-title">${escapeHtml(entry.title)}</span>
          <span class="entry-toggle">&#9660;</span>
        </div>
        <div class="entry-body">
          <p class="entry-description">${escapeHtml(entry.description)}</p>
          <div class="entry-tags">${tags}</div>
          ${commands}
          ${refs}
        </div>
      </div>`;
  }).join("");
}

// ========== Toggle Entry ==========
function toggleEntry(headerEl) {
  const body = headerEl.nextElementSibling;
  const toggle = headerEl.querySelector(".entry-toggle");
  body.classList.toggle("open");
  toggle.classList.toggle("open");
}

// ========== Copy Command ==========
function copyCommand(cmdId, btnEl) {
  const codeEl = document.getElementById(cmdId);
  const raw = decodeURIComponent(codeEl.getAttribute("data-raw"));
  const text = replaceVariables(raw);

  navigator.clipboard.writeText(text).then(() => {
    btnEl.textContent = "done";
    btnEl.classList.add("copied");
    setTimeout(() => {
      btnEl.textContent = "copy";
      btnEl.classList.remove("copied");
    }, 1200);
  });
}

// ========== Theme ==========
function initTheme() {
  const saved = localStorage.getItem("4n6-theme");
  const btn = document.getElementById("theme-switch");
  const icon = document.getElementById("toggle-icon");

  if (saved === "light") {
    document.documentElement.setAttribute("data-theme", "light");
    icon.innerHTML = "&#9788;";
  }

  btn.addEventListener("click", () => {
    const isLight = document.documentElement.getAttribute("data-theme") === "light";
    if (isLight) {
      document.documentElement.removeAttribute("data-theme");
      localStorage.setItem("4n6-theme", "dark");
      icon.innerHTML = "&#9790;";
    } else {
      document.documentElement.setAttribute("data-theme", "light");
      localStorage.setItem("4n6-theme", "light");
      icon.innerHTML = "&#9788;";
    }
  });
}

// ========== Settings Panel ==========
function initSettings() {
  const btn = document.getElementById("settings-btn");
  const panel = document.getElementById("settings-panel");

  btn.addEventListener("click", () => {
    const open = panel.classList.toggle("open");
    btn.classList.toggle("active", open);
  });
}

// ========== Search ==========
function initSearch() {
  const input = document.getElementById("search-input");
  let debounce;
  input.addEventListener("input", () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      state.search = input.value.trim();
      rebuildToolChips();
      renderEntries();
    }, 200);
  });
}

// ========== Mobile Sidebar ==========
function initSidebar() {
  const menuBtn = document.getElementById("menu-btn");
  const sidebar = document.getElementById("sidebar");
  const overlay = document.createElement("div");
  overlay.className = "sidebar-overlay";
  document.body.appendChild(overlay);

  menuBtn.addEventListener("click", () => {
    sidebar.classList.toggle("open");
    overlay.classList.toggle("active");
  });

  overlay.addEventListener("click", () => {
    sidebar.classList.remove("open");
    overlay.classList.remove("active");
  });
}

// ========== Init ==========
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initSettings();
  initSidebar();
  buildStaticFilters();
  rebuildToolChips();
  initSearch();
  renderEntries();
  renderBookmarks();

  document.getElementById("clear-filters").addEventListener("click", clearAllFilters);

  // Live variable replacement
  Object.values(VAR_MAP).forEach(id => {
    document.getElementById(id).addEventListener("input", () => {
      document.querySelectorAll(".command-code").forEach(codeEl => {
        const raw = decodeURIComponent(codeEl.getAttribute("data-raw"));
        codeEl.innerHTML = highlightVariables(raw);
      });
    });
  });
});
