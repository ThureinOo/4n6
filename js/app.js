// ========== Investigation Templates ==========
const TEMPLATES = [
  {
    id: "memory-dump",
    name: "I have a memory dump",
    desc: "Full memory analysis workflow from triage to credential extraction",
    steps: [
      { entry: "Volatility3 - Memory Forensics", note: "Start with windows.info / linux.info to identify the OS and kernel", cmds: ["Image info (Win)", "Image info (Linux)"] },
      { entry: "Volatility3 - Memory Forensics", note: "List processes — look for misspelled names, wrong parents, unusual paths", cmds: ["Process list", "Process tree", "Hidden processes"] },
      { entry: "Volatility3 - Memory Forensics", note: "Check network — external connections from system processes = C2", cmds: ["Network (netscan)", "Network (netstat)"] },
      { entry: "Volatility3 - Memory Forensics", note: "Examine command lines and loaded DLLs for suspicious arguments", cmds: ["Command line args", "DLL list"] },
      { entry: "Volatility3 - Memory Forensics", note: "Detect injected code — MZ headers in RWX regions = process injection", cmds: ["Malfind (all)"] },
      { entry: "Volatility3 - Memory Forensics", note: "Check for rootkit hooks in the SSDT", cmds: ["SSDT hooks"] },
      { entry: "Volatility3 - Memory Forensics", note: "Extract strings and map to processes to find IOCs", cmds: ["Extract strings", "Unicode strings", "Map strings to PIDs"] },
      { entry: "Volatility3 - Memory Forensics", note: "Dump credentials — SAM hashes, LSA secrets, cached domain creds", cmds: ["Hashdump", "LSA dump", "Cached creds"] },
      { entry: "Volatility3 - Memory Forensics", note: "Check registry for persistence (Run keys, services)", cmds: ["Registry hives", "Registry key"] },
      { entry: "Volatility3 - Memory Forensics", note: "Search for and extract suspicious files from memory", cmds: ["Filescan", "Filescan (filter)", "Dump file by addr"] },
      { entry: "Volatility3 - Memory Forensics", note: "Build a timeline of all activity", cmds: ["Timeline"] }
    ]
  },
  {
    id: "disk-image",
    name: "I have a disk image",
    desc: "Disk forensics from mounting to timeline generation",
    steps: [
      { entry: "File Hashing & Verification", note: "Hash the image first to preserve chain of custody" },
      { entry: "Mount Forensic Images", note: "Mount read-only — identify format (E01, raw, VMDK) and use the right tool" },
      { entry: "Sleuth Kit - File System Analysis", note: "Get partition layout with mmls, then list files and find deleted items" },
      { entry: "Windows MFT Analysis", note: "Parse $MFT for all file metadata including timestamps and deleted file records" },
      { entry: "Windows Prefetch Analysis", note: "Check what programs ran and when — key evidence of execution" },
      { entry: "Registry Analysis Tools", note: "Parse SYSTEM, SOFTWARE, SAM, NTUSER.DAT for persistence and user activity" },
      { entry: "ShimCache / AppCompatCache", note: "More evidence of execution — programs that ran even if deleted" },
      { entry: "Windows Event Logs", note: "Parse Security, System, PowerShell logs for logons, process creation, services" },
      { entry: "NTFS Alternate Data Streams (ADS)", note: "Check for hidden data in alternate data streams" },
      { entry: "Windows Recycle Bin", note: "Recover deleted files and see what the user tried to destroy" },
      { entry: "File Carving", note: "Carve deleted files from unallocated space" },
      { entry: "plaso / log2timeline - Super Timeline", note: "Generate a unified timeline of ALL artifacts for the incident window" }
    ]
  },
  {
    id: "pcap",
    name: "I have a PCAP",
    desc: "Network traffic analysis from overview to extraction",
    steps: [
      { entry: "tshark - CLI Packet Analysis", note: "Start with conversations and statistics to get the big picture", cmds: ["Conversations", "Statistics"] },
      { entry: "Wireshark - Display Filters", note: "Filter by protocol — HTTP requests, DNS queries, FTP creds, TLS handshakes" },
      { entry: "tshark - CLI Packet Analysis", note: "Extract DNS queries for C2/exfil domains and HTTP requests for IOCs", cmds: ["DNS queries", "Filter + fields"] },
      { entry: "tshark - CLI Packet Analysis", note: "Export files transferred over HTTP/SMB", cmds: ["Extract files"] },
      { entry: "Wireshark - TLS Decryption", note: "If you have the SSLKEYLOGFILE or private key, decrypt HTTPS traffic" },
      { entry: "tcpflow - TCP Stream Reconstruction", note: "Reconstruct full TCP streams to see conversation content" },
      { entry: "USB Keystroke Extraction from PCAP", note: "If USB traffic is present, extract keystrokes for typed content" },
      { entry: "Flag Grep - CTF Quick Search", note: "Search for flags directly in the PCAP data", cmds: ["In PCAP"] }
    ]
  },
  {
    id: "stego-image",
    name: "I have a stego image (CTF)",
    desc: "Systematic steganography analysis workflow",
    steps: [
      { entry: "Stego Workflow - Image Analysis Order", note: "Follow this exact order — most CTF stego challenges are solved in the first 5 steps" },
      { entry: "file - Identify File Type", note: "Check if the file is actually what it claims to be — wrong extension is common" },
      { entry: "ExifTool - Metadata Extraction", note: "Check for hidden comments, GPS coords, or flag in metadata fields" },
      { entry: "strings - Extract Readable Text", note: "Grep for flag format, URLs, base64 strings appended after image data" },
      { entry: "binwalk - Firmware / Embedded File Analysis", note: "Look for embedded ZIPs, images, or other files inside the image" },
      { entry: "pngcheck - PNG Integrity", note: "For PNG: check CRC errors and modified dimensions — fix and re-render" },
      { entry: "zsteg - PNG/BMP LSB Stego", note: "For PNG/BMP: detect LSB hidden data across all channels and bit planes" },
      { entry: "steghide - JPEG/BMP Stego", note: "For JPEG: try extraction with empty passphrase first, then common passwords" },
      { entry: "stegcracker - Brute Force Stego Passwords", note: "If steghide needs a password, brute force with rockyou.txt" },
      { entry: "Least Significant Bit (LSB) Manual", note: "If automated tools fail, manually extract LSB bits with Python" }
    ]
  },
  {
    id: "unknown-file",
    name: "I have an unknown file (CTF)",
    desc: "Systematic approach to identify and analyze any unknown file",
    steps: [
      { entry: "CTF - Quick File Checks", note: "Run through all 7 checks in order — most CTF files are solved here" },
      { entry: "file - Identify File Type", note: "If type is wrong, check magic bytes and fix the header" },
      { entry: "Magic Bytes Reference", note: "Compare first bytes against known signatures to identify the real format" },
      { entry: "strings - Extract Readable Text", note: "Look for flags, encoded data, URLs, and function names" },
      { entry: "xxd / hexdump - Hex Analysis", note: "Examine raw hex for patterns, headers, and anomalies" },
      { entry: "binwalk - Firmware / Embedded File Analysis", note: "Scan for embedded files and check entropy for encrypted sections" },
      { entry: "Entropy Analysis", note: "High entropy (>7.5) = encrypted/compressed. Low entropy = text. Spikes = hidden data" },
      { entry: "File Carving", note: "If multiple files are concatenated, carve them apart" },
      { entry: "Base Encoding / Decoding", note: "Try common decodings — base64, hex, ROT13, URL encoding" },
      { entry: "XOR Analysis", note: "If it looks random but entropy isn't 8.0, try single-byte XOR brute force" }
    ]
  },
  {
    id: "windows-ir",
    name: "Windows Incident Response",
    desc: "Live Windows system triage and artifact collection",
    steps: [
      { entry: "Windows Event Logs", note: "Check for failed logons (4625), new services (7045), PowerShell (4104), cleared logs (1102)" },
      { entry: "Registry Analysis Tools", note: "Parse all hives — look for persistence in Run keys, services, scheduled tasks" },
      { entry: "Windows Prefetch Analysis", note: "What programs ran? When? Especially check for tools like mimikatz, psexec, cmd" },
      { entry: "ShimCache / AppCompatCache", note: "More execution evidence — even if prefetch was cleared" },
      { entry: "Windows MFT Analysis", note: "Check file creation timestamps around the incident window" },
      { entry: "NTFS Alternate Data Streams (ADS)", note: "Attackers hide payloads in ADS — check suspicious files" },
      { entry: "plaso / log2timeline - Super Timeline", note: "Generate timeline and filter to the incident window" }
    ]
  }
];

// ========== State ==========
const state = {
  filters: { category: [], phase: [], os: [] },
  search: "",
  activeWorkflow: null,
  workflowProgress: JSON.parse(localStorage.getItem("4n6-workflow-progress") || "{}"),
  bookmarks: JSON.parse(localStorage.getItem("4n6-bookmarks") || "[]")
};

// ========== Variable Fields ==========
const VAR_MAP = {
  "{DUMP_FILE}":   "var-dump",
  "{IMAGE}":       "var-image",
  "{PCAP}":        "var-pcap",
  "{TARGET_IP}":   "var-target",
  "{FILE}":        "var-file",
  "{PID}":         "var-pid",
  "{OFFSET}":      "var-offset",
  "{INODE}":       "var-inode",
  "{SECTOR}":      "var-sector",
  "{STREAM_NUM}":  "var-stream",
  "{PASSWORD}":    "var-password",
  "{PASS}":        "var-password",
  "{USER}":        "var-user",
  "{DOMAIN}":      "var-domain",
  "{HASH}":        "var-hash",
  "{NTLM_HASH}":   "var-ntlm",
  "{KEY}":         "var-key",
  "{GUID}":        "var-guid",
  "{ADS_NAME}":    "var-ads",
  "{SIZE}":        "var-size",
  "{ENCODED}":     "var-encoded",
  "{CIPHERTEXT}":  "var-cipher"
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
        renderEntries();
        scrollToTop();
      });
      container.appendChild(chip);
    });
  });
}


// ========== Scroll to Top ==========
function scrollToTop() {
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ========== Clear Filters ==========
function clearAllFilters() {
  state.filters = { category: [], phase: [], os: [] };
  state.search = "";
  document.getElementById("search-input").value = "";
  document.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));

  renderEntries();
  scrollToTop();
}

// ========== Filter Entries ==========
function filterEntries() {
  return ENTRIES.filter(entry => {
    if (state.filters.category.length && !state.filters.category.some(c => entry.category.includes(c))) return false;
    if (state.filters.phase.length && !state.filters.phase.some(p => entry.phase.includes(p))) return false;
    if (state.filters.os.length && !state.filters.os.some(o => entry.os.includes(o))) return false;
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
      const body = card.querySelector(".entry-body");
      const toggle = card.querySelector(".entry-toggle");
      if (!body.classList.contains("open")) {
        body.classList.add("open");
        toggle.classList.add("open");
        card.classList.add("open");
      }
      // Flash highlight
      card.style.borderColor = "var(--accent)";
      setTimeout(() => { card.style.borderColor = ""; }, 1500);
      break;
    }
  }
}

// ========== Section Order ==========
const SECTION_ORDER = [
  "References", "File Analysis", "Disk", "Memory", "Network", "Stego",
  "Metadata", "Logs", "Registry", "Malware",
  "Crypto/Encoding"
];

function getSectionKey(entry) {
  // Use the first category that appears in SECTION_ORDER
  for (const sec of SECTION_ORDER) {
    if (entry.category.includes(sec)) return sec;
  }
  return entry.category[0] || "Other";
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

  const autoOpen = filtered.length <= 3;
  const hasActiveFilters = state.search || Object.values(state.filters).some(a => a.length);

  // Group entries by section when no filters active
  let html = "";
  let lastSection = null;

  // Sort filtered entries by section order
  const sorted = [...filtered].sort((a, b) => {
    const ai = SECTION_ORDER.indexOf(getSectionKey(a));
    const bi = SECTION_ORDER.indexOf(getSectionKey(b));
    return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi);
  });

  sorted.forEach((entry, idx) => {
    // Insert section header when category group changes (only if no filters)
    if (!hasActiveFilters) {
      const section = getSectionKey(entry);
      if (section !== lastSection) {
        lastSection = section;
        html += `<div class="section-header">${escapeHtml(section)}</div>`;
      }
    }

    const tags = [
      ...entry.category.map(c => `<span class="tag tag-category">${c}</span>`),
      ...entry.phase.map(p => `<span class="tag tag-phase">${p}</span>`),
      ...entry.os.map(o => `<span class="tag tag-os">${o}</span>`),
      ...entry.tools.map(t => `<span class="tag tag-tool">${t}</span>`)
    ].join("");

    // When searching, only show matching commands (unless match is in title/description)
    const q = state.search ? state.search.toLowerCase() : "";
    let cmdsToShow = entry.commands;
    let searchOpen = false;

    if (q) {
      const titleMatch = (entry.title + " " + entry.description).toLowerCase().includes(q);
      const cmdMatches = entry.commands.filter(c =>
        (c.label + " " + c.cmd).toLowerCase().includes(q)
      );
      // If search matched specific commands (not just title), show only those
      if (cmdMatches.length > 0 && !titleMatch) {
        cmdsToShow = cmdMatches;
      } else if (cmdMatches.length > 0 && titleMatch) {
        cmdsToShow = cmdMatches;
      }
      // else: titleMatch only → show all commands
      searchOpen = true;
    }

    const commands = cmdsToShow.map((cmd, ci) => {
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
    const isOpen = autoOpen || searchOpen;

    html += `
      <div class="entry-card${isOpen ? ' open' : ''}" data-entry-title="${escapeHtml(entry.title)}">
        <div class="entry-header" onclick="toggleEntry(this)">
          <button class="bookmark-btn ${bm ? 'bookmarked' : ''}" data-title="${escapeHtml(entry.title)}" onclick="event.stopPropagation(); toggleBookmark('${safeTitle}')">${bm ? '&#9733;' : '&#9734;'}</button>
          <span class="entry-title">${escapeHtml(entry.title)}</span>
          <span class="entry-toggle${isOpen ? ' open' : ''}">&#9660;</span>
        </div>
        <div class="entry-body${isOpen ? ' open' : ''}">
          <p class="entry-description">${escapeHtml(entry.description)}</p>
          ${entry.analysis ? `<div class="entry-analysis"><span class="analysis-label">What to look for</span>${escapeHtml(entry.analysis)}</div>` : ""}
          <div class="entry-tags">${tags}</div>
          ${commands}
          ${refs}
        </div>
      </div>`;
  });

  container.innerHTML = html;
}

// ========== Workflow System ==========
function initWorkflows() {
  const btn = document.getElementById("workflow-btn");
  const panel = document.getElementById("workflow-panel");
  const bar = document.getElementById("workflow-bar");
  const closeBtn = document.getElementById("workflow-close");

  // Build picker panel
  panel.innerHTML = `
    <h3>Investigation Workflows <span class="settings-hint">Step-by-step guided analysis</span></h3>
    <div class="workflow-grid">
      ${TEMPLATES.map(t => `
        <div class="workflow-card" data-id="${t.id}">
          <div class="workflow-card-title">${escapeHtml(t.name)}</div>
          <div class="workflow-card-desc">${escapeHtml(t.desc)}</div>
          <div class="workflow-card-steps">${t.steps.length} steps</div>
        </div>
      `).join("")}
    </div>`;

  btn.addEventListener("click", () => {
    if (state.activeWorkflow) { exitWorkflow(); return; }
    const open = panel.classList.toggle("open");
    btn.classList.toggle("active", open);
  });

  panel.querySelectorAll(".workflow-card").forEach(card => {
    card.addEventListener("click", () => {
      const tpl = TEMPLATES.find(t => t.id === card.dataset.id);
      if (tpl) activateWorkflow(tpl);
    });
  });

  closeBtn.addEventListener("click", exitWorkflow);
}

function activateWorkflow(tpl) {
  state.activeWorkflow = tpl;
  document.getElementById("workflow-panel").classList.remove("open");
  document.getElementById("workflow-btn").classList.add("active");
  document.getElementById("workflow-bar").style.display = "";
  document.getElementById("workflow-bar-title").textContent = tpl.name;

  // Init progress for this workflow
  if (!state.workflowProgress[tpl.id]) {
    state.workflowProgress[tpl.id] = {};
  }

  updateWorkflowProgress();
  renderWorkflow();
  scrollToTop();
}

function exitWorkflow() {
  state.activeWorkflow = null;
  document.getElementById("workflow-bar").style.display = "none";
  document.getElementById("workflow-btn").classList.remove("active");
  renderEntries();
  scrollToTop();
}

function toggleWorkflowStep(tplId, stepIdx) {
  if (!state.workflowProgress[tplId]) state.workflowProgress[tplId] = {};
  state.workflowProgress[tplId][stepIdx] = !state.workflowProgress[tplId][stepIdx];
  localStorage.setItem("4n6-workflow-progress", JSON.stringify(state.workflowProgress));
  updateWorkflowProgress();
  // Update checkbox visual
  const cb = document.querySelector(`.workflow-step[data-step="${stepIdx}"] .step-check`);
  if (cb) {
    cb.checked = state.workflowProgress[tplId][stepIdx];
    cb.closest(".workflow-step").classList.toggle("completed", cb.checked);
  }
}

function updateWorkflowProgress() {
  const tpl = state.activeWorkflow;
  if (!tpl) return;
  const prog = state.workflowProgress[tpl.id] || {};
  const done = Object.values(prog).filter(Boolean).length;
  const total = tpl.steps.length;
  document.getElementById("workflow-bar-progress").textContent = `${done}/${total}`;
  const fill = document.getElementById("workflow-progress-fill");
  fill.style.width = `${(done / total) * 100}%`;
}

function renderWorkflow() {
  const tpl = state.activeWorkflow;
  if (!tpl) return;
  const container = document.getElementById("entries-container");
  const prog = state.workflowProgress[tpl.id] || {};

  let html = "";
  tpl.steps.forEach((step, si) => {
    const entry = ENTRIES.find(e => e.title === step.entry);
    if (!entry) return;
    const done = !!prog[si];

    // Filter commands if step specifies specific ones
    let cmdsToShow = entry.commands;
    if (step.cmds) {
      cmdsToShow = entry.commands.filter(c => step.cmds.includes(c.label));
      if (cmdsToShow.length === 0) cmdsToShow = entry.commands;
    }

    const commands = cmdsToShow.map((cmd, ci) => {
      const cmdId = `wf-${si}-${ci}`;
      return `
        <div class="command-block">
          <div class="command-label">${escapeHtml(cmd.label)}</div>
          <div class="command-wrapper">
            <code class="command-code" id="${cmdId}" data-raw="${encodeURIComponent(cmd.cmd)}">${highlightVariables(cmd.cmd)}</code>
            <button class="copy-btn" onclick="copyCommand('${cmdId}', this)">copy</button>
          </div>
        </div>`;
    }).join("");

    html += `
      <div class="workflow-step${done ? ' completed' : ''}" data-step="${si}">
        <div class="step-header">
          <input type="checkbox" class="step-check" ${done ? 'checked' : ''} onchange="toggleWorkflowStep('${tpl.id}', ${si})">
          <span class="step-number">${si + 1}</span>
          <div class="step-info">
            <span class="step-title">${escapeHtml(entry.title)}</span>
            <span class="step-note">${escapeHtml(step.note)}</span>
          </div>
        </div>
        <div class="step-body">
          ${commands}
        </div>
      </div>`;
  });

  container.innerHTML = html;
  document.getElementById("entry-count").textContent = `${tpl.steps.length} steps`;
}

// ========== Toggle Entry ==========
function toggleEntry(headerEl) {
  const card = headerEl.closest(".entry-card");
  const body = headerEl.nextElementSibling;
  const toggle = headerEl.querySelector(".entry-toggle");
  const isOpen = body.classList.toggle("open");
  toggle.classList.toggle("open", isOpen);
  card.classList.toggle("open", isOpen);
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

  if (saved === "dark") {
    document.documentElement.setAttribute("data-theme", "dark");
    icon.innerHTML = "&#9790;";
  } else {
    document.documentElement.setAttribute("data-theme", "light");
    icon.innerHTML = "&#9788;";
  }

  btn.addEventListener("click", () => {
    const isDark = document.documentElement.getAttribute("data-theme") === "dark";
    if (isDark) {
      document.documentElement.setAttribute("data-theme", "light");
      localStorage.setItem("4n6-theme", "light");
      icon.innerHTML = "&#9788;";
    } else {
      document.documentElement.setAttribute("data-theme", "dark");
      localStorage.setItem("4n6-theme", "dark");
      icon.innerHTML = "&#9790;";
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

// ========== Mobile Bookmarks Toggle ==========
function initMobileBookmarks() {
  const btn = document.getElementById("bookmarks-toggle");
  const pane = document.getElementById("right-pane");

  const overlay = document.createElement("div");
  overlay.className = "bookmarks-overlay";
  document.body.appendChild(overlay);

  btn.addEventListener("click", () => {
    const open = pane.classList.toggle("open");
    overlay.classList.toggle("active", open);
    btn.classList.toggle("active", open);
  });

  overlay.addEventListener("click", () => {
    pane.classList.remove("open");
    overlay.classList.remove("active");
    btn.classList.remove("active");
  });
}

// ========== Init ==========
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initSettings();
  initSidebar();
  buildStaticFilters();

  initSearch();
  initWorkflows();
  initMobileBookmarks();
  renderEntries();
  renderBookmarks();

  document.getElementById("clear-filters").addEventListener("click", clearAllFilters);

  // Live variable replacement (deduplicated — {PASS} and {PASSWORD} share one input)
  [...new Set(Object.values(VAR_MAP))].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener("input", () => {
      document.querySelectorAll(".command-code").forEach(codeEl => {
        const raw = decodeURIComponent(codeEl.getAttribute("data-raw"));
        codeEl.innerHTML = highlightVariables(raw);
      });
    });
  });

  // Keyboard shortcuts: / to focus search, Esc to clear
  const searchInput = document.getElementById("search-input");
  document.addEventListener("keydown", e => {
    const tag = document.activeElement.tagName;
    if (e.key === "/" && tag !== "INPUT" && tag !== "TEXTAREA") {
      e.preventDefault();
      searchInput.focus();
      searchInput.select();
    }
    if (e.key === "Escape" && tag === "INPUT") {
      document.activeElement.blur();
      const hasFilters = state.search || Object.values(state.filters).some(a => a.length);
      if (hasFilters) clearAllFilters();
    }
  });

  // GoatCounter view count
  const gcPaths = [location.pathname, "/4n6/", "/"].map(p => encodeURIComponent(p || "/"));
  (async () => {
    const el = document.getElementById("view-count");
    for (const p of gcPaths) {
      try {
        const r = await fetch(`https://4n6.goatcounter.com/counter/${p}.json`);
        if (!r.ok) continue;
        const d = await r.json();
        if (d && d.count && d.count !== "0") { el.textContent = d.count + " views"; return; }
      } catch (_) {}
    }
  })();
});
