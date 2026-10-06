const loginPage = document.getElementById("login-page");
const scannerPage = document.getElementById("scanner-page");
const loginForm = document.getElementById("login-form");
const loginBtn = document.getElementById("login-btn");
const loginError = document.getElementById("login-error");
const logoutBtn = document.getElementById("logout-btn");

const startScanBtn = document.getElementById("start-scan-btn");
const stopScanBtn = document.getElementById("stop-scan-btn");
const scanStatus = document.getElementById("scan-status");

const modalOverlay = document.getElementById("result-modal");
const modalIcon = document.getElementById("modal-icon");
const modalTitle = document.getElementById("modal-title");
const modalMessage = document.getElementById("modal-message");
const modalDetails = document.getElementById("modal-details");
const modalCloseBtn = document.getElementById("modal-close-btn");

let html5QrCode = null;
let isScanning = false;

function showPage(page) {
  loginPage.hidden = page !== "login";
  scannerPage.hidden = page !== "scanner";
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    method: options.method || "GET",
    headers: options.body ? { "Content-Type": "application/json" } : undefined,
    body: options.body ? JSON.stringify(options.body) : undefined,
    credentials: "same-origin",
  });
  let data = {};
  try {
    data = await response.json();
  } catch (e) {
    // non-JSON response
  }
  return { status: response.status, ok: response.ok, data };
}

function openScanner() {
  showPage("scanner");
  startScanning();
}

async function init() {
  try {
    const { data } = await api("/api/session");
    if (data.authed) return openScanner();
  } catch (e) {
    // fall through to login
  }
  showPage("login");
}

loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  loginError.hidden = true;
  loginBtn.disabled = true;

  try {
    const { status, ok, data } = await api("/api/login", {
      method: "POST",
      body: {
        username: document.getElementById("username").value.trim(),
        password: document.getElementById("password").value,
      },
    });

    if (ok) {
      loginForm.reset();
      openScanner();
    } else {
      loginError.textContent =
        status === 429 ? data.error || "Too many attempts. Try again later." : "Invalid username or password.";
      loginError.hidden = false;
    }
  } catch (err) {
    loginError.textContent = "Could not reach the server.";
    loginError.hidden = false;
  } finally {
    loginBtn.disabled = false;
  }
});

logoutBtn.addEventListener("click", async () => {
  await stopScanning();
  try {
    await api("/api/logout", { method: "POST" });
  } catch (e) {
    // ignore
  }
  showPage("login");
});

async function startScanning() {
  if (isScanning) return;
  if (!html5QrCode) {
    html5QrCode = new Html5Qrcode("reader");
  }

  try {
    await html5QrCode.start(
      { facingMode: "environment" },
      { fps: 10, qrbox: { width: 250, height: 250 } },
      onScanSuccess,
      () => {} // ignore per-frame decode failures
    );
    isScanning = true;
    startScanBtn.hidden = true;
    stopScanBtn.hidden = false;
    scanStatus.textContent = "Point the camera at a QR code.";
  } catch (err) {
    scanStatus.textContent = window.isSecureContext
      ? "Could not start the camera. Allow camera access and try again."
      : "Camera needs HTTPS. Open this page over https:// to scan.";
  }
}

async function stopScanning() {
  if (html5QrCode && isScanning) {
    try {
      await html5QrCode.stop();
      html5QrCode.clear();
    } catch (err) {
      // ignore
    }
  }
  isScanning = false;
  startScanBtn.hidden = false;
  stopScanBtn.hidden = true;
  scanStatus.textContent = "";
}

startScanBtn.addEventListener("click", startScanning);
stopScanBtn.addEventListener("click", stopScanning);

function extractName(decodedText) {
  try {
    const parsed = JSON.parse(decodedText);
    if (parsed && typeof parsed === "object") return parsed.name;
  } catch (e) {
    // Invalid JSON (e.g. a typo in the QR): pull "name" out by pattern, else use the raw text.
    const match = decodedText.match(/"name"\s*:\s*"([^"]*)"/i);
    if (match) return match[1];
  }
  return decodedText;
}

async function onScanSuccess(decodedText) {
  // Pause scanning while we process this code to avoid duplicate submits.
  await stopScanning();

  let scannedName = extractName(decodedText);
  if (typeof scannedName !== "string" || !scannedName.trim()) {
    scanStatus.textContent = 'QR code has no "name" field. Scan again.';
    return;
  }
  scannedName = scannedName.trim();

  scanStatus.textContent = "Sending...";

  const now = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  const date = `${now.getMonth() + 1}/${now.getDate()}/${now.getFullYear()}`;
  const time = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
  const details = { name: scannedName, date, time };

  try {
    const { status, ok, data } = await api("/api/scan", { method: "POST", body: details });

    if (status === 401) {
      scanStatus.textContent = "";
      showPage("login");
      return;
    }
    if (ok) {
      showResultModal(true, details, "Attendance recorded successfully.");
    } else {
      showResultModal(false, details, data.error || `Request failed (${status}).`);
    }
  } catch (err) {
    showResultModal(false, details, "Network error. Check your connection.");
  }
}

function showResultModal(success, details, message) {
  modalIcon.className = "modal-icon " + (success ? "success" : "error");
  modalIcon.textContent = success ? "✓" : "✕";
  modalTitle.textContent = success ? "Done" : "Error";
  modalMessage.textContent = message;

  modalDetails.innerHTML = `
    <div><span>Name</span><strong>${escapeHtml(details.name)}</strong></div>
    <div><span>Date</span><strong>${escapeHtml(details.date)}</strong></div>
    <div><span>Time</span><strong>${escapeHtml(details.time)}</strong></div>
  `;

  modalOverlay.hidden = false;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

modalCloseBtn.addEventListener("click", () => {
  modalOverlay.hidden = true;
  scanStatus.textContent = "";
  if (!scannerPage.hidden) startScanning();
});

init();
