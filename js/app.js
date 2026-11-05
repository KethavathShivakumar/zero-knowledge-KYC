/**
 * app.js - The Zero-Knowledge KYC Dashboard Logic
 *
 * Implements:
 * - 4-section single page navigation: HOME, ENCRYPT, DECRYPT, MY VAULT.
 * - Automatic form & memory cleanup on view switching to prevent data leakage.
 * - PBKDF2-SHA256 key derivation with 600,000 iterations and 16-byte salt.
 * - AES-256-GCM authenticated encryption/decryption with .zkkyc/.enc container.
 * - Have I Been Pwned (HIBP) k-anonymity breach verification.
 * - Supabase Storage upload with real-time byte progress (0-100%), cancellation, and status feedback.
 * - Dedicated My Vault section for listing, downloading, and deleting cloud-stored encrypted files.
 * - Supabase Authentication integration (Email/Password & Anonymous sessions).
 * - Comprehensive inline field error indicators and strict memory hygiene.
 */

import { generateSalt, deriveKey, KDF_ITERATIONS } from "./key-derivation.js";
import {
  encryptFile,
  decryptContainer,
  parseContainer,
  containerToBlob,
} from "./crypto.js";
import { checkPassphraseBreach } from "./breach-check.js";
import {
  uploadEncryptedDocument,
  listStoredDocuments,
  downloadStoredDocument,
  deleteStoredDocument,
  friendlySupabaseError,
  getCurrentUser,
  signInWithEmail,
  signUpWithEmail,
  signInAnonymously,
  signOut,
  onAuthStateChange,
  getAssuranceLevel,
  listMFAFactors,
  enrollTOTPFactor,
  challengeAndVerifyMFA,
  unenrollMFAFactor,
} from "./supabase-storage.js";
import { isSupabaseConfigured } from "../supabase-config.js";

/* ---------- Constants ---------- */
const MAX_FILE_BYTES = 10 * 1024 * 1024; // 10 MB
const MAX_ENCRYPTED_BYTES = MAX_FILE_BYTES + 64 * 1024; // 10 MB + envelope overhead
const MIN_PASSPHRASE_LENGTH = 12;

const ALLOWED_TYPES = new Map([
  ["application/pdf", [".pdf"]],
  ["image/jpeg", [".jpg", ".jpeg"]],
  ["image/png", [".png"]],
  ["image/webp", [".webp"]],
]);

/* ---------- DOM Helpers & Elements ---------- */
const $ = (id) => document.getElementById(id);

const els = {
  // Views
  viewHome: $("viewHome"),
  viewEncrypt: $("viewEncrypt"),
  viewDecrypt: $("viewDecrypt"),
  viewVault: $("viewVault"),

  // Topbar & Navigation
  globalStatusBadge: $("globalStatusBadge"),
  globalStatusText: $("globalStatusText"),
  navBtns: document.querySelectorAll(".nav-btn"),

  // Auth Header Controls
  authOpenBtn: $("authOpenBtn"),
  authProfile: $("authProfile"),
  authEmailText: $("authEmailText"),
  mfaSettingsOpenBtn: $("mfaSettingsOpenBtn"),
  topbarMfaText: $("topbarMfaText"),
  authSignOutBtn: $("authSignOutBtn"),

  // Auth Modal & Views
  authModal: $("authModal"),
  authCloseBtn: $("authCloseBtn"),
  authModalTitle: $("authModalTitle"),
  authModalSub: $("authModalSub"),
  authStandardView: $("authStandardView"),
  tabSignIn: $("tabSignIn"),
  tabSignUp: $("tabSignUp"),
  authForm: $("authForm"),
  authEmailInput: $("authEmailInput"),
  authPasswordInput: $("authPasswordInput"),
  authErrorMessage: $("authErrorMessage"),
  authSubmitBtn: $("authSubmitBtn"),
  authAnonymousBtn: $("authAnonymousBtn"),

  // Login TOTP Challenge Step (Verify Your Identity)
  authTotpChallengeStep: $("authTotpChallengeStep"),
  authTotpForm: $("authTotpForm"),
  authTotpCodeInput: $("authTotpCodeInput"),
  authTotpErrorMessage: $("authTotpErrorMessage"),
  authTotpSubmitBtn: $("authTotpSubmitBtn"),
  authTotpCancelBtn: $("authTotpCancelBtn"),

  // Compact MFA Settings Card (in My Vault)
  mfaCompactCard: $("mfaCompactCard"),
  mfaCompactStatusBadge: $("mfaCompactStatusBadge"),
  mfaCompactStatusLabel: $("mfaCompactStatusLabel"),
  mfaCompactActionBtn: $("mfaCompactActionBtn"),

  // Compact Enrollment Modal
  mfaEnrollModal: $("mfaEnrollModal"),
  mfaEnrollCloseBtn: $("mfaEnrollCloseBtn"),
  mfaEnrollQrLoading: $("mfaEnrollQrLoading"),
  mfaEnrollQrImage: $("mfaEnrollQrImage"),
  mfaEnrollSecretCode: $("mfaEnrollSecretCode"),
  mfaEnrollCopySecretBtn: $("mfaEnrollCopySecretBtn"),
  mfaEnrollForm: $("mfaEnrollForm"),
  mfaEnrollCodeInput: $("mfaEnrollCodeInput"),
  mfaEnrollErrorMessage: $("mfaEnrollErrorMessage"),
  mfaEnrollSubmitBtn: $("mfaEnrollSubmitBtn"),
  mfaEnrollCancelBtn: $("mfaEnrollCancelBtn"),

  // Compact Manage MFA Modal
  mfaManageModal: $("mfaManageModal"),
  mfaManageCloseBtn: $("mfaManageCloseBtn"),
  mfaManageCloseBottomBtn: $("mfaManageCloseBottomBtn"),
  mfaManageAalBadge: $("mfaManageAalBadge"),
  mfaManageFactorDate: $("mfaManageFactorDate"),
  mfaManageErrorMessage: $("mfaManageErrorMessage"),
  mfaDisableBtn: $("mfaDisableBtn"),

  // Home CTA Buttons
  homeHeroEncryptBtn: $("homeHeroEncryptBtn"),
  homeHeroDecryptBtn: $("homeHeroDecryptBtn"),
  homeStartEncryptBtn: $("homeStartEncryptBtn"),
  homeStartDecryptBtn: $("homeStartDecryptBtn"),

  // Encrypt View Elements
  encryptFileInput: $("encryptFileInput"),
  encryptDropzone: $("encryptDropzone"),
  encryptFileError: $("encryptFileError"),
  encryptFileInfo: $("encryptFileInfo"),
  encryptFileName: $("encryptFileName"),
  encryptFileSize: $("encryptFileSize"),
  encryptFileType: $("encryptFileType"),
  encryptClearFileBtn: $("encryptClearFileBtn"),

  encryptPassphrase: $("encryptPassphrase"),
  toggleEncryptPass: $("toggleEncryptPass"),
  encryptMeterBar: $("encryptMeterBar"),
  encryptPassError: $("encryptPassError"),
  encryptBreachNotice: $("encryptBreachNotice"),
  chkEncryptFile: $("chkEncryptFile"),
  chkEncryptPass: $("chkEncryptPass"),
  chkEncryptBreach: $("chkEncryptBreach"),

  doEncryptBtn: $("doEncryptBtn"),
  encryptProgress: $("encryptProgress"),
  encryptProgressText: $("encryptProgressText"),
  encryptActionError: $("encryptActionError"),

  encryptionSuccessCard: $("encryptionSuccessCard"),
  encResultName: $("encResultName"),
  encResultSize: $("encResultSize"),
  downloadEncryptedBtn: $("downloadEncryptedBtn"),
  uploadSupabaseBtn: $("uploadSupabaseBtn"),
  uploadProgressContainer: $("uploadProgressContainer"),
  uploadProgressBar: $("uploadProgressBar"),
  uploadProgressPercent: $("uploadProgressPercent"),
  uploadProgressLabel: $("uploadProgressLabel"),
  uploadStatusMessage: $("uploadStatusMessage"),
  cancelUploadBtn: $("cancelUploadBtn"),

  // Decrypt View Elements
  decryptFileInput: $("decryptFileInput"),
  decryptDropzone: $("decryptDropzone"),
  decryptFileError: $("decryptFileError"),
  decryptFileInfo: $("decryptFileInfo"),
  decryptFileName: $("decryptFileName"),
  decryptFileSize: $("decryptFileSize"),
  decryptClearFileBtn: $("decryptClearFileBtn"),

  decryptPassphrase: $("decryptPassphrase"),
  toggleDecryptPass: $("toggleDecryptPass"),
  decryptPassError: $("decryptPassError"),

  doDecryptBtn: $("doDecryptBtn"),
  decryptProgress: $("decryptProgress"),
  decryptProgressText: $("decryptProgressText"),
  decryptActionError: $("decryptActionError"),

  decryptionSuccessCard: $("decryptionSuccessCard"),
  decResultName: $("decResultName"),
  decResultType: $("decResultType"),
  decResultSize: $("decResultSize"),
  downloadOriginalBtn: $("downloadOriginalBtn"),
  clearDecryptedBtn: $("clearDecryptedBtn"),

  // Vault Elements (Decrypt Sidebar)
  vaultRefreshBtn: $("vaultRefreshBtn"),
  vaultEmptyState: $("vaultEmptyState"),
  vaultListContainer: $("vaultListContainer"),

  // Vault Section (Dedicated My Vault View)
  vaultViewRefreshBtn: $("vaultViewRefreshBtn"),
  vaultMfaLockCard: $("vaultMfaLockCard"),
  vaultVerifyMfaBtn: $("vaultVerifyMfaBtn"),
  vaultLoadingState: $("vaultLoadingState"),
  vaultErrorState: $("vaultErrorState"),
  vaultErrorMessage: $("vaultErrorMessage"),
  vaultRetryBtn: $("vaultRetryBtn"),
  vaultEmptyStateMain: $("vaultEmptyStateMain"),
  vaultGoToEncryptBtn: $("vaultGoToEncryptBtn"),
  vaultFilesContainer: $("vaultFilesContainer"),
  vaultFilesList: $("vaultFilesList"),

  // Global Toasts
  toasts: $("toasts"),
};

/* ---------- Application State ---------- */
let currentView = "home";
let selectedFile = null; // Plaintext File object to encrypt
let encryptedResult = null; // { container: Uint8Array, docId: string }

let selectedEncFile = null; // Encrypted File object to decrypt (.enc / .zkkyc)
let decryptedResult = null; // { name, type, size, data: Uint8Array }

let isBusy = false;
let encryptGen = 0;
let decryptGen = 0;
let activeUploadTask = null;
let isPreservingDecryptFile = false; // Preserves file loaded from Vault into Decrypt
let authMode = "signin"; // "signin" | "signup"
let currentMfaFactorId = null;
let pendingEnrollFactorId = null;
let loginChallengeFactorId = null;

/* ---------- Utility Functions ---------- */

function formatBytes(bytes) {
  if (typeof bytes !== "number" || isNaN(bytes)) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[i]}`;
}

function showToast(message, type = "info", ms = 4500) {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.setAttribute("role", type === "error" ? "alert" : "status");
  toast.textContent = message; // textContent prevents HTML injection
  els.toasts.appendChild(toast);
  setTimeout(() => toast.remove(), ms);
}

function setFieldError(element, message) {
  if (!element) return;
  if (message) {
    element.textContent = message;
    element.classList.remove("hidden");
  } else {
    element.textContent = "";
    element.classList.add("hidden");
  }
}

/** Makes a recovered filename safe for local saving. */
function sanitizeFilename(name) {
  let clean = String(name || "document")
    .replace(/[\\/:*?"<>|\x00-\x1f\x7f]/g, "_")
    .replace(/^\.+/, "")
    .replace(/[. ]+$/, "")
    .trim();
  if (clean.length > 120) {
    const dot = clean.lastIndexOf(".");
    const ext = dot > 0 ? clean.slice(dot, dot + 10) : "";
    clean = clean.slice(0, 120 - ext.length) + ext;
  }
  return clean || "document";
}

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

function scorePassphrase(value) {
  if (!value) return 0;
  let score = Math.min(value.length, 20) * 3;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(value)).length;
  score += classes * 10;
  if (/^\d+$/.test(value)) score = Math.min(score, 25);
  if (/(.)\1{3,}/.test(value)) score -= 15;
  return Math.max(0, Math.min(100, score));
}

function validateUploadFile(file) {
  if (!file) return { ok: false, reason: "Please select a file." };
  if (file.size === 0) return { ok: false, reason: "The selected file is empty." };
  if (file.size > MAX_FILE_BYTES) {
    return {
      ok: false,
      reason: `File size exceeds the 10 MB limit (${formatBytes(file.size)}).`,
    };
  }
  const name = file.name.toLowerCase();
  const extensions = ALLOWED_TYPES.get(file.type);
  if (!extensions || !extensions.some((ext) => name.endsWith(ext))) {
    return { ok: false, reason: "Unsupported format. Use PDF, JPG, PNG or WebP." };
  }
  return { ok: true };
}

function validateContainerFile(file) {
  if (!file) return { ok: false, reason: "Please upload an encrypted file." };
  const name = file.name.toLowerCase();
  if (!name.endsWith(".zkkyc") && !name.endsWith(".enc")) {
    return { ok: false, reason: "Invalid file format. Please choose an encrypted .enc or .zkkyc container." };
  }
  if (file.size === 0) return { ok: false, reason: "The file is empty." };
  if (file.size > MAX_ENCRYPTED_BYTES) {
    return { ok: false, reason: "File is too large to be a valid encrypted document." };
  }
  return { ok: true };
}

/* ---------- Authentication & MFA UI Management ---------- */

async function updateAuthUI(user) {
  if (user) {
    els.authOpenBtn.classList.add("hidden");
    els.authProfile.classList.remove("hidden");
    const display = user.is_anonymous ? "Anonymous Session" : (user.email || "Signed In");
    els.authEmailText.textContent = display;
    els.authEmailText.title = user.id;

    // Show compact security settings card
    if (els.mfaCompactCard) {
      els.mfaCompactCard.classList.remove("hidden");
    }

    // Check MFA status from Supabase
    try {
      const aal = await getAssuranceLevel();
      const factors = await listMFAFactors();
      const verifiedFactors = factors.all?.filter((f) => f.status === "verified") || [];
      const isMfaActive = aal.nextLevel === "aal2" || verifiedFactors.length > 0;

      if (isMfaActive) {
        currentMfaFactorId = verifiedFactors[0]?.id || null;
        if (els.mfaCompactStatusBadge) {
          els.mfaCompactStatusBadge.className = "mfa-pill mfa-pill-on";
          els.mfaCompactStatusBadge.textContent = "Enabled";
        }
        if (els.mfaCompactStatusLabel) {
          els.mfaCompactStatusLabel.textContent = "Enabled";
        }
        if (els.mfaCompactActionBtn) {
          els.mfaCompactActionBtn.textContent = "Manage MFA";
          els.mfaCompactActionBtn.className = "btn btn-secondary btn-sm";
        }

        if (aal.currentLevel === "aal2") {
          els.topbarMfaText.textContent = "MFA Active (AAL2)";
          els.mfaSettingsOpenBtn.className = "btn btn-secondary btn-sm mfa-topbar-btn";
        } else {
          els.topbarMfaText.textContent = "MFA Pending (AAL1)";
          els.mfaSettingsOpenBtn.className = "btn btn-warn btn-sm mfa-topbar-btn";
        }
      } else {
        currentMfaFactorId = null;
        if (els.mfaCompactStatusBadge) {
          els.mfaCompactStatusBadge.className = "mfa-pill mfa-pill-off";
          els.mfaCompactStatusBadge.textContent = "Disabled";
        }
        if (els.mfaCompactStatusLabel) {
          els.mfaCompactStatusLabel.textContent = "Disabled";
        }
        if (els.mfaCompactActionBtn) {
          els.mfaCompactActionBtn.textContent = "Enable MFA";
          els.mfaCompactActionBtn.className = "btn btn-primary btn-sm";
        }

        els.topbarMfaText.textContent = "MFA Off";
        els.mfaSettingsOpenBtn.className = "btn btn-ghost btn-sm mfa-topbar-btn";
      }
    } catch {
      els.topbarMfaText.textContent = "MFA";
    }
  } else {
    els.authOpenBtn.classList.remove("hidden");
    els.authProfile.classList.add("hidden");
    els.authEmailText.textContent = "user";
    els.topbarMfaText.textContent = "MFA";
    if (els.mfaCompactCard) {
      els.mfaCompactCard.classList.add("hidden");
    }
    currentMfaFactorId = null;
  }
}

function setAuthMode(mode) {
  authMode = mode;
  els.tabSignIn.classList.toggle("active", mode === "signin");
  els.tabSignUp.classList.toggle("active", mode === "signup");
  els.authSubmitBtn.textContent = mode === "signin" ? "Sign In" : "Register Account";
  setFieldError(els.authErrorMessage, null);
}

function setAuthViewMode(view) {
  if (view === "totp") {
    els.authStandardView.classList.add("hidden");
    els.authTotpChallengeStep.classList.remove("hidden");
    els.authModalTitle.textContent = "Verify Your Identity";
    els.authModalSub.textContent = "Enter the six-digit verification code from your authenticator app.";
    els.authTotpCodeInput.value = "";
    setFieldError(els.authTotpErrorMessage, null);
    setTimeout(() => els.authTotpCodeInput.focus(), 50);
  } else {
    els.authStandardView.classList.remove("hidden");
    els.authTotpChallengeStep.classList.add("hidden");
    els.authModalTitle.textContent = "Cloud Vault Account Access";
    els.authModalSub.textContent = "Sign in to synchronize and manage your client-side encrypted KYC documents in your private cloud vault.";
    setAuthMode("signin");
  }
}

function openAuthModal() {
  setAuthViewMode("standard");
  els.authEmailInput.value = "";
  els.authPasswordInput.value = "";
  setFieldError(els.authErrorMessage, null);
  els.authModal.classList.remove("hidden");
  els.authEmailInput.focus();
}

function openTotpChallengeModal() {
  setAuthViewMode("totp");
  els.authModal.classList.remove("hidden");
}

function closeAuthModal() {
  els.authModal.classList.add("hidden");
  els.authPasswordInput.value = "";
  setFieldError(els.authErrorMessage, null);
  setFieldError(els.authTotpErrorMessage, null);
  setAuthViewMode("standard");
  loginChallengeFactorId = null;
}

/* ---------- Compact Authenticator Enrollment Modal ---------- */

async function openMfaEnrollModal() {
  const user = await getCurrentUser();
  if (!user) {
    openAuthModal();
    return;
  }

  els.mfaEnrollModal.classList.remove("hidden");
  setFieldError(els.mfaEnrollErrorMessage, null);
  els.mfaEnrollQrLoading.classList.remove("hidden");
  els.mfaEnrollQrImage.classList.add("hidden");
  els.mfaEnrollSecretCode.textContent = "Generating...";
  els.mfaEnrollCodeInput.value = "";
  pendingEnrollFactorId = null;

  try {
    const factor = await enrollTOTPFactor("ZeroKnowledgeKYC");
    pendingEnrollFactorId = factor.id;

    if (factor.totp) {
      els.mfaEnrollSecretCode.textContent = factor.totp.secret || "";
      if (factor.totp.qr_code) {
        els.mfaEnrollQrImage.src = factor.totp.qr_code;
        els.mfaEnrollQrLoading.classList.add("hidden");
        els.mfaEnrollQrImage.classList.remove("hidden");
      }
    }
    setTimeout(() => els.mfaEnrollCodeInput.focus(), 50);
  } catch (err) {
    setFieldError(els.mfaEnrollErrorMessage, friendlySupabaseError(err));
    pendingEnrollFactorId = null;
  }
}

function closeMfaEnrollModal() {
  els.mfaEnrollModal.classList.add("hidden");
  pendingEnrollFactorId = null;
  els.mfaEnrollCodeInput.value = "";
  setFieldError(els.mfaEnrollErrorMessage, null);
}

/* ---------- Compact Manage MFA Modal ---------- */

async function openMfaManageModal() {
  const user = await getCurrentUser();
  if (!user) {
    openAuthModal();
    return;
  }

  els.mfaManageModal.classList.remove("hidden");
  setFieldError(els.mfaManageErrorMessage, null);

  try {
    const aal = await getAssuranceLevel();
    const factors = await listMFAFactors();
    const verified = factors.all?.filter((f) => f.status === "verified") || [];

    const aalDisplay = aal.currentLevel ? aal.currentLevel.toUpperCase() : "AAL2";
    els.mfaManageAalBadge.textContent = aalDisplay;
    els.mfaManageAalBadge.className = aalDisplay === "AAL2" ? "mfa-pill mfa-pill-on" : "mfa-pill mfa-pill-warn";

    if (verified.length > 0 && verified[0].created_at) {
      els.mfaManageFactorDate.textContent = new Date(verified[0].created_at).toLocaleDateString();
      currentMfaFactorId = verified[0].id;
    } else {
      els.mfaManageFactorDate.textContent = "Active";
    }
  } catch (err) {
    setFieldError(els.mfaManageErrorMessage, friendlySupabaseError(err));
  }
}

function closeMfaManageModal() {
  els.mfaManageModal.classList.add("hidden");
  setFieldError(els.mfaManageErrorMessage, null);
}

function handleMfaAction() {
  if (currentMfaFactorId) {
    openMfaManageModal();
  } else {
    openMfaEnrollModal();
  }
}

/* ---------- Automatic Form Clearing & Tab Switching ---------- */

function resetEncryptForm() {
  // Cancel active upload task if user navigates away mid-upload
  if (activeUploadTask) {
    try {
      activeUploadTask.cancel();
    } catch { /* ignore */ }
    activeUploadTask = null;
  }

  // Invalidate any in-flight async operations
  encryptGen++;

  // Reset file selection
  selectedFile = null;
  els.encryptFileInput.value = "";
  els.encryptFileName.textContent = "";
  els.encryptFileSize.textContent = "";
  els.encryptFileType.textContent = "";
  els.encryptFileInfo.classList.add("hidden");

  // Reset passphrase input and meter
  els.encryptPassphrase.value = "";
  els.encryptMeterBar.style.width = "0%";

  // Clear all validation errors and notices
  setFieldError(els.encryptFileError, null);
  setFieldError(els.encryptPassError, null);
  setFieldError(els.encryptActionError, null);
  els.encryptBreachNotice.classList.add("hidden");

  // Reset checklist
  els.chkEncryptFile.classList.remove("done");
  els.chkEncryptPass.classList.remove("done");
  els.chkEncryptBreach.classList.remove("done");

  // Reset progress states & cards
  els.encryptProgress.classList.add("hidden");
  els.encryptionSuccessCard.classList.add("hidden");
  els.uploadProgressContainer.classList.add("hidden");
  els.uploadProgressBar.style.width = "0%";
  els.uploadProgressPercent.textContent = "0%";

  // Wipe temporary encrypted container from memory
  if (encryptedResult && encryptedResult.container) {
    try {
      encryptedResult.container.fill(0);
    } catch { /* ignore */ }
  }
  encryptedResult = null;

  els.doEncryptBtn.disabled = false;
  els.uploadSupabaseBtn.disabled = false;
}

function resetDecryptForm() {
  if (isPreservingDecryptFile) {
    // Preserve file loaded directly from My Vault
    isPreservingDecryptFile = false;
    return;
  }

  // Invalidate any in-flight async decryption
  decryptGen++;

  // Reset encrypted file selection
  selectedEncFile = null;
  els.decryptFileInput.value = "";
  els.decryptFileName.textContent = "";
  els.decryptFileSize.textContent = "";
  els.decryptFileInfo.classList.add("hidden");

  // Reset passphrase input
  els.decryptPassphrase.value = "";

  // Clear validation errors
  setFieldError(els.decryptFileError, null);
  setFieldError(els.decryptPassError, null);
  setFieldError(els.decryptActionError, null);

  // Reset progress and result cards
  els.decryptProgress.classList.add("hidden");
  els.decryptionSuccessCard.classList.add("hidden");

  // Zero out plaintext decrypted buffer in memory
  if (decryptedResult && decryptedResult.data) {
    try {
      decryptedResult.data.fill(0);
    } catch { /* ignore */ }
  }
  decryptedResult = null;

  els.doDecryptBtn.disabled = false;
}

function switchView(viewName) {
  const prevView = currentView;
  currentView = viewName;

  // Clear relevant forms when switching away
  if (prevView === "encrypt" && viewName !== "encrypt") {
    resetEncryptForm();
  }
  if (prevView === "decrypt" && viewName !== "decrypt") {
    resetDecryptForm();
  }

  // Toggle view visibility
  els.viewHome.classList.toggle("hidden", viewName !== "home");
  els.viewEncrypt.classList.toggle("hidden", viewName !== "encrypt");
  els.viewDecrypt.classList.toggle("hidden", viewName !== "decrypt");
  els.viewVault.classList.toggle("hidden", viewName !== "vault");

  // Update nav buttons
  els.navBtns.forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.nav === viewName);
  });

  window.scrollTo({ top: 0, behavior: "smooth" });

  if (location.hash !== `#${viewName}`) {
    history.replaceState(null, "", `#${viewName}`);
  }

  // Fetch / refresh data for relevant views
  if (viewName === "vault") {
    loadVaultMain();
  } else if (viewName === "decrypt" && isSupabaseConfigured()) {
    renderSidebarVault();
  }
}

/* ---------- Encrypt View Logic ---------- */

function updateEncryptMeter() {
  const pass = els.encryptPassphrase.value;
  const score = scorePassphrase(pass);
  els.encryptMeterBar.style.width = `${score}%`;
  els.encryptMeterBar.style.background =
    score < 40 ? "#ef4444" : score < 70 ? "#f59e0b" : "#10b981";

  els.chkEncryptPass.classList.toggle("done", pass.length >= MIN_PASSPHRASE_LENGTH);
}

function setEncryptFile(file) {
  setFieldError(els.encryptFileError, null);
  setFieldError(els.encryptActionError, null);

  const res = validateUploadFile(file);
  if (!res.ok) {
    clearEncryptFile();
    setFieldError(els.encryptFileError, res.reason);
    return;
  }

  selectedFile = file;
  encryptedResult = null;
  encryptGen++;
  els.encryptionSuccessCard.classList.add("hidden");

  els.encryptFileName.textContent = file.name;
  els.encryptFileName.title = file.name;
  els.encryptFileSize.textContent = formatBytes(file.size);
  els.encryptFileType.textContent = file.type || "Document";
  els.encryptFileInfo.classList.remove("hidden");

  els.chkEncryptFile.classList.add("done");
  showToast("Document loaded.", "info", 2000);
}

function clearEncryptFile() {
  selectedFile = null;
  encryptedResult = null;
  encryptGen++;
  els.encryptFileInput.value = "";
  els.encryptFileInfo.classList.add("hidden");
  els.encryptionSuccessCard.classList.add("hidden");
  els.chkEncryptFile.classList.remove("done");
}

async function handleEncryptDocument() {
  if (isBusy) return;

  setFieldError(els.encryptFileError, null);
  setFieldError(els.encryptPassError, null);
  setFieldError(els.encryptActionError, null);
  els.encryptBreachNotice.classList.add("hidden");

  // 1. Validate file
  if (!selectedFile) {
    setFieldError(els.encryptFileError, "Please select a file.");
    els.encryptDropzone.scrollIntoView({ behavior: "smooth", block: "center" });
    return;
  }

  // 2. Validate passphrase
  const passphrase = els.encryptPassphrase.value;
  if (!passphrase) {
    setFieldError(els.encryptPassError, "Please enter your passphrase.");
    els.encryptPassphrase.focus();
    return;
  }
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    setFieldError(
      els.encryptPassError,
      `Please use a stronger passphrase (at least ${MIN_PASSPHRASE_LENGTH} characters).`
    );
    els.encryptPassphrase.focus();
    return;
  }

  const myGen = ++encryptGen;
  encryptedResult = null;
  isBusy = true;
  els.doEncryptBtn.disabled = true;
  els.encryptProgress.classList.remove("hidden");
  els.encryptProgressText.textContent = "Checking passphrase with Have I Been Pwned...";

  try {
    // 3. Breach Check (k-anonymity)
    const breachCheck = await checkPassphraseBreach(passphrase);
    if (myGen !== encryptGen) return;

    if (breachCheck.breached) {
      setFieldError(
        els.encryptPassError,
        `This password appears in known breach data (${breachCheck.count.toLocaleString()} times). Please choose another one.`
      );
      els.chkEncryptBreach.classList.remove("done");
      showToast("Compromised passphrase detected. Please choose a unique passphrase.", "error", 6000);
      return;
    } else {
      els.chkEncryptBreach.classList.add("done");
      els.encryptBreachNotice.textContent =
        "No match found in the known breach database. This does not guarantee that your passphrase is strong or cannot be guessed.";
      els.encryptBreachNotice.className = "field-notice warn";
      els.encryptBreachNotice.classList.remove("hidden");
    }

    // 4. Derive key and encrypt
    els.encryptProgressText.textContent = "Deriving secure key (Secure Key Generation)...";
    await new Promise((r) => setTimeout(r, 30));

    const started = performance.now();
    const salt = generateSalt();
    const key = await deriveKey(passphrase, salt, KDF_ITERATIONS);

    els.encryptProgressText.textContent = "Encrypting document with industry-standard encryption...";
    const res = await encryptFile(selectedFile, key, salt, KDF_ITERATIONS);
    const elapsed = Math.round(performance.now() - started);

    if (myGen !== encryptGen) return;

    encryptedResult = res;

    // 5. Update UI
    els.encResultName.textContent = `${res.docId}.zkkyc`;
    els.encResultSize.textContent = formatBytes(res.container.length);
    els.encryptionSuccessCard.classList.remove("hidden");
    els.encryptionSuccessCard.scrollIntoView({ behavior: "smooth", block: "nearest" });

    showToast(`Document encrypted successfully in ${elapsed} ms.`, "success", 4000);
  } catch {
    if (myGen === encryptGen) {
      setFieldError(els.encryptActionError, "Encryption failed. Please try again.");
      showToast("Encryption error. Check your file and try again.", "error", 5000);
    }
  } finally {
    isBusy = false;
    els.doEncryptBtn.disabled = false;
    els.encryptProgress.classList.add("hidden");
  }
}

function handleDownloadEncrypted() {
  if (!encryptedResult) return;
  triggerDownload(containerToBlob(encryptedResult.container), `${encryptedResult.docId}.zkkyc`);
  showToast("Encrypted container downloaded.", "success", 3000);
}

/* ---------- Supabase Storage Upload Experience ---------- */

async function handleUploadSupabase() {
  if (isBusy || !encryptedResult) return;

  if (!isSupabaseConfigured()) {
    showToast(
      "Private Cloud Vault is not configured. Please fill in your project URL and anon key in supabase-config.js.",
      "error",
      6000
    );
    return;
  }

  isBusy = true;
  els.uploadSupabaseBtn.disabled = true;
  els.uploadProgressContainer.classList.remove("hidden");
  els.uploadProgressBar.style.width = "0%";
  els.uploadProgressPercent.textContent = "0%";
  els.uploadProgressLabel.textContent = "Preparing upload...";
  els.uploadStatusMessage.textContent = "Status: Preparing";

  const myGen = encryptGen;

  try {
    // Upload already-encrypted blob directly without re-encryption
    const blob = containerToBlob(encryptedResult.container);

    await uploadEncryptedDocument(
      blob,
      { docId: encryptedResult.docId },
      (percent) => {
        if (myGen !== encryptGen) return;
        const p = Math.round(percent);
        els.uploadProgressBar.style.width = `${p}%`;
        els.uploadProgressPercent.textContent = `${p}%`;
        els.uploadProgressLabel.textContent = `Uploading encrypted file (${p}%)...`;
        els.uploadStatusMessage.textContent = `Status: Uploading (${p}%)`;
      },
      (task) => {
        activeUploadTask = task;
      }
    );

    if (myGen !== encryptGen) return;

    activeUploadTask = null;
    els.uploadProgressBar.style.width = "100%";
    els.uploadProgressPercent.textContent = "100%";
    els.uploadProgressLabel.textContent = "Upload complete!";
    els.uploadStatusMessage.textContent = "Status: Upload complete";

    showToast("Encrypted file uploaded successfully to Private Cloud Vault.", "success", 5000);

    // Auto-update Vault list
    if (isSupabaseConfigured()) {
      renderSidebarVault();
    }
  } catch (err) {
    activeUploadTask = null;
    if (myGen !== encryptGen) return;

    if (err && err.code === "storage/canceled") {
      els.uploadStatusMessage.textContent = "Status: Upload cancelled";
      showToast("Upload cancelled.", "info", 3000);
      els.uploadProgressContainer.classList.add("hidden");
      return;
    }

    els.uploadStatusMessage.textContent = "Status: Upload failed";
    showToast(`Upload failed: ${friendlySupabaseError(err)}`, "error", 6000);
  } finally {
    isBusy = false;
    els.uploadSupabaseBtn.disabled = false;
    activeUploadTask = null;
  }
}

/* ---------- Decrypt View Logic ---------- */

function setDecryptFile(file) {
  setFieldError(els.decryptFileError, null);
  setFieldError(els.decryptActionError, null);

  const res = validateContainerFile(file);
  if (!res.ok) {
    clearDecryptFile();
    setFieldError(els.decryptFileError, res.reason);
    return;
  }

  selectedEncFile = file;
  decryptedResult = null;
  decryptGen++;
  els.decryptionSuccessCard.classList.add("hidden");

  els.decryptFileName.textContent = file.name;
  els.decryptFileName.title = file.name;
  els.decryptFileSize.textContent = formatBytes(file.size);
  els.decryptFileInfo.classList.remove("hidden");

  showToast("Encrypted file loaded.", "info", 2000);
}

function clearDecryptFile() {
  selectedEncFile = null;
  clearDecryptedMemory();
  decryptGen++;
  els.decryptFileInput.value = "";
  els.decryptFileInfo.classList.add("hidden");
}

function clearDecryptedMemory() {
  if (decryptedResult && decryptedResult.data) {
    try {
      decryptedResult.data.fill(0);
    } catch { /* ignore */ }
  }
  decryptedResult = null;
  els.decryptionSuccessCard.classList.add("hidden");
}

async function handleDecryptDocument() {
  if (isBusy) return;

  setFieldError(els.decryptFileError, null);
  setFieldError(els.decryptPassError, null);
  setFieldError(els.decryptActionError, null);

  // 1. Validate file
  if (!selectedEncFile) {
    setFieldError(els.decryptFileError, "Please upload an encrypted file.");
    els.decryptDropzone.scrollIntoView({ behavior: "smooth", block: "center" });
    return;
  }

  // 2. Validate passphrase
  const passphrase = els.decryptPassphrase.value;
  if (!passphrase) {
    setFieldError(els.decryptPassError, "Please enter your passphrase.");
    els.decryptPassphrase.focus();
    return;
  }

  const myGen = ++decryptGen;
  clearDecryptedMemory();
  isBusy = true;
  els.doDecryptBtn.disabled = true;
  els.decryptProgress.classList.remove("hidden");
  els.decryptProgressText.textContent = "Reading container and deriving key...";

  let fileBytes = null;
  let parsed = null;
  try {
    fileBytes = new Uint8Array(await selectedEncFile.arrayBuffer());

    // Validate container format
    try {
      parsed = parseContainer(fileBytes);
    } catch {
      setFieldError(els.decryptFileError, "Invalid encrypted file format.");
      showToast("Invalid encrypted container.", "error", 4000);
      return;
    }

    els.decryptProgressText.textContent = "Deriving key from container salt and iterations...";
    await new Promise((r) => setTimeout(r, 30));

    const key = await deriveKey(passphrase, parsed.salt, parsed.iterations);

    els.decryptProgressText.textContent = "Verifying authentication tag and decrypting...";
    let result = null;
    try {
      result = await decryptContainer(fileBytes, key);
    } catch {
      setFieldError(
        els.decryptPassError,
        "Incorrect passphrase or corrupted encrypted document."
      );
      showToast("Decryption failed: wrong passphrase or modified file.", "error", 5000);
      return;
    }

    if (myGen !== decryptGen) {
      if (result && result.data) result.data.fill(0);
      return;
    }

    decryptedResult = result;

    // Display result
    els.decResultName.textContent = sanitizeFilename(result.name);
    els.decResultType.textContent = result.type || "Document";
    els.decResultSize.textContent = formatBytes(result.size);
    els.decryptionSuccessCard.classList.remove("hidden");
    els.decryptionSuccessCard.scrollIntoView({ behavior: "smooth", block: "nearest" });

    showToast("Document decrypted successfully.", "success", 4000);
  } catch {
    if (myGen === decryptGen) {
      setFieldError(els.decryptActionError, "Decryption failed. Please try again.");
      showToast("Decryption failed.", "error", 4000);
    }
  } finally {
    if (parsed) {
      if (parsed.salt) parsed.salt.fill(0);
      if (parsed.iv) parsed.iv.fill(0);
    }
    if (fileBytes) fileBytes.fill(0);
    isBusy = false;
    els.doDecryptBtn.disabled = false;
    els.decryptProgress.classList.add("hidden");
  }
}

function handleDownloadOriginal() {
  if (!decryptedResult) return;
  const mime = ALLOWED_TYPES.has(decryptedResult.type)
    ? decryptedResult.type
    : "application/octet-stream";
  triggerDownload(
    new Blob([decryptedResult.data], { type: mime }),
    sanitizeFilename(decryptedResult.name)
  );
  showToast("Original document downloaded.", "success", 3000);
}

/* ---------- Dedicated My Vault Section Logic ---------- */

async function loadVaultMain() {
  if (!isSupabaseConfigured()) {
    els.vaultLoadingState.classList.add("hidden");
    els.vaultErrorState.classList.add("hidden");
    els.vaultFilesContainer.classList.add("hidden");
    els.vaultEmptyStateMain.classList.remove("hidden");
    els.vaultEmptyStateMain.querySelector("h3").textContent = "Cloud Vault Not Configured";
    els.vaultEmptyStateMain.querySelector("p").textContent =
      "Please fill in your configuration in supabase-config.js to enable the cloud vault.";
    return;
  }

  // Show loading
  els.vaultLoadingState.classList.remove("hidden");
  els.vaultErrorState.classList.add("hidden");
  els.vaultEmptyStateMain.classList.add("hidden");
  els.vaultFilesContainer.classList.add("hidden");
  els.vaultMfaLockCard.classList.add("hidden");

  try {
    const docs = await listStoredDocuments();
    els.vaultLoadingState.classList.add("hidden");

    if (!docs || docs.length === 0) {
      els.vaultEmptyStateMain.classList.remove("hidden");
      els.vaultEmptyStateMain.querySelector("h3").textContent = "Your Vault is Empty";
      els.vaultEmptyStateMain.querySelector("p").textContent =
        "You haven't uploaded any encrypted documents to your cloud vault yet.";
      return;
    }

    els.vaultFilesContainer.classList.remove("hidden");
    els.vaultFilesList.textContent = "";

    for (const doc of docs) {
      const row = document.createElement("div");
      row.className = "vault-file-row";

      // Document ID
      const colId = document.createElement("div");
      colId.className = "vault-doc-id";
      colId.textContent = doc.name || `${doc.docId}.zkkyc`;
      colId.title = doc.docId;

      // Security Badge
      const colType = document.createElement("div");
      const badge = document.createElement("span");
      badge.className = "vault-badge-enc";
      badge.textContent = "Industry-Standard Encryption";
      colType.appendChild(badge);

      // Size
      const colSize = document.createElement("div");
      colSize.className = "vault-cell-muted";
      colSize.textContent = formatBytes(doc.size);

      // Date
      const colDate = document.createElement("div");
      colDate.className = "vault-cell-muted";
      colDate.textContent = doc.updated ? new Date(doc.updated).toLocaleDateString() : "Saved";

      // Actions
      const colActions = document.createElement("div");
      colActions.className = "vault-row-actions";

      // Decrypt in App Button
      const decryptBtn = document.createElement("button");
      decryptBtn.type = "button";
      decryptBtn.className = "btn btn-primary btn-sm";
      decryptBtn.textContent = "Decrypt in App";
      decryptBtn.addEventListener("click", async () => {
        decryptBtn.disabled = true;
        showToast("Fetching encrypted document from Private Cloud Vault...", "info", 3000);
        try {
          const res = await downloadStoredDocument(doc.docId);
          const file = new File([res.bytes], doc.name || `${doc.docId}.zkkyc`, {
            type: "application/octet-stream",
          });

          // Set preservation flag so switching to Decrypt doesn't wipe this file
          isPreservingDecryptFile = true;
          switchView("decrypt");

          setDecryptFile(file);
          els.decryptPassphrase.focus();
          showToast("Document loaded from Vault. Enter your passphrase to decrypt.", "success", 4000);
        } catch (err) {
          showToast(`Could not load document: ${friendlySupabaseError(err)}`, "error", 5000);
        } finally {
          decryptBtn.disabled = false;
        }
      });

      // Download Button
      const downloadBtn = document.createElement("button");
      downloadBtn.type = "button";
      downloadBtn.className = "btn btn-secondary btn-sm";
      downloadBtn.textContent = "Download";
      downloadBtn.addEventListener("click", async () => {
        downloadBtn.disabled = true;
        showToast("Downloading encrypted file from Private Cloud Vault...", "info", 2000);
        try {
          const res = await downloadStoredDocument(doc.docId);
          triggerDownload(
            new Blob([res.bytes], { type: "application/octet-stream" }),
            doc.name || `${doc.docId}.zkkyc`
          );
          showToast("Encrypted file downloaded.", "success", 3000);
        } catch (err) {
          showToast(`Download failed: ${friendlySupabaseError(err)}`, "error", 5000);
        } finally {
          downloadBtn.disabled = false;
        }
      });

      // Delete Button with confirmation
      const deleteBtn = document.createElement("button");
      deleteBtn.type = "button";
      deleteBtn.className = "btn btn-danger btn-sm";
      deleteBtn.textContent = "Delete";
      deleteBtn.addEventListener("click", async () => {
        const confirmed = window.confirm(
          `Permanently delete this encrypted file from your cloud vault?\n\nDocument ID: ${doc.docId}\n\nThis action cannot be undone.`
        );
        if (!confirmed) return;

        deleteBtn.disabled = true;
        showToast("Deleting encrypted document from Private Cloud Vault...", "info", 2000);
        try {
          await deleteStoredDocument(doc.docId);
          showToast("Encrypted document deleted successfully.", "success", 3000);
          await loadVaultMain();
          renderSidebarVault();
        } catch (err) {
          showToast(`Deletion failed: ${friendlySupabaseError(err)}`, "error", 5000);
        } finally {
          deleteBtn.disabled = false;
        }
      });

      colActions.appendChild(decryptBtn);
      colActions.appendChild(downloadBtn);
      colActions.appendChild(deleteBtn);

      row.appendChild(colId);
      row.appendChild(colType);
      row.appendChild(colSize);
      row.appendChild(colDate);
      row.appendChild(colActions);

      els.vaultFilesList.appendChild(row);
    }
  } catch (err) {
    els.vaultLoadingState.classList.add("hidden");
    if (err.code === "mfa_required" || (err.message && err.message.includes("MFA verification required"))) {
      els.vaultMfaLockCard.classList.remove("hidden");
      els.vaultErrorState.classList.add("hidden");
      els.vaultEmptyStateMain.classList.add("hidden");
      els.vaultFilesContainer.classList.add("hidden");
    } else {
      els.vaultErrorState.classList.remove("hidden");
      els.vaultErrorMessage.textContent = `Could not load vault: ${friendlySupabaseError(err)}`;
    }
  }
}

/* ---------- Sidebar Vault (Decrypt View) ---------- */

async function renderSidebarVault() {
  if (!isSupabaseConfigured()) {
    els.vaultEmptyState.textContent =
      "Private Cloud Vault is not configured. Add credentials in supabase-config.js to enable cloud vault.";
    els.vaultEmptyState.classList.remove("hidden");
    els.vaultListContainer.classList.add("hidden");
    return;
  }

  try {
    const docs = await listStoredDocuments();
    els.vaultListContainer.textContent = "";

    if (!docs || docs.length === 0) {
      els.vaultEmptyState.textContent = "No encrypted documents found in cloud vault.";
      els.vaultEmptyState.classList.remove("hidden");
      els.vaultListContainer.classList.add("hidden");
      return;
    }

    els.vaultEmptyState.classList.add("hidden");
    els.vaultListContainer.classList.remove("hidden");

    for (const doc of docs) {
      const card = document.createElement("div");
      card.className = "vault-item-card";

      const idSpan = document.createElement("div");
      idSpan.className = "vault-item-id";
      idSpan.textContent = doc.name || `${doc.docId}.zkkyc`;
      idSpan.title = doc.docId;

      const metaSpan = document.createElement("div");
      metaSpan.className = "vault-item-meta";
      const date = doc.updated ? new Date(doc.updated).toLocaleDateString() : "Saved";
      metaSpan.textContent = `${formatBytes(doc.size)} • ${date}`;

      const actions = document.createElement("div");
      actions.className = "vault-item-actions";

      const loadBtn = document.createElement("button");
      loadBtn.type = "button";
      loadBtn.className = "btn btn-primary btn-sm";
      loadBtn.textContent = "Retrieve to Decrypt";
      loadBtn.addEventListener("click", async () => {
        if (isBusy) return;
        isBusy = true;
        showToast("Fetching encrypted document from Private Cloud Vault...", "info", 3000);
        try {
          const res = await downloadStoredDocument(doc.docId);
          const file = new File([res.bytes], doc.name || `${doc.docId}.zkkyc`, {
            type: "application/octet-stream",
          });
          setDecryptFile(file);
          els.decryptDropzone.scrollIntoView({ behavior: "smooth", block: "center" });
          showToast("Document retrieved. Enter your passphrase to decrypt.", "success", 4000);
        } catch (err) {
          showToast(`Retrieval failed: ${friendlySupabaseError(err)}`, "error", 5000);
        } finally {
          isBusy = false;
        }
      });

      const dlBtn = document.createElement("button");
      dlBtn.type = "button";
      dlBtn.className = "btn btn-secondary btn-sm";
      dlBtn.textContent = "Download";
      dlBtn.addEventListener("click", async () => {
        if (isBusy) return;
        isBusy = true;
        showToast("Downloading encrypted file from Private Cloud Vault...", "info", 2000);
        try {
          const res = await downloadStoredDocument(doc.docId);
          triggerDownload(
            new Blob([res.bytes], { type: "application/octet-stream" }),
            doc.name || `${doc.docId}.zkkyc`
          );
          showToast("Encrypted file downloaded.", "success", 3000);
        } catch (err) {
          showToast(`Download failed: ${friendlySupabaseError(err)}`, "error", 5000);
        } finally {
          isBusy = false;
        }
      });

      actions.appendChild(loadBtn);
      actions.appendChild(dlBtn);
      card.appendChild(idSpan);
      card.appendChild(metaSpan);
      card.appendChild(actions);

      els.vaultListContainer.appendChild(card);
    }
  } catch (err) {
    if (err.code === "mfa_required" || (err.message && err.message.includes("MFA verification required"))) {
      els.vaultEmptyState.textContent = "MFA verification (AAL2) required. Click Security/MFA in top bar to unlock.";
    } else {
      els.vaultEmptyState.textContent = "Could not load vault documents.";
    }
  }
}

/* ---------- Wire Dropzones ---------- */

function wireDropzone(zone, onFile) {
  zone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      zone.click();
    }
  });

  ["dragenter", "dragover"].forEach((evt) => {
    zone.addEventListener(evt, (e) => {
      e.preventDefault();
      zone.classList.add("drag");
    });
  });

  ["dragleave", "drop"].forEach((evt) => {
    zone.addEventListener(evt, (e) => {
      e.preventDefault();
      zone.classList.remove("drag");
    });
  });

  zone.addEventListener("drop", (e) => {
    const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) onFile(file);
  });
}

/* ---------- Event Listeners Setup ---------- */

// Navigation Links
els.navBtns.forEach((btn) => {
  btn.addEventListener("click", () => switchView(btn.dataset.nav));
});

// Home Page CTA Buttons
[els.homeHeroEncryptBtn, els.homeStartEncryptBtn].forEach((btn) => {
  if (btn) btn.addEventListener("click", () => switchView("encrypt"));
});

[els.homeHeroDecryptBtn, els.homeStartDecryptBtn].forEach((btn) => {
  if (btn) btn.addEventListener("click", () => switchView("decrypt"));
});

// Encrypt File Selection
wireDropzone(els.encryptDropzone, setEncryptFile);
els.encryptFileInput.addEventListener("change", () => {
  if (els.encryptFileInput.files && els.encryptFileInput.files[0]) {
    setEncryptFile(els.encryptFileInput.files[0]);
  }
});
els.encryptClearFileBtn.addEventListener("click", clearEncryptFile);

// Encrypt Passphrase & Show/Hide
els.encryptPassphrase.addEventListener("input", () => {
  setFieldError(els.encryptPassError, null);
  setFieldError(els.encryptActionError, null);
  els.encryptBreachNotice.classList.add("hidden");
  els.chkEncryptBreach.classList.remove("done");
  updateEncryptMeter();
  encryptedResult = null;
  encryptGen++;
  els.encryptionSuccessCard.classList.add("hidden");
});

els.toggleEncryptPass.addEventListener("click", () => {
  const isPass = els.encryptPassphrase.type === "password";
  els.encryptPassphrase.type = isPass ? "text" : "password";
  els.toggleEncryptPass.textContent = isPass ? "Hide" : "Show";
});

// Encrypt Actions
els.doEncryptBtn.addEventListener("click", handleEncryptDocument);
els.downloadEncryptedBtn.addEventListener("click", handleDownloadEncrypted);
els.uploadSupabaseBtn.addEventListener("click", handleUploadSupabase);

// Upload Cancellation Button
els.cancelUploadBtn.addEventListener("click", () => {
  if (activeUploadTask) {
    try {
      activeUploadTask.cancel();
    } catch { /* ignore */ }
    activeUploadTask = null;
  }
  els.uploadProgressContainer.classList.add("hidden");
  els.uploadSupabaseBtn.disabled = false;
  isBusy = false;
});

// Decrypt File Selection
wireDropzone(els.decryptDropzone, setDecryptFile);
els.decryptFileInput.addEventListener("change", () => {
  if (els.decryptFileInput.files && els.decryptFileInput.files[0]) {
    setDecryptFile(els.decryptFileInput.files[0]);
  }
});
els.decryptClearFileBtn.addEventListener("click", clearDecryptFile);

// Decrypt Passphrase & Show/Hide
els.decryptPassphrase.addEventListener("input", () => {
  setFieldError(els.decryptPassError, null);
  setFieldError(els.decryptActionError, null);
  clearDecryptedMemory();
  decryptGen++;
});

els.toggleDecryptPass.addEventListener("click", () => {
  const isPass = els.decryptPassphrase.type === "password";
  els.decryptPassphrase.type = isPass ? "text" : "password";
  els.toggleDecryptPass.textContent = isPass ? "Hide" : "Show";
});

// Decrypt Actions
els.doDecryptBtn.addEventListener("click", handleDecryptDocument);
els.downloadOriginalBtn.addEventListener("click", handleDownloadOriginal);
els.clearDecryptedBtn.addEventListener("click", () => {
  clearDecryptedMemory();
  showToast("Decrypted document cleared from memory.", "info", 2000);
});

// Sidebar Vault Refresh
els.vaultRefreshBtn.addEventListener("click", () => {
  renderSidebarVault();
  showToast("Vault refreshed.", "info", 2000);
});

// Dedicated My Vault Actions
els.vaultViewRefreshBtn.addEventListener("click", () => {
  loadVaultMain();
  showToast("My Vault refreshed.", "info", 2000);
});

els.vaultRetryBtn.addEventListener("click", () => {
  loadVaultMain();
});

els.vaultGoToEncryptBtn.addEventListener("click", () => {
  switchView("encrypt");
});

// Supabase Authentication Listeners
els.authOpenBtn.addEventListener("click", openAuthModal);
els.authCloseBtn.addEventListener("click", closeAuthModal);
els.authModal.addEventListener("click", (e) => {
  if (e.target === els.authModal) closeAuthModal();
});

els.tabSignIn.addEventListener("click", () => setAuthMode("signin"));
els.tabSignUp.addEventListener("click", () => setAuthMode("signup"));

// Step 1 & 2: Normal Login & Check MFA Status
els.authForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = els.authEmailInput.value.trim();
  const password = els.authPasswordInput.value;

  if (!email || !password) {
    setFieldError(els.authErrorMessage, "Please enter both email and password.");
    return;
  }

  setFieldError(els.authErrorMessage, null);
  els.authSubmitBtn.disabled = true;

  try {
    if (authMode === "signin") {
      // Step 1: Normal login with email and password
      await signInWithEmail(email, password);

      // Step 2: Retrieve actual Supabase MFA factors and check assurance level
      const factors = await listMFAFactors();
      const verifiedTotpFactor =
        factors.totp?.[0] ||
        factors.all?.find((f) => f.factor_type === "totp" && f.status === "verified");
      const aal = await getAssuranceLevel();

      // If user has verified TOTP factor, do NOT grant access yet; prompt for 6-digit code
      if (verifiedTotpFactor && (aal.nextLevel === "aal2" || aal.currentLevel !== "aal2")) {
        loginChallengeFactorId = verifiedTotpFactor.id;
        setAuthViewMode("totp");
        return;
      }

      // If no verified MFA factor, continue normal login
      closeAuthModal();
      showToast("Signed in successfully.", "success", 3000);
      const user = await getCurrentUser();
      await updateAuthUI(user);
      if (currentView === "vault") loadVaultMain();
      renderSidebarVault();
    } else {
      await signUpWithEmail(email, password);
      showToast("Account created. Check your email if confirmation is required.", "success", 4000);
      closeAuthModal();
      const user = await getCurrentUser();
      await updateAuthUI(user);
      if (currentView === "vault") loadVaultMain();
      renderSidebarVault();
    }
  } catch (err) {
    setFieldError(els.authErrorMessage, friendlySupabaseError(err));
  } finally {
    els.authSubmitBtn.disabled = false;
  }
});

// Step 3 & 4: Login-Time MFA Challenge Verification
els.authTotpForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const code = els.authTotpCodeInput.value.trim();

  if (!/^\d{6}$/.test(code)) {
    setFieldError(els.authTotpErrorMessage, "Please enter a valid 6-digit verification code.");
    return;
  }

  setFieldError(els.authTotpErrorMessage, null);
  els.authTotpSubmitBtn.disabled = true;

  try {
    if (!loginChallengeFactorId) {
      const factors = await listMFAFactors();
      const verified =
        factors.totp?.[0] ||
        factors.all?.find((f) => f.factor_type === "totp" && f.status === "verified");
      if (!verified) throw new Error("No verified authenticator factor found for this account.");
      loginChallengeFactorId = verified.id;
    }

    // Step 4: Verify the authenticator code with Supabase
    await challengeAndVerifyMFA(loginChallengeFactorId, code);

    // Confirm assurance level reaches AAL2
    const aal = await getAssuranceLevel();
    if (aal.currentLevel !== "aal2") {
      throw new Error("Authentication assurance level could not reach AAL2.");
    }

    closeAuthModal();
    showToast("Identity verified successfully. Welcome!", "success", 3000);

    const user = await getCurrentUser();
    await updateAuthUI(user);
    if (currentView === "vault") loadVaultMain();
    renderSidebarVault();
  } catch (err) {
    setFieldError(els.authTotpErrorMessage, friendlySupabaseError(err));
    els.authTotpCodeInput.value = "";
    els.authTotpCodeInput.focus();
  } finally {
    els.authTotpSubmitBtn.disabled = false;
  }
});

els.authTotpCancelBtn.addEventListener("click", async () => {
  try {
    await signOut();
  } catch { /* ignore */ }
  closeAuthModal();
  await updateAuthUI(null);
  showToast("Sign-in cancelled.", "info", 2000);
  if (currentView === "vault") loadVaultMain();
  renderSidebarVault();
});

els.authAnonymousBtn.addEventListener("click", async () => {
  els.authAnonymousBtn.disabled = true;
  setFieldError(els.authErrorMessage, null);
  try {
    await signInAnonymously();
    showToast("Signed in with anonymous session.", "success", 3000);
    closeAuthModal();
    const user = await getCurrentUser();
    await updateAuthUI(user);
    if (currentView === "vault") loadVaultMain();
    renderSidebarVault();
  } catch (err) {
    setFieldError(els.authErrorMessage, friendlySupabaseError(err));
  } finally {
    els.authAnonymousBtn.disabled = false;
  }
});

els.authSignOutBtn.addEventListener("click", async () => {
  try {
    await signOut();
    await updateAuthUI(null);
    showToast("Signed out successfully.", "info", 3000);
    if (currentView === "vault") loadVaultMain();
    renderSidebarVault();
  } catch (err) {
    showToast(`Sign out failed: ${friendlySupabaseError(err)}`, "error", 4000);
  }
});

// Compact MFA Action Listeners (Header button & Dashboard Settings card)
els.mfaSettingsOpenBtn.addEventListener("click", handleMfaAction);
if (els.mfaCompactActionBtn) {
  els.mfaCompactActionBtn.addEventListener("click", handleMfaAction);
}

// Compact Enrollment Modal Listeners
els.mfaEnrollCloseBtn.addEventListener("click", closeMfaEnrollModal);
els.mfaEnrollCancelBtn.addEventListener("click", closeMfaEnrollModal);
els.mfaEnrollModal.addEventListener("click", (e) => {
  if (e.target === els.mfaEnrollModal) closeMfaEnrollModal();
});

els.mfaEnrollCopySecretBtn.addEventListener("click", async () => {
  const secret = els.mfaEnrollSecretCode.textContent;
  if (!secret || secret === "Generating...") return;
  try {
    await navigator.clipboard.writeText(secret);
    const orig = els.mfaEnrollCopySecretBtn.textContent;
    els.mfaEnrollCopySecretBtn.textContent = "Copied!";
    setTimeout(() => {
      els.mfaEnrollCopySecretBtn.textContent = orig;
    }, 2000);
    showToast("Secret copied to clipboard.", "info", 2000);
  } catch {
    showToast("Failed to copy secret.", "error", 2000);
  }
});

els.mfaEnrollForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const code = els.mfaEnrollCodeInput.value.trim();

  if (!/^\d{6}$/.test(code)) {
    setFieldError(els.mfaEnrollErrorMessage, "Please enter a valid 6-digit code.");
    return;
  }

  if (!pendingEnrollFactorId) {
    setFieldError(els.mfaEnrollErrorMessage, "Enrollment session expired. Please reopen and try again.");
    return;
  }

  setFieldError(els.mfaEnrollErrorMessage, null);
  els.mfaEnrollSubmitBtn.disabled = true;

  try {
    await challengeAndVerifyMFA(pendingEnrollFactorId, code);
    showToast("Multi-Factor Authentication enabled successfully!", "success", 4000);
    closeMfaEnrollModal();

    const user = await getCurrentUser();
    await updateAuthUI(user);
    if (currentView === "vault") loadVaultMain();
    renderSidebarVault();
  } catch (err) {
    setFieldError(els.mfaEnrollErrorMessage, friendlySupabaseError(err));
    els.mfaEnrollCodeInput.focus();
  } finally {
    els.mfaEnrollSubmitBtn.disabled = false;
  }
});

// Compact Manage MFA Modal Listeners
els.mfaManageCloseBtn.addEventListener("click", closeMfaManageModal);
els.mfaManageCloseBottomBtn.addEventListener("click", closeMfaManageModal);
els.mfaManageModal.addEventListener("click", (e) => {
  if (e.target === els.mfaManageModal) closeMfaManageModal();
});

els.mfaDisableBtn.addEventListener("click", async () => {
  if (!currentMfaFactorId) {
    setFieldError(els.mfaManageErrorMessage, "No active factor found to disable.");
    return;
  }

  const confirmed = window.confirm(
    "Are you sure you want to disable Multi-Factor Authentication?\n\nYour account will return to single-factor password login."
  );
  if (!confirmed) return;

  els.mfaDisableBtn.disabled = true;
  els.mfaDisableBtn.textContent = "Disabling...";

  try {
    await unenrollMFAFactor(currentMfaFactorId);
    showToast("Multi-Factor Authentication has been disabled.", "info", 3000);
    closeMfaManageModal();

    const user = await getCurrentUser();
    await updateAuthUI(user);
    if (currentView === "vault") loadVaultMain();
    renderSidebarVault();
  } catch (err) {
    setFieldError(els.mfaManageErrorMessage, friendlySupabaseError(err));
    els.mfaDisableBtn.disabled = false;
    els.mfaDisableBtn.textContent = "Disable Multi-Factor Authentication";
  }
});

// Vault Lock Card Button
els.vaultVerifyMfaBtn.addEventListener("click", () => {
  openTotpChallengeModal();
});

// Subscribe to auth state changes
if (isSupabaseConfigured()) {
  onAuthStateChange(async (_event, session) => {
    const user = session?.user || null;
    await updateAuthUI(user);
    if (user) {
      try {
        const aal = await getAssuranceLevel();
        if (aal && aal.nextLevel === "aal2" && aal.currentLevel !== "aal2") {
          if (currentView === "vault") loadVaultMain();
          return;
        }
      } catch { /* ignore */ }
    }
    if (currentView === "vault") loadVaultMain();
    renderSidebarVault();
  });
}

// Hash routing support
window.addEventListener("hashchange", () => {
  const hash = location.hash.replace("#", "");
  if (["home", "encrypt", "decrypt", "vault"].includes(hash)) {
    switchView(hash);
  }
});

/* ---------- Initialization ---------- */
const initHash = location.hash.replace("#", "");
if (["home", "encrypt", "decrypt", "vault"].includes(initHash)) {
  switchView(initHash);
} else {
  switchView("home");
}

updateEncryptMeter();

if (isSupabaseConfigured()) {
  getCurrentUser()
    .then(async (user) => {
      await updateAuthUI(user);
      if (user) {
        const aal = await getAssuranceLevel();
        if (aal && aal.nextLevel === "aal2" && aal.currentLevel !== "aal2") {
          // Intermediate AAL1 state on page refresh: challenge user
          const factors = await listMFAFactors();
          const verified =
            factors.totp?.[0] ||
            factors.all?.find((f) => f.factor_type === "totp" && f.status === "verified");
          if (verified) {
            loginChallengeFactorId = verified.id;
          }
          openTotpChallengeModal();
        } else {
          renderSidebarVault();
        }
      }
    })
    .catch(() => {});
}
