/* ═══════════════════════════════════════════════
   SECUREVAULT — Main JS
   ═══════════════════════════════════════════════ */

/* ── CSRF: attach token to every same-origin fetch() ──
   Flask-WTF's CSRFProtect checks this header on every
   POST/PUT/PATCH/DELETE. Patching fetch here means none
   of the existing fetch() calls elsewhere need to change. */
(function() {
  const token = document.querySelector('meta[name="csrf-token"]')?.content;
  const originalFetch = window.fetch;
  window.fetch = function(input, init) {
    init = init || {};
    const method = (init.method || 'GET').toUpperCase();
    const isSameOrigin = !/^https?:\/\//i.test(typeof input === 'string' ? input : input.url) ;
    if (token && isSameOrigin && !['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(method)) {
      init.headers = Object.assign({}, init.headers, { 'X-CSRFToken': token });
    }
    return originalFetch(input, init);
  };
})();

/* ── Dark Mode ─────────────────────────────────── */
(function() {
  const saved = localStorage.getItem('sv-theme') || 'light';
  document.documentElement.setAttribute('data-theme', saved);
})();

function toggleDark() {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('sv-theme', next);
  const icon = document.getElementById('darkIcon');
  if (icon) icon.className = next === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
}

document.addEventListener('DOMContentLoaded', () => {
  const icon = document.getElementById('darkIcon');
  if (icon) {
    const theme = document.documentElement.getAttribute('data-theme');
    icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
  }
});

/* ── Toast Notifications ───────────────────────── */
function showToast(message, type = 'info', title = null) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }

  const icons = {
    success: 'fa-circle-check',
    error:   'fa-circle-exclamation',
    warning: 'fa-triangle-exclamation',
    info:    'fa-circle-info'
  };
  const titles = {
    success: title || 'Success',
    error:   title || 'Error',
    warning: title || 'Warning',
    info:    title || 'Info'
  };

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <i class="fas ${icons[type] || icons.info} toast-icon"></i>
    <div class="toast-body">
      <div class="toast-title">${titles[type]}</div>
      <div class="toast-msg">${message}</div>
    </div>
    <button class="toast-close" onclick="dismissToast(this.parentElement)">×</button>
  `;
  container.appendChild(toast);

  setTimeout(() => dismissToast(toast), 4500);
}

function dismissToast(toast) {
  if (!toast || toast.classList.contains('hiding')) return;
  toast.classList.add('hiding');
  setTimeout(() => toast.remove(), 300);
}

/* Convert flash messages to toasts */
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.alert').forEach(alert => {
    const cat = [...alert.classList].find(c => c.startsWith('alert-'))?.replace('alert-', '') || 'info';
    const msg = alert.querySelector('span')?.textContent?.trim() || alert.textContent.trim();
    const typeMap = { error: 'error', success: 'success', warning: 'warning', info: 'info' };
    showToast(msg, typeMap[cat] || 'info');
    alert.remove();
  });
  const fc = document.querySelector('.flash-container');
  if (fc) fc.remove();
});

/* ── Password Toggle ───────────────────────────── */
function togglePw(id) {
  const inp = document.getElementById(id);
  if (!inp) return;
  const isPw = inp.type === 'password';
  inp.type = isPw ? 'text' : 'password';
  const parent = inp.closest('.gate-input-wrap, .input-wrapper, .form-group') || inp.parentElement;
  if (parent) {
    const btn = parent.querySelector('.toggle-pw-gate, .toggle-pw, .share-pw-toggle');
    if (btn) {
      const icon = btn.querySelector('i');
      if (icon) {
        if (isPw) {
          icon.classList.remove('fa-eye');
          icon.classList.add('fa-eye-slash');
        } else {
          icon.classList.remove('fa-eye-slash');
          icon.classList.add('fa-eye');
        }
      }
    }
  }
}

/* ── Generic button loading state (prevents double-clicks) ─
   Shared by any form/button across the app — see .btn.is-loading in
   style.css. Usage: onclick="setBtnLoading(this, 'Saving...')" */
function setBtnLoading(btn, label) {
  if (!btn) return;
  btn.classList.add('is-loading');
  btn.disabled = true;
  btn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${label}`;
}

/* ── Delete / Stop-Sharing Confirmation Modal ──── */
let pendingDeleteForm = null;
let pendingAjaxRevoke = null; // { vaultId, shareId, onSuccess } — set by confirmStopSharingAjax

const CONFIRM_COPY = {
  document: {
    title: 'Delete this document?',
    message: (name) => `Are you sure you want to delete <span class="modal-filename">${name}</span>?<br>This action <strong>cannot be undone.</strong>`,
    btn: '<i class="fas fa-trash"></i> Delete Document'
  },
  vault: {
    title: 'Delete this folder?',
    message: (name) => `Are you sure you want to delete <span class="modal-filename">${name}</span> and everything inside it?<br>This action <strong>cannot be undone.</strong>`,
    btn: '<i class="fas fa-trash"></i> Delete Folder'
  },
  share: {
    title: 'Stop sharing this document?',
    message: (name) => `<span class="modal-filename">${name}</span> will no longer be reachable through this link or QR code.<br>Anyone who has it will lose access right away.`,
    btn: '<i class="fas fa-ban"></i> Stop Sharing'
  },
  share_delete: {
    title: 'Delete this share record?',
    message: (name) => `This removes <span class="modal-filename">${name}</span> and its access history for good.<br>This action <strong>cannot be undone.</strong>`,
    btn: '<i class="fas fa-trash"></i> Delete'
  }
};

function confirmDelete(filename, formId, type = 'document') {
  pendingAjaxRevoke = null;
  pendingDeleteForm = document.getElementById(formId);
  const modal = document.getElementById('deleteModal');
  const titleEl = document.getElementById('deleteModalTitle');
  const msgEl = document.getElementById('deleteModalMessage');
  const btnEl = document.getElementById('deleteModalConfirmBtn');
  const copy = CONFIRM_COPY[type] || CONFIRM_COPY.document;
  const safeName = `"${filename}"`;
  if (titleEl) titleEl.textContent = copy.title;
  if (msgEl) msgEl.innerHTML = copy.message(safeName);
  if (btnEl) btnEl.innerHTML = copy.btn;
  if (modal) modal.classList.remove('hidden');
}

/* Stop a share link without navigating away — used on pages (like Activity
   Log) where a full-page redirect back to the share-management page would
   be disruptive. Calls onSuccess(data) so the caller can update just that
   row's UI in place. */
function confirmStopSharingAjax(filename, vaultId, shareId, onSuccess) {
  pendingDeleteForm = null;
  pendingAjaxRevoke = { vaultId, shareId, onSuccess };
  const modal = document.getElementById('deleteModal');
  const titleEl = document.getElementById('deleteModalTitle');
  const msgEl = document.getElementById('deleteModalMessage');
  const btnEl = document.getElementById('deleteModalConfirmBtn');
  const copy = CONFIRM_COPY.share;
  const safeName = `"${filename}"`;
  if (titleEl) titleEl.textContent = copy.title;
  if (msgEl) msgEl.innerHTML = copy.message(safeName);
  if (btnEl) btnEl.innerHTML = copy.btn;
  if (modal) modal.classList.remove('hidden');
}

function cancelDelete() {
  pendingDeleteForm = null;
  pendingAjaxRevoke = null;
  const modal = document.getElementById('deleteModal');
  if (modal) modal.classList.add('hidden');
}

async function proceedDelete() {
  if (pendingAjaxRevoke) {
    const { vaultId, shareId, onSuccess } = pendingAjaxRevoke;
    const btnEl = document.getElementById('deleteModalConfirmBtn');
    setBtnLoading(btnEl, 'Stopping...');
    try {
      const res = await fetch(`/vault/${vaultId}/share/${shareId}/revoke`, {
        method: 'POST',
        headers: { 'Accept': 'application/json' }
      });
      const data = await res.json();
      if (data.success) {
        showToast(data.message || 'Share link stopped.', 'success');
        if (onSuccess) onSuccess();
      } else {
        showToast(data.message || 'Could not stop sharing.', 'error');
      }
    } catch (err) {
      showToast('Network error while stopping the share. Please try again.', 'error');
    }
    cancelDelete();
    return;
  }
  if (pendingDeleteForm) pendingDeleteForm.submit();
  cancelDelete();
}

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') cancelDelete();
});

document.addEventListener('click', e => {
  const modal = document.getElementById('deleteModal');
  if (modal && e.target === modal) cancelDelete();
});

/* ── Stat Card Counter Animation ──────────────── */
function animateCount(el, target, duration = 1200, isFloat = false) {
  const start = performance.now();
  const update = (now) => {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const ease = 1 - Math.pow(1 - progress, 3);
    const current = isFloat ? (target * ease).toFixed(1) : Math.round(target * ease);
    el.textContent = current;
    if (progress < 1) requestAnimationFrame(update);
    else el.textContent = isFloat ? target.toFixed(1) : target;
  };
  requestAnimationFrame(update);
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-count]').forEach(el => {
    const target = parseFloat(el.dataset.count);
    const isFloat = el.dataset.float === 'true';
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          animateCount(el, target, 1000, isFloat);
          observer.disconnect();
        }
      });
    }, { threshold: .3 });
    observer.observe(el);
  });
});

/* ── Search & Filter (legacy manage page only) ─── */
document.addEventListener('DOMContentLoaded', () => {
  // Only run on pages using the old .doc-card class (not the new workspace)
  if (!document.querySelector('.doc-card') || document.querySelector('.doc-grid-card')) return;

  const search = document.getElementById('searchInput');
  if (search) {
    search.addEventListener('input', function() {
      const q = this.value.toLowerCase();
      document.querySelectorAll('.doc-card').forEach(card => {
        card.style.display = (card.dataset.name || '').includes(q) ? '' : 'none';
      });
    });
  }

  document.querySelectorAll('.filter-chip').forEach(chip => {
    chip.addEventListener('click', function() {
      document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
      this.classList.add('active');
      const filter = this.dataset.filter;
      document.querySelectorAll('.doc-card').forEach(card => {
        if (filter === 'all') card.style.display = '';
        else if (filter === 'pdf') card.style.display = card.dataset.type === 'pdf' ? '' : 'none';
        else card.style.display = ['jpg','jpeg','png'].includes(card.dataset.type) ? '' : 'none';
      });
    });
  });
});

/* ── View Toggle (legacy manage page only) ─────────── */
function toggleViewMenu(e) {
  if (e) e.stopPropagation();
  const menu = document.getElementById('viewMenu');
  if (menu) menu.classList.toggle('hidden');
}

document.addEventListener('DOMContentLoaded', () => {
  // Only restore view on pages with the OLD vault-items-container (not the new workspace)
  if (!document.getElementById('vault-items-container') || document.getElementById('vault-items-wrapper')) return;
  let saved = 'medium';
  try { saved = localStorage.getItem('vaultViewMode') || 'medium'; } catch (err) {}
  // legacy setVaultView for manage.html
  const container = document.getElementById('vault-items-container');
  if (container) container.classList.toggle('view-details', saved === 'details');
});

document.addEventListener('click', (e) => {
  const wrap = document.getElementById('viewToggleWrap');
  const menu = document.getElementById('viewMenu');
  if (wrap && menu && !wrap.contains(e.target)) menu.classList.add('hidden');
});

/* ── Scroll-to-top FAB ──────────────────────────── */
(function() {
  const fab = document.getElementById('scrollTopFab');
  if (!fab) return;
  const toggleFab = () => {
    if (window.scrollY > 320) fab.classList.remove('hidden');
    else fab.classList.add('hidden');
  };
  window.addEventListener('scroll', toggleFab, { passive: true });
  toggleFab();
})();

/* ── Rename helpers ────────────────────────────── */
function startRename(docId) {
  document.getElementById('name-' + docId)?.classList.add('hidden');
  const form = document.getElementById('rename-form-' + docId);
  form?.classList.remove('hidden');
  const inp = document.getElementById('rename-input-' + docId);
  if (inp) { inp.focus(); inp.select(); }
}
function cancelRename(docId) {
  document.getElementById('name-' + docId)?.classList.remove('hidden');
  document.getElementById('rename-form-' + docId)?.classList.add('hidden');
}

/* ── Copy to clipboard ─────────────────────────── */
function copyText(elemId, btn) {
  const text = document.getElementById(elemId)?.textContent?.trim();
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    if (btn) {
      btn.innerHTML = '<i class="fas fa-check"></i>';
      btn.style.color = '#10b981';
      setTimeout(() => { btn.innerHTML = '<i class="fas fa-copy"></i>'; btn.style.color = ''; }, 2000);
    }
    showToast('Copied to clipboard!', 'success');
  });
}

/* ── Paste helper ──────────────────────────────── */
async function pasteVaultId() {
  try {
    const text = await navigator.clipboard.readText();
    const inp = document.getElementById('vaultIdInput');
    if (inp) inp.value = text.trim();
    showToast('Pasted!', 'success');
  } catch(e) {
    showToast('Paste with Ctrl+V / Cmd+V', 'info');
  }
}

/* ── User Profile Dropdown ──────────────────────── */
function toggleUserMenu(e) {
  if (e) {
    e.stopPropagation();
    e.preventDefault();
  }
  const btn = document.getElementById('userMenuBtn');
  const dropdown = document.getElementById('userDropdown');
  if (!dropdown) return;
  const isHidden = dropdown.classList.toggle('hidden');
  if (btn) btn.setAttribute('aria-expanded', isHidden ? 'false' : 'true');
}

document.addEventListener('click', function(e) {
  const wrap = document.getElementById('userMenuWrap');
  const dropdown = document.getElementById('userDropdown');
  const btn = document.getElementById('userMenuBtn');
  if (wrap && dropdown && !wrap.contains(e.target)) {
    dropdown.classList.add('hidden');
    if (btn) btn.setAttribute('aria-expanded', 'false');
  }
});

/* ── Mobile nav toggle ─────────────────────────── */
(function() {
  const toggle = document.getElementById('navToggle');
  const links  = document.getElementById('navLinks');
  if (!toggle || !links) return;

  toggle.addEventListener('click', function() {
    const open = links.classList.toggle('is-open');
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    toggle.innerHTML = open ? '<i class="fas fa-xmark"></i>' : '<i class="fas fa-bars"></i>';
  });

  // Close the menu after tapping a link (mobile), but ignore userMenuBtn toggle clicks
  links.querySelectorAll('a').forEach(function(a) {
    a.addEventListener('click', function() {
      links.classList.remove('is-open');
      toggle.setAttribute('aria-expanded', 'false');
      toggle.innerHTML = '<i class="fas fa-bars"></i>';
    });
  });
})();
