// EncryptorVault Web Application Logic — OWASP Hardened

document.addEventListener('DOMContentLoaded', () => {
  initSearch();
  initKeyVisibility();
});

// ═══════════════════════════════════════════════
//  CSRF TOKEN HELPER (A01, A08)
// ═══════════════════════════════════════════════

function getCSRFToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute('content') : '';
}

// ═══════════════════════════════════════════════
//  TOAST NOTIFICATIONS — XSS-safe (A07)
// ═══════════════════════════════════════════════

function showToast(message, type = 'success') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;

  // Use textContent instead of innerHTML to prevent XSS (A07)
  const icon = document.createElement('span');
  icon.textContent = type === 'success' ? '✓' : '⚠️';
  const msg = document.createElement('div');
  msg.textContent = message;

  toast.appendChild(icon);
  toast.appendChild(msg);
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// ═══════════════════════════════════════════════
//  CLIPBOARD
// ═══════════════════════════════════════════════

function copyToClipboard(text, label = 'Key') {
  navigator.clipboard.writeText(text).then(() => {
    showToast(`${label} copied to clipboard!`, 'success');
  }).catch(err => {
    showToast('Failed to copy: ' + err, 'error');
  });
}

// ═══════════════════════════════════════════════
//  SEARCH & FILTER
// ═══════════════════════════════════════════════

function initSearch() {
  const searchInput = document.getElementById('searchInput');
  if (!searchInput) return;

  searchInput.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase();
    const rows = document.querySelectorAll('.key-row');

    rows.forEach(row => {
      const name = row.getAttribute('data-name') || '';
      const algo = row.getAttribute('data-algo') || '';
      const path = row.getAttribute('data-path') || '';

      if (name.toLowerCase().includes(query) || algo.toLowerCase().includes(query) || path.toLowerCase().includes(query)) {
        row.style.display = '';
      } else {
        row.style.display = 'none';
      }
    });
  });
}

// ═══════════════════════════════════════════════
//  KEY VISIBILITY TOGGLE
// ═══════════════════════════════════════════════

function initKeyVisibility() {
  document.addEventListener('click', (e) => {
    const toggleBtn = e.target.closest('.toggle-key-btn');
    if (!toggleBtn) return;

    const targetId = toggleBtn.getAttribute('data-target');
    const secretElem = document.getElementById(targetId);
    if (!secretElem) return;

    const isMasked = secretElem.getAttribute('data-masked') === 'true';
    const realValue = secretElem.getAttribute('data-real-value');

    if (isMasked) {
      secretElem.textContent = realValue;
      secretElem.setAttribute('data-masked', 'false');
      toggleBtn.textContent = '👁️';
    } else {
      secretElem.textContent = '••••••••••••••••';
      secretElem.setAttribute('data-masked', 'true');
      toggleBtn.textContent = '🔒';
    }
  });
}

// ═══════════════════════════════════════════════
//  MODALS
// ═══════════════════════════════════════════════

function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add('active');
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove('active');
  }
}

// ═══════════════════════════════════════════════
//  KEY GENERATION
// ═══════════════════════════════════════════════

function generateRandomKey(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=';
  const array = new Uint32Array(length);
  window.crypto.getRandomValues(array);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[array[i] % chars.length];
  }
  return result;
}

function handleGenerateKeyInModal() {
  const lenSelect = document.getElementById('genLength');
  const len = lenSelect ? parseInt(lenSelect.value) : 32;
  const newKey = generateRandomKey(len);
  const keyInput = document.getElementById('newKeyValue');
  if (keyInput) {
    keyInput.value = newKey;
    showToast('New random key generated!', 'success');
  }
}

// ═══════════════════════════════════════════════
//  API FUNCTIONS — with CSRF Token (A01, A08)
// ═══════════════════════════════════════════════

async function submitCreateKey(event) {
  event.preventDefault();
  const form = event.target;
  const keyName = form.key_name.value.trim();
  const algorithm = form.algorithm.value;
  const keyValue = form.key_value.value.trim();
  const filePath = form.file_path.value.trim();

  if (!keyName || !keyValue) {
    showToast('Key Name and Key Value are required', 'error');
    return;
  }

  // Input length validation (client-side, server also validates)
  if (keyName.length > 200) {
    showToast('Key Name is too long (max 200 characters)', 'error');
    return;
  }
  if (keyValue.length > 1000) {
    showToast('Key Value is too long (max 1000 characters)', 'error');
    return;
  }

  try {
    const res = await fetch('/api/keys', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCSRFToken()
      },
      body: JSON.stringify({ key_name: keyName, algorithm, key_value: keyValue, file_path: filePath })
    });

    const data = await res.json();
    if (res.ok) {
      showToast('Key saved to vault successfully!', 'success');
      closeModal('createKeyModal');
      setTimeout(() => location.reload(), 600);
    } else {
      showToast(data.error || 'Failed to save key', 'error');
    }
  } catch (err) {
    showToast('Network error: ' + err, 'error');
  }
}

function openEditModal(id, name, value) {
  document.getElementById('editKeyId').value = id;
  document.getElementById('editKeyName').value = name;
  document.getElementById('editKeyValue').value = value;
  openModal('editKeyModal');
}

async function submitEditKey(event) {
  event.preventDefault();
  const id = document.getElementById('editKeyId').value;
  const keyName = document.getElementById('editKeyName').value.trim();
  const keyValue = document.getElementById('editKeyValue').value.trim();

  if (!keyName || !keyValue) {
    showToast('Key Name and Key Value are required', 'error');
    return;
  }

  try {
    const res = await fetch(`/api/keys/${id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCSRFToken()
      },
      body: JSON.stringify({ key_name: keyName, key_value: keyValue })
    });

    const data = await res.json();
    if (res.ok) {
      showToast('Key updated successfully!', 'success');
      closeModal('editKeyModal');
      setTimeout(() => location.reload(), 600);
    } else {
      showToast(data.error || 'Failed to update key', 'error');
    }
  } catch (err) {
    showToast('Network error: ' + err, 'error');
  }
}

async function deleteKey(id, name) {
  if (!confirm(`Are you sure you want to delete key "${name}" from your vault?`)) {
    return;
  }

  try {
    const res = await fetch(`/api/keys/${id}`, {
      method: 'DELETE',
      headers: {
        'X-CSRF-Token': getCSRFToken()
      }
    });
    const data = await res.json();
    if (res.ok) {
      showToast(`Key "${name}" deleted`, 'success');
      const row = document.getElementById(`key-row-${id}`);
      if (row) row.remove();
      setTimeout(() => location.reload(), 600);
    } else {
      showToast(data.error || 'Failed to delete key', 'error');
    }
  } catch (err) {
    showToast('Network error: ' + err, 'error');
  }
}
