/* ── Drag & Drop Upload with Remove & Live Upload Progress ──────── */
document.addEventListener('DOMContentLoaded', () => {
  const dropZone  = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const fileList  = document.getElementById('fileList');
  if (!dropZone || !fileInput) return;

  let dt = new DataTransfer();

  dropZone.addEventListener('click', e => {
    if (e.target !== fileInput) fileInput.click();
  });

  ['dragenter', 'dragover'].forEach(ev => {
    dropZone.addEventListener(ev, e => {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    });
  });

  ['dragleave', 'drop'].forEach(ev => {
    dropZone.addEventListener(ev, e => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
    });
  });

  dropZone.addEventListener('drop', e => {
    const droppedFiles = e.dataTransfer.files;
    if (droppedFiles && droppedFiles.length) {
      appendFiles(droppedFiles);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files && fileInput.files.length) {
      appendFiles(fileInput.files);
    }
  });

  function appendFiles(newFiles) {
    Array.from(newFiles).forEach(f => {
      // Avoid duplicate filenames if already in queue
      let exists = false;
      for (let i = 0; i < dt.items.length; i++) {
        const itemFile = dt.items[i].getAsFile();
        if (itemFile && itemFile.name === f.name && itemFile.size === f.size) {
          exists = true;
          break;
        }
      }
      if (!exists) {
        dt.items.add(f);
      }
    });
    fileInput.files = dt.files;
    renderFileList();
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }

  function renderFileList() {
    if (!fileList) return;
    fileList.innerHTML = '';
    const files = dt.files;

    if (!files.length) {
      fileList.classList.add('hidden');
      return;
    }

    fileList.classList.remove('hidden');

    Array.from(files).forEach((f, idx) => {
      const isPdf = f.name.toLowerCase().endsWith('.pdf');
      const item = document.createElement('div');
      item.className = 'file-item';
      item.innerHTML = `
        <div class="file-item-left">
          <i class="fas fa-${isPdf ? 'file-pdf' : 'image'} file-item-icon" style="font-size:1.2rem; color:${isPdf ? '#dc2626' : '#2563eb'}"></i>
          <span class="file-item-name" title="${escapeHtml(f.name)}">${escapeHtml(f.name)}</span>
          <span class="file-item-size">(${formatSize(f.size)})</span>
        </div>
        <div class="file-item-right">
          <span class="ready-badge">
            <i class="fas fa-circle-check"></i> Ready to upload
          </span>
          <button type="button" class="btn-remove-file" title="Remove this file" aria-label="Remove ${escapeHtml(f.name)}" data-index="${idx}">
            <i class="fas fa-xmark"></i>
          </button>
        </div>
      `;

      item.querySelector('.btn-remove-file').addEventListener('click', (e) => {
        e.stopPropagation();
        removeFile(idx);
      });

      fileList.appendChild(item);
    });
  }

  function removeFile(indexToRemove) {
    const newDT = new DataTransfer();
    Array.from(dt.files).forEach((f, idx) => {
      if (idx !== indexToRemove) {
        newDT.items.add(f);
      }
    });
    dt = newDT;
    fileInput.files = dt.files;
    renderFileList();
  }

  function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
});

/* ── Form Upload with Progress Bar & Abort/Cancel ────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('#createForm, #addForm').forEach(form => {
    form.addEventListener('submit', function(e) {
      const fileInput = form.querySelector('input[type="file"]');
      const submitBtn = form.querySelector('button[type="submit"]');

      // Check required text input (e.g. vault_name in createForm)
      const nameInput = form.querySelector('#vault_name');
      if (nameInput && !nameInput.value.trim()) {
        nameInput.focus();
        return; // standard HTML5 validation
      }

      if (!fileInput || !fileInput.files || !fileInput.files.length) {
        // If no files, let standard form submission happen with loading state
        if (submitBtn) {
          submitBtn.disabled = true;
          submitBtn.classList.add('is-loading');
        }
        return;
      }

      e.preventDefault();

      // Create or show progress UI
      let progressBox = form.querySelector('.upload-progress-box');
      if (!progressBox) {
        progressBox = document.createElement('div');
        progressBox.className = 'upload-progress-box';
        form.appendChild(progressBox);
      }
      progressBox.style.display = 'flex';

      progressBox.innerHTML = `
        <div class="progress-header">
          <span class="progress-title"><i class="fas fa-shield-halved"></i> Encrypting & Uploading Documents...</span>
          <span class="progress-percentage" id="uploadPercentage">0%</span>
        </div>
        <div class="progress-track">
          <div class="progress-bar-fill" id="uploadProgressFill" style="width: 0%;"></div>
        </div>
        <div class="progress-footer">
          <span class="progress-status" id="uploadStatusText">Starting secure upload...</span>
          <button type="button" class="btn-cancel-upload" id="abortUploadBtn">Cancel</button>
        </div>
      `;

      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.style.display = 'none';
      }

      const formData = new FormData(form);
      const xhr = new XMLHttpRequest();
      let aborted = false;

      const abortBtn = progressBox.querySelector('#abortUploadBtn');
      if (abortBtn) {
        abortBtn.addEventListener('click', () => {
          aborted = true;
          xhr.abort();
          progressBox.style.display = 'none';
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.style.display = 'inline-flex';
          }
          if (typeof showToast === 'function') {
            showToast('Upload cancelled.', 'info');
          }
        });
      }

      xhr.upload.addEventListener('progress', (event) => {
        if (event.lengthComputable && !aborted) {
          const percent = Math.round((event.loaded / event.total) * 100);
          const fillEl = document.getElementById('uploadProgressFill');
          const percentEl = document.getElementById('uploadPercentage');
          const statusEl = document.getElementById('uploadStatusText');

          if (fillEl) fillEl.style.width = percent + '%';
          if (percentEl) percentEl.textContent = percent + '%';
          if (statusEl) {
            if (percent < 100) {
              const loadedMb = (event.loaded / (1024 * 1024)).toFixed(1);
              const totalMb = (event.total / (1024 * 1024)).toFixed(1);
              statusEl.textContent = `Uploaded ${loadedMb} MB of ${totalMb} MB...`;
            } else {
              statusEl.textContent = 'Encrypting and saving documents...';
            }
          }
        }
      });

      xhr.addEventListener('load', () => {
        if (aborted) return;
        if (xhr.status >= 200 && xhr.status < 400) {
          window.location.href = xhr.responseURL || window.location.href;
        } else {
          progressBox.style.display = 'none';
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.style.display = 'inline-flex';
          }
          if (typeof showToast === 'function') {
            showToast('An error occurred while uploading. Please try again.', 'error');
          }
        }
      });

      xhr.addEventListener('error', () => {
        if (aborted) return;
        progressBox.style.display = 'none';
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.style.display = 'inline-flex';
        }
        if (typeof showToast === 'function') {
          showToast('Upload connection error. Please try again.', 'error');
        }
      });

      xhr.open(form.method || 'POST', form.action || window.location.href);
      xhr.send(formData);
    });
  });
});
