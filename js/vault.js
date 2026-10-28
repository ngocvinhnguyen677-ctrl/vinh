/* ==========================================================
 * vault.js - Giao diện chính: thêm / tìm / sao chép / xem mã hóa / xóa
 * Mọi mật khẩu được mã hóa AES-256 phía client trước khi lưu.
 * localStorage('pmv_vault') đóng vai trò "server" mô phỏng.
 * ========================================================== */
(() => {
  const VAULT_KEY = 'pmv_vault';
  const AUTO_LOCK_MS = 5 * 60 * 1000;
  const CLIPBOARD_CLEAR_MS = 30 * 1000;

  const $ = (id) => document.getElementById(id);

  /* ---------- Cổng bảo vệ: chưa xác thực thì quay về index ---------- */
  const keys = VaultCrypto.loadSession();
  if (!keys || sessionStorage.getItem('pmv_unlocked') !== '1') {
    location.replace('index.html');
    return;
  }
  $('app-body').classList.remove('d-none');

  let entries = [];
  let viewMode = 'card';
  let cipherShown = '';
  let deleteId = null;
  let clipTimer = null;

  const load = () => { try { entries = JSON.parse(localStorage.getItem(VAULT_KEY)) || []; } catch { entries = []; } };
  const persist = () => localStorage.setItem(VAULT_KEY, JSON.stringify(entries));

  /* ---------- Khóa kho & tự khóa ---------- */
  function lock(reason) {
    VaultCrypto.clearSession();
    sessionStorage.removeItem('pmv_unlocked');
    sessionStorage.removeItem('pmv_last');
    if (reason) sessionStorage.setItem('pmv_notice', reason);
    location.replace('index.html');
  }
  $('btn-lock').addEventListener('click', () => lock());

  let lastActivity = Date.now();
  ['click', 'keydown', 'mousemove', 'touchstart', 'scroll'].forEach((ev) =>
    document.addEventListener(ev, () => { lastActivity = Date.now(); }, { passive: true })
  );
  setInterval(() => {
    const left = AUTO_LOCK_MS - (Date.now() - lastActivity);
    if (left <= 0) return lock('timeout');
    const s = Math.ceil(left / 1000);
    $('lock-countdown').textContent = String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0');
  }, 1000);

  /* ---------- Form thêm tài khoản ---------- */
  const fPass = $('f-pass');
  Utils.bindToggle($('f-eye'), fPass);
  fPass.addEventListener('input', () => Utils.renderStrength(fPass.value, $('f-bar'), $('f-label')));

  /* Generator */
  $('g-len').addEventListener('input', (e) => { $('g-len-val').textContent = e.target.value; });
  $('btn-generate').addEventListener('click', () => {
    const opts = {
      length: +$('g-len').value,
      upper: $('g-upper').checked,
      lower: $('g-lower').checked,
      digits: $('g-digit').checked,
      symbols: $('g-symbol').checked,
      noAmbiguous: $('g-ambig').checked,
    };
    if (!opts.upper && !opts.lower && !opts.digits && !opts.symbols) {
      return Utils.toast('Hãy chọn ít nhất một loại ký tự.', 'warning');
    }
    fPass.value = Utils.generate(opts);
    fPass.type = 'text';
    $('f-eye').innerHTML = '<i class="bi bi-eye-slash"></i>';
    Utils.renderStrength(fPass.value, $('f-bar'), $('f-label'));
    Utils.toast('Đã sinh mật khẩu ngẫu nhiên.', 'info', 2000);
  });

  $('form-add').addEventListener('submit', (e) => {
    e.preventDefault();
    const app = $('f-app').value.trim();
    const user = $('f-user').value.trim();
    const pass = fPass.value;
    if (!app || !user || !pass) return Utils.toast('Vui lòng điền đủ ba trường.', 'warning');

    // 1) MÃ HÓA NGAY trên client bằng AES-256
    const cipher = VaultCrypto.encrypt(pass, keys);
    const entry = { id: Utils.uid(), app, username: user, cipher, createdAt: new Date().toISOString() };

    // 2) Chỉ gửi bản mã lên "server" (mô phỏng)
    entries.unshift(entry);
    persist();
    $('server-payload').textContent =
      'POST /api/vault  (HTTP 201)\n' +
      JSON.stringify({ id: entry.id, app: entry.app, username: entry.username, encrypted_password: entry.cipher, algorithm: 'AES-256-CBC + HMAC-SHA256' }, null, 2);

    // 3) Xóa mật khẩu thô khỏi form
    $('form-add').reset();
    fPass.type = 'password';
    $('f-eye').innerHTML = '<i class="bi bi-eye"></i>';
    Utils.renderStrength('', $('f-bar'), $('f-label'));
    render();
    Utils.toast('Đã thêm tài khoản mới (mật khẩu đã được mã hóa).', 'success');
  });

  /* ---------- Hiển thị danh sách ---------- */
  const COLORS = ['#5b8cff', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#06b6d4', '#ef4444', '#84cc16'];
  const colorOf = (s) => COLORS[[...s].reduce((a, c) => a + c.charCodeAt(0), 0) % COLORS.length];

  const actions = (id) => `
    <button class="btn btn-outline-light act-btn" data-act="copy" data-id="${id}" title="Sao chép mật khẩu"><i class="bi bi-clipboard-fill"></i></button>
    <button class="btn btn-outline-info act-btn" data-act="cipher" data-id="${id}" title="Xem chuỗi mã hóa AES-256"><i class="bi bi-eye-fill"></i></button>
    <button class="btn btn-outline-danger act-btn" data-act="delete" data-id="${id}" title="Xóa"><i class="bi bi-trash3-fill"></i></button>`;

  function render() {
    const q = $('search').value.trim().toLowerCase();
    const list = entries.filter((x) => x.app.toLowerCase().includes(q) || x.username.toLowerCase().includes(q));
    $('vault-count').textContent = entries.length;
    const box = $('vault-list');

    if (!list.length) {
      box.innerHTML = `<div class="empty-state"><i class="bi bi-inbox"></i>
        <p class="mt-3 mb-0">${entries.length ? 'Không tìm thấy kết quả phù hợp.' : 'Kho trống. Hãy thêm tài khoản đầu tiên ở khung bên trái.'}</p></div>`;
      return;
    }

    if (viewMode === 'card') {
      box.innerHTML = '<div class="row g-3">' + list.map((x) => `
        <div class="col-12 col-md-6">
          <div class="glass vault-card p-3 h-100">
            <div class="d-flex align-items-center gap-3 mb-3">
              <div class="avatar" style="background:${colorOf(x.app)}">${Utils.escapeHtml(x.app[0].toUpperCase())}</div>
              <div class="min-w-0">
                <div class="fw-semibold text-truncate">${Utils.escapeHtml(x.app)}</div>
                <div class="small text-dim text-truncate">${Utils.escapeHtml(x.username)}</div>
              </div>
            </div>
            <div class="d-flex align-items-center justify-content-between">
              <span class="pw-dots font-mono">••••••••••</span>
              <div class="d-flex gap-2">${actions(x.id)}</div>
            </div>
          </div>
        </div>`).join('') + '</div>';
    } else {
      box.innerHTML = `<div class="table-responsive"><table class="table table-dark table-hover align-middle mb-0">
        <thead><tr><th>Ứng dụng</th><th>Tài khoản</th><th>Mật khẩu</th><th class="text-end">Thao tác</th></tr></thead>
        <tbody>${list.map((x) => `
          <tr>
            <td class="fw-semibold">${Utils.escapeHtml(x.app)}</td>
            <td class="text-dim">${Utils.escapeHtml(x.username)}</td>
            <td class="pw-dots font-mono">••••••••••</td>
            <td class="text-end text-nowrap"><div class="d-inline-flex gap-2">${actions(x.id)}</div></td>
          </tr>`).join('')}</tbody></table></div>`;
    }
  }

  $('search').addEventListener('input', render);
  $('view-card').addEventListener('click', () => setView('card'));
  $('view-table').addEventListener('click', () => setView('table'));
  function setView(m) {
    viewMode = m;
    $('view-card').classList.toggle('active', m === 'card');
    $('view-table').classList.toggle('active', m === 'table');
    render();
  }

  /* ---------- Thao tác trên từng mục (ủy quyền sự kiện) ---------- */
  const cipherModal = new bootstrap.Modal($('modal-cipher'));
  const deleteModal = new bootstrap.Modal($('modal-delete'));

  $('vault-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    const entry = entries.find((x) => x.id === btn.dataset.id);
    if (!entry) return;

    if (btn.dataset.act === 'copy') {
      try {
        const plain = VaultCrypto.decrypt(entry.cipher, keys);
        await Utils.copyText(plain);
        Utils.toast(`Đã sao chép mật khẩu "${entry.app}". Sẽ tự xóa khỏi clipboard sau 30 giây.`, 'success', 3500);
        clearTimeout(clipTimer);
        clipTimer = setTimeout(() => { navigator.clipboard && navigator.clipboard.writeText(' ').catch(() => {}); }, CLIPBOARD_CLEAR_MS);
      } catch (err) {
        Utils.toast('Giải mã thất bại: ' + err.message, 'error', 5000);
      }
    }

    if (btn.dataset.act === 'cipher') {
      const [iv, ct, mac] = entry.cipher.split(':');
      cipherShown = entry.cipher;
      $('cipher-app').textContent = entry.app;
      $('c-iv').textContent = iv;
      $('c-ct').textContent = ct;
      $('c-mac').textContent = mac;
      cipherModal.show();
    }

    if (btn.dataset.act === 'delete') {
      deleteId = entry.id;
      $('del-name').textContent = entry.app;
      deleteModal.show();
    }
  });

  $('btn-copy-cipher').addEventListener('click', async () => {
    await Utils.copyText(cipherShown);
    Utils.toast('Đã sao chép chuỗi mã hóa.', 'success');
  });

  $('btn-del-confirm').addEventListener('click', () => {
    entries = entries.filter((x) => x.id !== deleteId);
    persist();
    deleteModal.hide();
    render();
    Utils.toast('Đã xóa tài khoản khỏi kho.', 'info');
  });

  /* ---------- Khởi động ---------- */
  load();
  render();
})();
