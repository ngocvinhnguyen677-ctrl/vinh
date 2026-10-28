/* ==========================================================
 * auth.js - Luồng xác thực 2 lớp trước khi vào Vault
 *   Lần đầu : đặt mật khẩu chủ  ->  đăng ký khuôn mặt  ->  vào Vault
 *   Các lần sau: nhập mật khẩu chủ  ->  quét khuôn mặt  ->  vào Vault
 * Mật khẩu chủ không lưu; chỉ lưu salt + SHA-256(authKey).
 * Mẫu khuôn mặt được mã hóa AES-256 bằng khóa suy ra từ mật khẩu chủ.
 * ========================================================== */
(() => {
  const META_KEY = 'pmv_meta';
  const VAULT_KEY = 'pmv_vault';
  const MAX_ATTEMPTS = 5;
  const LOCK_SECONDS = 30;

  const $ = (id) => document.getElementById(id);
  const panes = { setup: $('pane-setup'), login: $('pane-login'), face: $('pane-face') };

  const getMeta = () => { try { return JSON.parse(localStorage.getItem(META_KEY)); } catch { return null; } };
  const setMeta = (m) => localStorage.setItem(META_KEY, JSON.stringify(m));

  let keys = null;          // khóa suy ra, chỉ giữ trong RAM
  let faceMode = 'verify';  // 'enroll' | 'verify'
  let abortCtl = null;

  function show(name, step) {
    Object.entries(panes).forEach(([k, el]) => el.classList.toggle('d-none', k !== name));
    $('dot-1').className = 'dot ' + (step > 1 ? 'done' : 'active');
    $('dot-2').className = 'dot ' + (step === 2 ? 'active' : '');
  }

  /* Nếu đã có phiên hợp lệ thì vào thẳng Vault */
  if (VaultCrypto.loadSession() && sessionStorage.getItem('pmv_unlocked') === '1') {
    location.replace('vault.html');
    return;
  }

  const meta = getMeta();
  if (!meta) show('setup', 1); else show('login', 1);

  if (sessionStorage.getItem('pmv_notice') === 'timeout') {
    sessionStorage.removeItem('pmv_notice');
    setTimeout(() => Utils.toast('Kho đã tự khóa do không hoạt động.', 'warning', 4500), 300);
  }

  /* ---------------- Ẩn/hiện + thanh độ mạnh ---------------- */
  Utils.bindToggle($('setup-pw-eye'), $('setup-pw'));
  Utils.bindToggle($('login-pw-eye'), $('login-pw'));
  $('setup-pw').addEventListener('input', (e) => Utils.renderStrength(e.target.value, $('setup-bar'), $('setup-label')));

  /* ---------------- THIẾT LẬP LẦN ĐẦU ---------------- */
  $('form-setup').addEventListener('submit', async (e) => {
    e.preventDefault();
    const pw = $('setup-pw').value;
    const pw2 = $('setup-pw2').value;
    if (pw.length < 10) return Utils.toast('Mật khẩu chủ cần tối thiểu 10 ký tự.', 'warning');
    if (Utils.evaluate(pw).level < 2) return Utils.toast('Mật khẩu chủ còn yếu. Hãy dùng chữ hoa, thường, số và ký tự đặc biệt.', 'warning');
    if (pw !== pw2) return Utils.toast('Hai mật khẩu không khớp.', 'error');

    const btn = $('btn-setup');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Đang sinh khóa (PBKDF2)…';
    try {
      const salt = VaultCrypto.newSalt();
      keys = await VaultCrypto.deriveKeys(pw, salt);
      setMeta({ salt, iterations: VaultCrypto.ITERATIONS, authHash: VaultCrypto.authHash(keys.authKey), faceEnc: null });
      Utils.toast('Đã tạo mật khẩu chủ. Tiếp theo: đăng ký khuôn mặt.', 'success');
      startFaceStep('enroll');
    } catch (err) {
      Utils.toast(err.message, 'error', 5000);
    } finally {
      btn.disabled = false;
      btn.innerHTML = 'Tiếp tục <i class="bi bi-arrow-right ms-1"></i>';
    }
  });

  /* ---------------- ĐĂNG NHẬP BẰNG MẬT KHẨU ---------------- */
  let attempts = 0;
  let lockedUntil = 0;
  let lockTimer = null;

  function updateLockUI() {
    const left = Math.ceil((lockedUntil - Date.now()) / 1000);
    const note = $('login-attempts');
    if (left > 0) {
      note.classList.remove('d-none');
      note.innerHTML = `<i class="bi bi-lock-fill text-danger"></i> Tạm khóa ${left}s do nhập sai nhiều lần.`;
      $('btn-login').disabled = true;
    } else {
      clearInterval(lockTimer);
      $('btn-login').disabled = false;
      note.classList.add('d-none');
    }
  }

  $('form-login').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (Date.now() < lockedUntil) return;
    const pw = $('login-pw').value;
    if (!pw) return Utils.toast('Vui lòng nhập mật khẩu chủ.', 'warning');

    const m = getMeta();
    const btn = $('btn-login');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Đang kiểm tra…';
    try {
      const k = await VaultCrypto.deriveKeys(pw, m.salt);
      const ok = VaultCrypto.authHash(k.authKey) === m.authHash;
      if (!ok) {
        attempts++;
        const left = MAX_ATTEMPTS - attempts;
        if (left <= 0) {
          attempts = 0;
          lockedUntil = Date.now() + LOCK_SECONDS * 1000;
          lockTimer = setInterval(updateLockUI, 500);
          updateLockUI();
          Utils.toast(`Sai quá ${MAX_ATTEMPTS} lần. Tạm khóa ${LOCK_SECONDS} giây.`, 'error', 4500);
        } else {
          Utils.toast(`Mật khẩu chủ không đúng. Còn ${left} lần thử.`, 'error');
        }
        $('login-pw').value = '';
        $('login-pw').focus();
        return;
      }
      attempts = 0;
      keys = k;
      $('login-pw').value = '';
      Utils.toast('Mật khẩu chính xác. Vui lòng quét khuôn mặt.', 'success');
      startFaceStep(m.faceEnc ? 'verify' : 'enroll');
    } catch (err) {
      Utils.toast(err.message, 'error', 5000);
    } finally {
      if (Date.now() >= lockedUntil) btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-unlock-fill me-1"></i> Xác thực mật khẩu';
    }
  });

  /* ---------------- BƯỚC KHUÔN MẶT ---------------- */
  const scanner = $('scanner');
  const video = $('video');
  const statusEl = $('face-status');
  const setStatus = (html) => { statusEl.innerHTML = html; };
  const setScanner = (cls) => { scanner.className = 'scanner mb-3 ' + cls; };

  async function startFaceStep(mode) {
    faceMode = mode;
    show('face', 2);
    $('btn-enroll').classList.add('d-none');
    $('btn-retry').classList.add('d-none');
    $('face-progress-wrap').classList.add('d-none');
    setScanner('idle');

    if (mode === 'enroll') {
      $('face-title').textContent = 'Bước 2 · Đăng ký khuôn mặt';
      $('face-desc').textContent = 'Đặt khuôn mặt vào giữa khung, đủ sáng, chỉ một người. Hệ thống sẽ chụp nhiều mẫu.';
    } else {
      $('face-title').textContent = 'Bước 2 · Nhận diện khuôn mặt';
      $('face-desc').textContent = 'Nhìn thẳng vào camera để mở khóa kho mật khẩu.';
    }

    try {
      setStatus('<span class="spinner-border spinner-border-sm me-2"></span>Đang tải mô hình nhận diện…');
      await Face.loadModels();
      setStatus('<span class="spinner-border spinner-border-sm me-2"></span>Đang bật camera…');
      await Face.startCamera(video);
    } catch (err) {
      setScanner('fail');
      const msg = err && err.name === 'NotAllowedError'
        ? 'Bạn đã từ chối quyền truy cập camera. Hãy cấp quyền rồi thử lại.'
        : (err.message || 'Không thể khởi tạo camera/mô hình.');
      setStatus(`<span class="text-danger"><i class="bi bi-camera-video-off"></i> ${Utils.escapeHtml(msg)}</span>`);
      $('btn-retry').classList.remove('d-none');
      return;
    }

    if (mode === 'enroll') {
      setScanner('');
      setStatus('<span class="text-dim">Sẵn sàng. Bấm nút bên dưới để bắt đầu quét.</span>');
      $('btn-enroll').classList.remove('d-none');
    } else {
      runVerify();
    }
  }

  /* --- Đăng ký --- */
  $('btn-enroll').addEventListener('click', async () => {
    const btn = $('btn-enroll');
    btn.disabled = true;
    setScanner('');
    $('face-progress-wrap').classList.remove('d-none');
    try {
      const template = await Face.enroll(video, 6, (p, count) => {
        $('face-progress').style.width = Math.round(p * 100) + '%';
        if (count === 0) setStatus('<span class="text-warning">Không thấy khuôn mặt – hãy nhìn thẳng vào camera.</span>');
        else if (count > 1) setStatus('<span class="text-warning">Phát hiện nhiều khuôn mặt – chỉ để một người trong khung.</span>');
        else setStatus('<span class="text-info">Đang thu mẫu khuôn mặt…</span>');
      });
      const m = getMeta();
      m.faceEnc = VaultCrypto.encrypt(JSON.stringify(template), keys); // mã hóa mẫu mặt
      setMeta(m);
      setScanner('success');
      setStatus('<span class="text-success"><i class="bi bi-check-circle-fill"></i> Đăng ký khuôn mặt thành công!</span>');
      Utils.toast('Đã đăng ký khuôn mặt. Đang mở kho mật khẩu…', 'success');
      finishLogin();
    } catch (err) {
      setScanner('fail');
      setStatus(`<span class="text-danger">${Utils.escapeHtml(err.message)}</span>`);
      $('face-progress-wrap').classList.add('d-none');
      btn.disabled = false;
    }
  });

  /* --- Xác thực --- */
  async function runVerify() {
    setScanner('');
    $('btn-retry').classList.add('d-none');
    abortCtl = new AbortController();
    let template;
    try {
      template = JSON.parse(VaultCrypto.decrypt(getMeta().faceEnc, keys));
    } catch {
      setScanner('fail');
      setStatus('<span class="text-danger">Không đọc được mẫu khuôn mặt (dữ liệu hỏng).</span>');
      return;
    }
    $('face-progress-wrap').classList.remove('d-none');
    const res = await Face.verify(video, template, {
      signal: abortCtl.signal,
      onTick: ({ state, streak }) => {
        $('face-progress').style.width = Math.round((streak / Face.REQUIRED_MATCHES) * 100) + '%';
        const msg = {
          noface: '<span class="text-warning">Không thấy khuôn mặt…</span>',
          multi: '<span class="text-warning">Có nhiều hơn một khuôn mặt trong khung.</span>',
          mismatch: '<span class="text-danger">Khuôn mặt chưa khớp…</span>',
          match: '<span class="text-info">Đang xác minh…</span>',
        }[state];
        setStatus(msg);
      },
    }).catch(() => ({ ok: false, aborted: true }));

    if (res.aborted) return;
    if (res.ok) {
      setScanner('success');
      setStatus('<span class="text-success"><i class="bi bi-check-circle-fill"></i> Xác thực khuôn mặt thành công!</span>');
      Utils.toast('Chào mừng trở lại! Đang mở kho mật khẩu…', 'success');
      finishLogin();
    } else {
      setScanner('fail');
      setStatus('<span class="text-danger"><i class="bi bi-x-circle-fill"></i> Khuôn mặt không khớp hoặc hết thời gian.</span>');
      $('btn-retry').classList.remove('d-none');
      Utils.toast('Nhận diện khuôn mặt thất bại.', 'error');
    }
  }

  $('btn-retry').addEventListener('click', () => startFaceStep(faceMode));

  $('btn-back').addEventListener('click', () => {
    if (abortCtl) abortCtl.abort();
    Face.stopCamera(video);
    keys = null;
    show(getMeta() && getMeta().faceEnc ? 'login' : (getMeta() ? 'login' : 'setup'), 1);
  });

  function finishLogin() {
    Face.stopCamera(video);
    VaultCrypto.saveSession(keys);
    sessionStorage.setItem('pmv_unlocked', '1');
    sessionStorage.setItem('pmv_last', String(Date.now()));
    setTimeout(() => location.replace('vault.html'), 900);
  }

  /* ---------------- RESET ---------------- */
  const resetModal = new bootstrap.Modal($('modal-reset'));
  $('btn-reset').addEventListener('click', () => resetModal.show());
  $('btn-reset-confirm').addEventListener('click', () => {
    localStorage.removeItem(META_KEY);
    localStorage.removeItem(VAULT_KEY);
    VaultCrypto.clearSession();
    sessionStorage.removeItem('pmv_unlocked');
    resetModal.hide();
    Utils.toast('Đã xóa toàn bộ dữ liệu. Hãy thiết lập lại.', 'info');
    setTimeout(() => location.reload(), 900);
  });

  window.addEventListener('beforeunload', () => Face.stopCamera(video));
})();
