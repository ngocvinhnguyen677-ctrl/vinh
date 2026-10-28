/* ==========================================================
 * utils.js - Toast, đo độ mạnh mật khẩu, sinh mật khẩu, tiện ích
 * ========================================================== */
const Utils = (() => {
  /* ---------- Toast Notification (thay alert) ---------- */
  const ICONS = {
    success: 'bi-check-circle-fill',
    error: 'bi-x-circle-fill',
    warning: 'bi-exclamation-triangle-fill',
    info: 'bi-info-circle-fill',
  };

  function toast(message, type = 'info', duration = 3200) {
    let box = document.getElementById('toast-container');
    if (!box) {
      box = document.createElement('div');
      box.id = 'toast-container';
      document.body.appendChild(box);
    }
    const el = document.createElement('div');
    el.className = `toast-item ${type}`;
    el.setAttribute('role', 'status');
    el.innerHTML = `<i class="bi ${ICONS[type] || ICONS.info} ico"></i><div class="flex-grow-1 small"></div>`;
    el.querySelector('div').textContent = message; // textContent => chống XSS
    box.appendChild(el);
    const close = () => {
      el.classList.add('hide');
      el.addEventListener('animationend', () => el.remove(), { once: true });
    };
    setTimeout(close, duration);
    el.addEventListener('click', close);
  }

  /* ---------- Độ mạnh mật khẩu ---------- */
  const LEVELS = [
    { name: 'Yếu', width: 25 },
    { name: 'Trung bình', width: 50 },
    { name: 'Mạnh', width: 75 },
    { name: 'Rất mạnh', width: 100 },
  ];

  function evaluate(pw) {
    if (!pw) return { level: -1, bits: 0 };
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
    let bits = pw.length * Math.log2(Math.max(pool, 2));
    // phạt: ký tự lặp liên tiếp & dãy phổ biến
    if (/(.)\1{2,}/.test(pw)) bits *= 0.75;
    if (/(0123|1234|2345|3456|abcd|qwer|password|matkhau)/i.test(pw)) bits *= 0.6;
    let level = 0;
    if (bits >= 90) level = 3;
    else if (bits >= 60) level = 2;
    else if (bits >= 35) level = 1;
    return { level, bits: Math.round(bits) };
  }

  /** Gắn thanh đo độ mạnh vào cặp (barEl, labelEl) */
  function renderStrength(pw, barEl, labelEl) {
    const r = evaluate(pw);
    LEVELS.forEach((_, i) => {
      barEl.classList.remove(`lvl-${i}`);
      labelEl.classList.remove(`lvl-${i}`);
    });
    if (r.level < 0) {
      barEl.style.width = '0';
      labelEl.textContent = 'Chưa nhập';
      return r;
    }
    barEl.style.width = LEVELS[r.level].width + '%';
    barEl.classList.add(`lvl-${r.level}`);
    labelEl.classList.add(`lvl-${r.level}`);
    labelEl.textContent = `${LEVELS[r.level].name} · ~${r.bits} bit`;
    return r;
  }

  /* ---------- Sinh mật khẩu ngẫu nhiên (CSPRNG) ---------- */
  function randInt(max) {
    const buf = new Uint32Array(1);
    const limit = Math.floor(0x100000000 / max) * max;
    do { crypto.getRandomValues(buf); } while (buf[0] >= limit); // tránh modulo bias
    return buf[0] % max;
  }

  function generate({ length = 16, upper = true, lower = true, digits = true, symbols = true, noAmbiguous = false }) {
    let sets = [];
    if (lower) sets.push('abcdefghijklmnopqrstuvwxyz');
    if (upper) sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if (digits) sets.push('0123456789');
    if (symbols) sets.push('!@#$%^&*()-_=+[]{};:,.<>?/~');
    if (!sets.length) return '';
    if (noAmbiguous) sets = sets.map((s) => s.replace(/[O0oIl1|]/g, ''));
    const all = sets.join('');
    const chars = sets.map((s) => s[randInt(s.length)]); // đảm bảo mỗi nhóm có ≥1 ký tự
    while (chars.length < length) chars.push(all[randInt(all.length)]);
    for (let i = chars.length - 1; i > 0; i--) { // Fisher–Yates
      const j = randInt(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.slice(0, length).join('');
  }

  /* ---------- Ẩn/hiện mật khẩu ---------- */
  function bindToggle(btn, input) {
    btn.addEventListener('click', () => {
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.innerHTML = `<i class="bi ${show ? 'bi-eye-slash' : 'bi-eye'}"></i>`;
    });
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
    }
  }

  const escapeHtml = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const uid = () => 'id_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);

  return { toast, evaluate, renderStrength, generate, bindToggle, copyText, escapeHtml, uid, LEVELS };
})();
