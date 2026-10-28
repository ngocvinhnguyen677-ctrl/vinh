/* ==========================================================
 * crypto.js - Lớp mã hóa phía Client (Zero-Knowledge)
 * ----------------------------------------------------------
 * - PBKDF2-HMAC-SHA256 (Web Crypto API, 310.000 vòng) sinh 768 bit:
 *     encKey  (256 bit) -> khóa AES-256
 *     macKey  (256 bit) -> khóa HMAC-SHA256 (toàn vẹn dữ liệu)
 *     authKey (256 bit) -> dùng để xác minh mật khẩu chủ
 * - AES-256-CBC + IV ngẫu nhiên mỗi lần mã hóa (CryptoJS)
 * - Encrypt-then-MAC: HMAC(iv || ciphertext)
 * - Mật khẩu chủ KHÔNG bao giờ được lưu; chỉ lưu salt + hash của authKey.
 * ========================================================== */
const VaultCrypto = (() => {
  const ITERATIONS = 310000;
  const SESSION_KEY = 'pmv_session';

  const bytesToHex = (bytes) =>
    Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  const hexToBytes = (hex) =>
    new Uint8Array(hex.match(/.{2}/g).map((h) => parseInt(h, 16)));

  function newSalt() {
    return CryptoJS.lib.WordArray.random(16).toString();
  }

  async function deriveKeys(password, saltHex) {
    if (!window.crypto || !crypto.subtle) {
      throw new Error('Trình duyệt cần chạy ở localhost hoặc HTTPS để dùng Web Crypto API.');
    }
    const baseKey = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: ITERATIONS, hash: 'SHA-256' },
      baseKey, 768
    );
    const hex = bytesToHex(new Uint8Array(bits));
    return { encKey: hex.slice(0, 64), macKey: hex.slice(64, 128), authKey: hex.slice(128, 192) };
  }

  function authHash(authKey) {
    return CryptoJS.SHA256(CryptoJS.enc.Hex.parse(authKey)).toString();
  }

  function safeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  /** Trả về chuỗi "ivHex:cipherBase64:macHex" */
  function encrypt(plain, keys) {
    const key = CryptoJS.enc.Hex.parse(keys.encKey);
    const iv = CryptoJS.lib.WordArray.random(16);
    const ct = CryptoJS.AES.encrypt(plain, key, {
      iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7,
    });
    const mac = CryptoJS.HmacSHA256(
      iv.clone().concat(ct.ciphertext), CryptoJS.enc.Hex.parse(keys.macKey)
    );
    return [iv.toString(), ct.ciphertext.toString(CryptoJS.enc.Base64), mac.toString()].join(':');
  }

  function decrypt(payload, keys) {
    const [ivHex, ctB64, macHex] = payload.split(':');
    if (!ivHex || !ctB64 || !macHex) throw new Error('Dữ liệu mã hóa không hợp lệ');
    const iv = CryptoJS.enc.Hex.parse(ivHex);
    const ct = CryptoJS.enc.Base64.parse(ctB64);
    const mac = CryptoJS.HmacSHA256(iv.clone().concat(ct), CryptoJS.enc.Hex.parse(keys.macKey)).toString();
    if (!safeEqual(mac, macHex)) throw new Error('Sai khóa hoặc dữ liệu đã bị chỉnh sửa (HMAC không khớp)');
    const dec = CryptoJS.AES.decrypt(
      CryptoJS.lib.CipherParams.create({ ciphertext: ct }),
      CryptoJS.enc.Hex.parse(keys.encKey),
      { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
    );
    return dec.toString(CryptoJS.enc.Utf8);
  }

  /* Khóa phiên chỉ nằm trong sessionStorage (mất khi đóng tab) */
  const saveSession = (keys) =>
    sessionStorage.setItem(SESSION_KEY, JSON.stringify({ encKey: keys.encKey, macKey: keys.macKey }));
  const loadSession = () => {
    try {
      const s = JSON.parse(sessionStorage.getItem(SESSION_KEY));
      return s && s.encKey && s.macKey ? s : null;
    } catch { return null; }
  };
  const clearSession = () => sessionStorage.removeItem(SESSION_KEY);

  return { ITERATIONS, newSalt, deriveKeys, authHash, encrypt, decrypt, saveSession, loadSession, clearSession };
})();
