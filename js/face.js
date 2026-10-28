/* ==========================================================
 * face.js - Nhận diện khuôn mặt chạy hoàn toàn trên trình duyệt
 * ----------------------------------------------------------
 * Dùng @vladmandic/face-api (TinyFaceDetector + landmark 68 + face recognition net).
 * Mỗi khuôn mặt -> vector đặc trưng 128 số. So khớp bằng khoảng cách Euclid.
 * Vector này được MÃ HÓA bằng khóa từ mật khẩu chủ trước khi lưu (xem auth.js).
 * ========================================================== */
const Face = (() => {
  const MODEL_URL = 'https://cdn.jsdelivr.net/npm/@vladmandic/face-api@1.7.12/model/';
  const MATCH_THRESHOLD = 0.45; // càng nhỏ càng khắt khe (face-api khuyến nghị ~0.6, ở đây siết chặt hơn)
  const REQUIRED_MATCHES = 3;   // số khung hình khớp liên tiếp để cho qua
  let loaded = false;
  let stream = null;

  async function loadModels() {
    if (loaded) return;
    if (typeof faceapi === 'undefined') throw new Error('Không tải được thư viện face-api (kiểm tra kết nối mạng).');
    await Promise.all([
      faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL),
      faceapi.nets.faceLandmark68TinyNet.loadFromUri(MODEL_URL),
      faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL),
    ]);
    loaded = true;
  }

  async function startCamera(videoEl) {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      throw new Error('Trình duyệt không hỗ trợ camera. Hãy chạy qua http://localhost hoặc HTTPS.');
    }
    stream = await navigator.mediaDevices.getUserMedia({
      video: { width: { ideal: 480 }, height: { ideal: 480 }, facingMode: 'user' },
      audio: false,
    });
    videoEl.srcObject = stream;
    await new Promise((res) => { videoEl.onloadedmetadata = () => { videoEl.play(); res(); }; });
  }

  function stopCamera(videoEl) {
    if (stream) { stream.getTracks().forEach((t) => t.stop()); stream = null; }
    if (videoEl) videoEl.srcObject = null;
  }

  const opts = () => new faceapi.TinyFaceDetectorOptions({ inputSize: 320, scoreThreshold: 0.55 });

  /** Phát hiện đúng 1 khuôn mặt & trả về descriptor (Float32Array 128) hoặc null */
  async function detect(videoEl) {
    const all = await faceapi.detectAllFaces(videoEl, opts()).withFaceLandmarks(true).withFaceDescriptors();
    if (all.length !== 1) return { count: all.length, descriptor: null };
    return { count: 1, descriptor: all[0].descriptor };
  }

  /** Đăng ký: thu thập n mẫu rồi lấy trung bình */
  async function enroll(videoEl, samples = 6, onProgress = () => {}) {
    const collected = [];
    let guard = 0;
    while (collected.length < samples && guard++ < samples * 12) {
      const r = await detect(videoEl);
      if (r.descriptor) {
        collected.push(Array.from(r.descriptor));
        onProgress(collected.length / samples);
      } else {
        onProgress(collected.length / samples, r.count);
      }
      await new Promise((res) => setTimeout(res, 250));
    }
    if (collected.length < samples) throw new Error('Không thu đủ mẫu khuôn mặt. Hãy thử nơi đủ sáng và chỉ có 1 người trong khung hình.');
    const avg = new Array(128).fill(0);
    collected.forEach((d) => d.forEach((v, i) => { avg[i] += v / collected.length; }));
    return avg;
  }

  /** Xác thực: cần REQUIRED_MATCHES khung khớp liên tiếp trong thời gian timeoutMs */
  async function verify(videoEl, template, { timeoutMs = 25000, onTick = () => {}, signal } = {}) {
    const ref = Float32Array.from(template);
    const t0 = Date.now();
    let streak = 0;
    let best = Infinity;
    while (Date.now() - t0 < timeoutMs) {
      if (signal && signal.aborted) throw new Error('Đã hủy');
      const r = await detect(videoEl);
      if (!r.descriptor) {
        streak = 0;
        onTick({ state: r.count === 0 ? 'noface' : 'multi', streak });
      } else {
        const dist = faceapi.euclideanDistance(ref, r.descriptor);
        best = Math.min(best, dist);
        if (dist < MATCH_THRESHOLD) {
          streak++;
          onTick({ state: 'match', streak, dist });
          if (streak >= REQUIRED_MATCHES) return { ok: true, dist };
        } else {
          streak = 0;
          onTick({ state: 'mismatch', streak, dist });
        }
      }
      await new Promise((res) => setTimeout(res, 300));
    }
    return { ok: false, dist: best };
  }

  return { loadModels, startCamera, stopCamera, enroll, verify, MATCH_THRESHOLD, REQUIRED_MATCHES };
})();
