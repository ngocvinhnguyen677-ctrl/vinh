# SecureVault – Password Manager (Zero-Knowledge, Client-side AES-256)

Đồ án tốt nghiệp ngành An toàn thông tin. Toàn bộ mã hóa và nhận diện khuôn mặt chạy **trên trình duyệt**.

## Cấu trúc

```
password-vault/
├── index.html        # Giao diện phụ: Mật khẩu chủ + Nhận diện khuôn mặt (cổng vào)
├── vault.html        # Giao diện chính: Kho mật khẩu
├── css/style.css     # Giao diện (Bootstrap 5 + theme tối tùy biến)
└── js/
    ├── crypto.js     # PBKDF2, AES-256-CBC, HMAC-SHA256 (CryptoJS + Web Crypto API)
    ├── face.js       # Nhận diện khuôn mặt (face-api.js)
    ├── auth.js       # Luồng xác thực 2 lớp
    ├── utils.js      # Toast, đo độ mạnh, sinh mật khẩu, tiện ích
    └── vault.js      # Logic kho mật khẩu
```

## Cách chạy

Camera và Web Crypto yêu cầu `localhost` hoặc HTTPS, nên **không nên** mở file bằng cách nhấp đúp. Chạy một server tĩnh trong thư mục dự án:

```bash
# Cách 1: Python
python -m http.server 8000

# Cách 2: Node
npx serve .
```

Rồi mở **http://localhost:8000** (Chrome / Edge / Firefox). Hoặc dùng extension *Live Server* của VS Code.

> Cần Internet lần đầu để tải Bootstrap, CryptoJS, face-api và mô hình nhận diện từ CDN.

## Luồng sử dụng

1. **Lần đầu**: đặt Mật khẩu chủ (≥10 ký tự, mức "Mạnh" trở lên) → đăng ký khuôn mặt (6 mẫu) → vào Vault.
2. **Các lần sau**: nhập Mật khẩu chủ → quét khuôn mặt → vào Vault.
3. Trong Vault: thêm tài khoản, sinh mật khẩu, tìm kiếm, sao chép, xem chuỗi mã hóa, xóa.
4. Kho tự khóa sau 5 phút không hoạt động hoặc khi bấm "Khóa kho".

## Thiết kế bảo mật (dùng khi trình bày với hội đồng)

| Thành phần | Chi tiết |
|---|---|
| Dẫn xuất khóa | PBKDF2-HMAC-SHA256, 310.000 vòng, salt ngẫu nhiên 128-bit → 768 bit chia thành `encKey`, `macKey`, `authKey` |
| Mã hóa | AES-256-CBC, IV 128-bit ngẫu nhiên cho mỗi lần mã hóa (cùng mật khẩu → bản mã khác nhau) |
| Toàn vẹn | Encrypt-then-MAC: HMAC-SHA256 trên `IV ‖ ciphertext`, kiểm tra trước khi giải mã |
| Xác minh mật khẩu chủ | Chỉ lưu `SHA-256(authKey)`; **không lưu mật khẩu chủ**, `authKey` tách biệt với khóa mã hóa |
| Định dạng lưu | `ivHex:cipherBase64:hmacHex` |
| Khuôn mặt | Vector đặc trưng 128 chiều, **được mã hóa AES-256** bằng khóa từ mật khẩu chủ trước khi lưu; ngưỡng khớp 0.45, cần 3 khung liên tiếp |
| Phiên | Khóa chỉ nằm trong `sessionStorage` (mất khi đóng tab); chống brute-force ở form đăng nhập (khóa 30 giây sau 5 lần sai) |
| Clipboard | Tự xóa sau 30 giây khi sao chép mật khẩu |
| Chống XSS | Dữ liệu người dùng được escape / gán bằng `textContent` |

"Server" được mô phỏng bằng `localStorage`; khung **Mô phỏng Server** trong Vault hiển thị đúng payload mà server thật sẽ nhận (chỉ có bản mã).

## Hạn chế cần nêu trung thực trong báo cáo

- **Nhận diện khuôn mặt chưa có chống giả mạo (liveness detection)**: ảnh/video của chủ sở hữu có thể qua mặt được. Mật khẩu chủ vẫn là lớp bảo vệ chính; khuôn mặt là lớp bổ sung.
- Tên ứng dụng và tên tài khoản được lưu dạng rõ để phục vụ tìm kiếm; chỉ **mật khẩu** được mã hóa.
- Quên Mật khẩu chủ = mất dữ liệu (đây là bản chất của Zero-Knowledge).
- Vì là mô phỏng chạy thuần client, kẻ có quyền chỉnh sửa JavaScript trên máy bị nhiễm mã độc vẫn có thể đánh cắp dữ liệu; một hệ thống thật cần thêm backend, HTTPS, CSP và kiểm thử bảo mật.

## Hướng phát triển

Backend thật (Node/Express + DB) thay `localStorage`, WebAuthn/Passkey, liveness detection, 2FA TOTP, đồng bộ đa thiết bị, nhập/xuất kho đã mã hóa.
