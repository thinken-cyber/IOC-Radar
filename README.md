# IOC Radar – Threat Intel Lookup

Extension Chrome nhẹ để tra cứu nhanh **Hash (MD5/SHA1/SHA256), Domain, URL, IP**
qua VirusTotal, AbuseIPDB và urlscan.io — gộp lại thành **một đánh giá rủi ro
duy nhất** thay vì phải mở nhiều tab.

## Vì sao "nhẹ"

- Không có trang nền (background page) chạy liên tục — chỉ có Service Worker
  (Manifest V3), Chrome tự đánh thức khi cần và tắt khi rảnh.
- Không dùng framework (React, jQuery...) — thuần HTML/CSS/JS (ES modules).
- Không tải font hay thư viện ngoài — dùng font hệ thống sẵn có.
- Kết quả tra cứu được **cache** trong `chrome.storage.local` (hash: 6 giờ,
  domain/URL/IP: 30 phút) để tránh gọi lại API không cần thiết.

## 1. Cài đặt vào Chrome

1. Giải nén file zip ra một thư mục bất kỳ.
2. Mở Chrome, vào `chrome://extensions`.
3. Bật **Developer mode** (góc trên bên phải).
4. Bấm **Load unpacked** (Tải tiện ích đã giải nén) → chọn thư mục vừa giải nén
   (thư mục chứa file `manifest.json`).
5. Icon "IOC Radar" sẽ xuất hiện trên thanh công cụ Chrome.

## 2. Cấu hình backend

Extension không chứa API key. Backend giữ các key trong environment variables và
gọi VirusTotal, AbuseIPDB, và urlscan.io thay cho extension.

Chạy backend local:

```powershell
$env:VIRUSTOTAL_API_KEY = 'server-only-key'
$env:ABUSEIPDB_API_KEY = 'server-only-key'
$env:URLSCAN_API_KEY = 'server-only-key'
$env:PORT = '8787'
node .\server\index.js
```

| Dịch vụ | Đăng ký | Lấy key ở đâu sau khi đăng ký | Giới hạn free-tier (tham khảo) |
|---|---|---|---|
| VirusTotal | https://www.virustotal.com/gui/join-us | Vào **Profile → API Key** | ~4 req/phút, 500 req/ngày |
| AbuseIPDB | https://www.abuseipdb.com/register | Vào **Account → API** | 1.000 req/ngày |
| urlscan.io | https://urlscan.io/user/signup | Vào **Profile → API Key** | 100 lượt tìm kiếm/ngày |

> Không đưa key thật vào Git hoặc file ZIP extension. Xem thêm
> `server/.env.example` và `server/README.md`.

## 3. Cách dùng

- Bấm icon extension → dán hash/domain/URL/IP vào ô nhập → extension tự nhận
  diện loại IOC (hiển thị badge) → bấm **Quét** (hoặc Enter).
- Kết quả hiển thị:
  - **Banner đánh giá tổng quan**: Sạch / Nghi ngờ / Độc hại / Chưa đủ dữ liệu,
    kèm điểm rủi ro 0–100 (gộp từ mọi nguồn có dữ liệu).
  - **Từng nguồn** (VirusTotal, AbuseIPDB, urlscan.io) dưới dạng card có thể
    thu/mở, kèm link xem báo cáo đầy đủ trên trang gốc.
  - Nút **Sao chép JSON** để lấy dữ liệu thô, tiện dán vào ticket/báo cáo.
- **Mẹo nhanh**: bôi đen một chuỗi (hash/IP/domain/URL) trên bất kỳ trang web
  nào → chuột phải → **"Quét ... bằng IOC Radar"** → popup tự mở và quét luôn.
- Các lượt tra gần đây hiện thành chip bên dưới ô nhập, bấm vào để quét lại
  nhanh (sẽ dùng cache nếu còn hạn).

## 4. Loại IOC nào dùng nguồn nào

| Loại IOC | VirusTotal | AbuseIPDB | urlscan.io |
|---|---|---|---|
| Hash (MD5/SHA1/SHA256) | ✅ | – | – |
| Domain | ✅ | – | ✅ |
| IP | ✅ | ✅ | ✅ |
| URL | ✅ | – | ✅ |

Với URL chưa từng được quét trên VirusTotal, extension sẽ tự gửi URL đó để
phân tích và báo bạn quay lại tra sau ít phút (VirusTotal cần thời gian xử lý).

## 5. Bảo mật & dữ liệu

- API key chỉ lưu ở backend environment variables, không nằm trong extension.
- Extension chỉ gửi IOC tới backend qua endpoint `/scan`.
- Backend có rate limit cơ bản và endpoint `/health` để kiểm tra hoạt động.

## 6. Cấu trúc thư mục

```
ioc-radar/
├── manifest.json
├── background.js          # Service worker: context menu quét nhanh
├── popup.html / css/popup.css / js/popup.js
├── server/
│   ├── index.js            # Backend giữ key và gọi các provider
│   ├── .env.example        # Tên biến môi trường, không chứa key thật
│   └── README.md
├── lib/
│   ├── detect.js           # Nhận diện loại IOC
│   ├── cache.js             # Cache kết quả (TTL)
│   ├── aggregate.js         # Gộp thành 1 điểm rủi ro
│   └── providers/
│       ├── virustotal.js
│       ├── abuseipdb.js
│       └── urlscan.js
└── icons/
```

## 7. Giới hạn hiện tại (có thể mở rộng sau)

- Tra cứu từng IOC một (chưa hỗ trợ bulk/nhiều dòng cùng lúc).
- Chưa hỗ trợ thêm nguồn khác (Shodan, OTX AlienVault, MISP nội bộ...) — kiến
  trúc `lib/providers/` được thiết kế để dễ thêm provider mới nếu cần.
- urlscan.io ở chế độ tìm kết quả đã có sẵn (nhanh, không tốn hạn mức); chưa
  làm tính năng "quét trực tiếp" (submit scan) vì thao tác đó mất 10–20 giây
  và tốn hạn mức nhanh hơn.
