# IOC Radar – Threat Intel Lookup

Extension Chrome nhẹ để tra cứu nhanh **Hash (MD5/SHA1/SHA256), Domain, URL, IP**
qua VirusTotal, AbuseIPDB và urlscan.io — gộp lại thành **một đánh giá rủi ro
duy nhất** thay vì phải mở nhiều tab.

- Không có trang nền (background page) chạy liên tục — chỉ có Service Worker
  (Manifest V3), Chrome tự đánh thức khi cần và tắt khi rảnh.
- Không dùng framework (React, jQuery...) — thuần HTML/CSS/JS (ES modules).
- Không tải font hay thư viện ngoài — dùng font hệ thống sẵn có.
- Kết quả tra cứu được **cache** trong `chrome.storage.local` (hash: 6 giờ,
  domain/URL/IP: 30 phút) để tránh gọi lại API không cần thiết.



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

