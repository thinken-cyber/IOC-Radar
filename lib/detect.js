// lib/detect.js
// Nhận diện loại IOC (Indicator of Compromise) từ chuỗi người dùng nhập.
// Thứ tự kiểm tra: hash (độ dài hex cố định) -> IP -> URL -> domain.

const HEX32 = /^[a-fA-F0-9]{32}$/; // MD5
const HEX40 = /^[a-fA-F0-9]{40}$/; // SHA1
const HEX64 = /^[a-fA-F0-9]{64}$/; // SHA256

const IPV4 =
  /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;

// Regex IPv6 rút gọn nhưng đủ dùng cho phần lớn trường hợp thực tế
// (bao gồm dạng nén "::" và dạng đầy đủ 8 nhóm).
const IPV6 =
  /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$|^:((:[0-9a-fA-F]{1,4}){1,7})$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$|^::$/;

const DOMAIN =
  /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

const HAS_SCHEME = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//;

export const IOC_TYPES = {
  HASH_MD5: 'hash_md5',
  HASH_SHA1: 'hash_sha1',
  HASH_SHA256: 'hash_sha256',
  DOMAIN: 'domain',
  IP: 'ip',
  URL: 'url'
};

const TYPE_LABELS_VI = {
  [IOC_TYPES.HASH_MD5]: 'MD5',
  [IOC_TYPES.HASH_SHA1]: 'SHA1',
  [IOC_TYPES.HASH_SHA256]: 'SHA256',
  [IOC_TYPES.DOMAIN]: 'Domain',
  [IOC_TYPES.IP]: 'IP',
  [IOC_TYPES.URL]: 'URL'
};

export function isHash(type) {
  return (
    type === IOC_TYPES.HASH_MD5 ||
    type === IOC_TYPES.HASH_SHA1 ||
    type === IOC_TYPES.HASH_SHA256
  );
}

export function typeLabel(type) {
  return TYPE_LABELS_VI[type] || 'Không xác định';
}

export function detectIOC(raw) {
  const value = (raw || '').trim();
  if (!value) return { type: null, value: '' };

  // URL: có scheme rõ ràng (http://, https://, ftp://...)
  if (HAS_SCHEME.test(value)) {
    try {
      // eslint-disable-next-line no-new
      new URL(value);
      return { type: IOC_TYPES.URL, value };
    } catch (_) {
      /* rơi xuống các kiểm tra khác */
    }
  }

  if (HEX32.test(value)) return { type: IOC_TYPES.HASH_MD5, value: value.toLowerCase() };
  if (HEX40.test(value)) return { type: IOC_TYPES.HASH_SHA1, value: value.toLowerCase() };
  if (HEX64.test(value)) return { type: IOC_TYPES.HASH_SHA256, value: value.toLowerCase() };

  if (IPV4.test(value)) return { type: IOC_TYPES.IP, value };
  if (value.includes(':') && IPV6.test(value)) return { type: IOC_TYPES.IP, value };

  // URL không có scheme nhưng có path phía sau domain, vd: example.com/a/b
  if (!value.includes(' ') && /^[^/]+\.[a-zA-Z]{2,}\/.+/.test(value)) {
    try {
      const withScheme = `http://${value}`;
      // eslint-disable-next-line no-new
      new URL(withScheme);
      return { type: IOC_TYPES.URL, value: withScheme };
    } catch (_) {
      /* rơi xuống domain check */
    }
  }

  if (DOMAIN.test(value)) return { type: IOC_TYPES.DOMAIN, value: value.toLowerCase() };

  return { type: null, value };
}
