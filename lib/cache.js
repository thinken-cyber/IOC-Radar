// lib/cache.js
// Cache kết quả tra cứu trong chrome.storage.local để:
//  1) Phản hồi tức thì cho IOC đã tra trước đó.
//  2) Tránh tốn quota của các API free-tier (VT: 4 req/phút, v.v).
// Cache tự hết hạn theo TTL riêng cho từng loại IOC.

const PREFIX = 'ioc_cache_';

const TTL_MS = {
  hash: 6 * 60 * 60 * 1000, // 6 giờ – hash gần như không đổi kết quả theo thời gian
  domain: 30 * 60 * 1000, // 30 phút
  ip: 30 * 60 * 1000, // 30 phút
  url: 30 * 60 * 1000 // 30 phút
};

function ttlBucket(type) {
  return type && type.startsWith('hash') ? 'hash' : type;
}

function keyOf(provider, type, value) {
  return `${PREFIX}${provider}_${type}_${value}`;
}

export async function getCached(provider, type, value) {
  const k = keyOf(provider, type, value);
  const res = await chrome.storage.local.get(k);
  const entry = res[k];
  if (!entry) return null;
  const ttl = TTL_MS[ttlBucket(type)] ?? TTL_MS.domain;
  if (Date.now() - entry.ts > ttl) return null;
  return { data: entry.data, cachedAt: entry.ts };
}

export async function setCached(provider, type, value, data) {
  const k = keyOf(provider, type, value);
  await chrome.storage.local.set({ [k]: { ts: Date.now(), data } });
}

// Dọn các entry cache đã hết hạn từ lâu để storage không phình to theo thời gian.
export async function pruneCache() {
  const all = await chrome.storage.local.get(null);
  const maxTtl = Math.max(...Object.values(TTL_MS));
  const now = Date.now();
  const toRemove = Object.keys(all).filter((k) => {
    if (!k.startsWith(PREFIX)) return false;
    const entry = all[k];
    return !entry || now - entry.ts > maxTtl;
  });
  if (toRemove.length) await chrome.storage.local.remove(toRemove);
}
