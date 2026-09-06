// lib/providers/urlscan.js
const BASE = 'https://urlscan.io/api/v1';

async function search(apiKey, query) {
  const res = await fetch(`${BASE}/search/?q=${encodeURIComponent(query)}&size=1`, {
    headers: apiKey ? { 'API-Key': apiKey } : {}
  });
  if (res.status === 401) throw new Error('API key không hợp lệ.');
  if (res.status === 429) throw new Error('Đã vượt giới hạn request. Thử lại sau.');
  if (!res.ok) throw new Error(`Lỗi ${res.status}.`);
  const json = await res.json();
  const top = json.results && json.results[0];
  if (!top) return { found: false };
  return {
    found: true,
    scanDate: top.task?.time || null,
    reportLink: top.result || null,
    screenshot: top.screenshot || null,
    verdictMalicious: top.verdicts?.overall?.malicious ?? null,
    score: top.verdicts?.overall?.score ?? null,
    ip: top.page?.ip || null,
    server: top.page?.server || null,
    country: top.page?.country || null
  };
}

export async function lookupDomain(apiKey, domain) {
  return search(apiKey, `domain:${domain}`);
}

export async function lookupURL(apiKey, url) {
  return search(apiKey, `page.url:"${url}"`);
}

export async function lookupIP(apiKey, ip) {
  return search(apiKey, `ip:${ip}`);
}

export async function validateKey(apiKey) {
  try {
    await search(apiKey, 'domain:example.com');
    return { ok: true, message: 'Key hợp lệ.' };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}
