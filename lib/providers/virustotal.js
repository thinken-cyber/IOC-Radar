// lib/providers/virustotal.js
const BASE = 'https://www.virustotal.com/api/v3';

function b64urlNoPad(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function vtFetch(path, apiKey, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: { 'x-apikey': apiKey, ...(options.headers || {}) }
  });
  if (res.status === 401) throw new Error('API key không hợp lệ.');
  if (res.status === 429) throw new Error('Đã vượt giới hạn request (rate limit). Thử lại sau ít phút.');
  return res;
}

function summarize(attrs) {
  const stats = attrs.last_analysis_stats || {};
  const total = Object.values(stats).reduce((a, b) => a + b, 0) || 0;
  return {
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    total,
    reputation: attrs.reputation ?? null,
    tags: attrs.tags || [],
    lastAnalysisDate: attrs.last_analysis_date ? attrs.last_analysis_date * 1000 : null
  };
}

export async function lookupHash(apiKey, hash) {
  const res = await vtFetch(`/files/${hash}`, apiKey);
  if (res.status === 404) return { found: false };
  if (!res.ok) throw new Error(`Lỗi ${res.status} khi tra file.`);
  const json = await res.json();
  const a = json.data.attributes;
  return {
    found: true,
    ...summarize(a),
    fileNames: (a.names || []).slice(0, 5),
    fileType: a.type_description || a.type_tag || null,
    size: a.size || null,
    link: `https://www.virustotal.com/gui/file/${json.data.id}`
  };
}

export async function lookupDomain(apiKey, domain) {
  const res = await vtFetch(`/domains/${domain}`, apiKey);
  if (res.status === 404) return { found: false };
  if (!res.ok) throw new Error(`Lỗi ${res.status} khi tra domain.`);
  const json = await res.json();
  const a = json.data.attributes;
  return {
    found: true,
    ...summarize(a),
    categories: a.categories ? Object.values(a.categories).slice(0, 5) : [],
    creationDate: a.creation_date ? a.creation_date * 1000 : null,
    registrar: a.registrar || null,
    link: `https://www.virustotal.com/gui/domain/${domain}`
  };
}

export async function lookupIP(apiKey, ip) {
  const res = await vtFetch(`/ip_addresses/${ip}`, apiKey);
  if (res.status === 404) return { found: false };
  if (!res.ok) throw new Error(`Lỗi ${res.status} khi tra IP.`);
  const json = await res.json();
  const a = json.data.attributes;
  return {
    found: true,
    ...summarize(a),
    asOwner: a.as_owner || null,
    asn: a.asn || null,
    country: a.country || null,
    network: a.network || null,
    link: `https://www.virustotal.com/gui/ip-address/${ip}`
  };
}

export async function lookupURL(apiKey, url) {
  const id = b64urlNoPad(url);
  const res = await vtFetch(`/urls/${id}`, apiKey);

  if (res.status === 404) {
    // Chưa có báo cáo sẵn có -> gửi để phân tích (kết quả sẽ có sau ít phút).
    const submit = await vtFetch('/urls', apiKey, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `url=${encodeURIComponent(url)}`
    });
    if (!submit.ok) throw new Error(`Lỗi ${submit.status} khi gửi URL để quét.`);
    return { found: false, submitted: true, link: `https://www.virustotal.com/gui/url/${id}` };
  }
  if (!res.ok) throw new Error(`Lỗi ${res.status} khi tra URL.`);
  const json = await res.json();
  const a = json.data.attributes;
  return {
    found: true,
    ...summarize(a),
    title: a.title || null,
    finalUrl: a.last_final_url || url,
    link: `https://www.virustotal.com/gui/url/${id}`
  };
}

// Gọi thử một endpoint rẻ để xác thực API key ở trang Options.
export async function validateKey(apiKey) {
  const res = await fetch(`${BASE}/ip_addresses/8.8.8.8`, {
    headers: { 'x-apikey': apiKey }
  });
  if (res.status === 401) return { ok: false, message: 'API key không hợp lệ.' };
  if (res.status === 429) return { ok: true, message: 'Key hợp lệ (đang bị rate limit tạm thời).' };
  if (!res.ok) return { ok: false, message: `Phản hồi bất thường (HTTP ${res.status}).` };
  return { ok: true, message: 'Key hợp lệ.' };
}
