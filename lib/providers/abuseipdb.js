// lib/providers/abuseipdb.js
const BASE = 'https://api.abuseipdb.com/api/v2';

export async function lookupIP(apiKey, ip) {
  const res = await fetch(
    `${BASE}/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
    { headers: { Key: apiKey, Accept: 'application/json' } }
  );
  if (res.status === 401 || res.status === 403) throw new Error('API key không hợp lệ.');
  if (res.status === 429) throw new Error('Đã vượt giới hạn request. Thử lại sau.');
  if (!res.ok) throw new Error(`Lỗi ${res.status}.`);
  const json = await res.json();
  const d = json.data;
  return {
    found: true,
    abuseScore: d.abuseConfidenceScore,
    totalReports: d.totalReports,
    lastReportedAt: d.lastReportedAt,
    countryCode: d.countryCode,
    isp: d.isp,
    usageType: d.usageType,
    domain: d.domain,
    isTor: d.isTor,
    link: `https://www.abuseipdb.com/check/${ip}`
  };
}

export async function validateKey(apiKey) {
  try {
    const r = await lookupIP(apiKey, '8.8.8.8');
    return r.found ? { ok: true, message: 'Key hợp lệ.' } : { ok: false, message: 'Phản hồi bất thường.' };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}
