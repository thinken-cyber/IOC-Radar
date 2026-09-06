import http from 'node:http';
import * as vt from '../lib/providers/virustotal.js';
import * as abuseipdb from '../lib/providers/abuseipdb.js';
import * as urlscan from '../lib/providers/urlscan.js';
import { aggregateVerdict } from '../lib/aggregate.js';
import { detectIOC, isHash } from '../lib/detect.js';

const PORT = Number(process.env.PORT || 8787);
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const RATE_LIMIT_PER_MINUTE = Number(process.env.RATE_LIMIT_PER_MINUTE || 30);
const rateBuckets = new Map();

const PROVIDERS_BY_GROUP = {
  hash: ['virustotal'],
  domain: ['virustotal', 'urlscan'],
  ip: ['virustotal', 'abuseipdb', 'urlscan'],
  url: ['virustotal', 'urlscan']
};

const API_KEYS = {
  virustotal: process.env.VIRUSTOTAL_API_KEY,
  abuseipdb: process.env.ABUSEIPDB_API_KEY,
  urlscan: process.env.URLSCAN_API_KEY
};

function groupOf(type) {
  return isHash(type) ? 'hash' : type;
}

function providerCall(providerId, group, apiKey, value) {
  if (providerId === 'virustotal') {
    if (group === 'hash') return vt.lookupHash(apiKey, value);
    if (group === 'domain') return vt.lookupDomain(apiKey, value);
    if (group === 'ip') return vt.lookupIP(apiKey, value);
    if (group === 'url') return vt.lookupURL(apiKey, value);
  }
  if (providerId === 'abuseipdb') return abuseipdb.lookupIP(apiKey, value);
  if (providerId === 'urlscan') {
    if (group === 'domain') return urlscan.lookupDomain(apiKey, value);
    if (group === 'ip') return urlscan.lookupIP(apiKey, value);
    if (group === 'url') return urlscan.lookupURL(apiKey, value);
  }
  throw new Error('Provider không được hỗ trợ cho loại IOC này.');
}

function responseHeaders(contentType = 'application/json; charset=utf-8') {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Content-Type': contentType,
    'Cache-Control': 'no-store'
  };
}

function sendJson(res, status, body) {
  res.writeHead(status, responseHeaders());
  res.end(JSON.stringify(body));
}

function clientId(req) {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
}

function isRateLimited(req) {
  const now = Date.now();
  const id = clientId(req);
  const bucket = rateBuckets.get(id) || { startedAt: now, count: 0 };
  if (now - bucket.startedAt >= 60_000) {
    bucket.startedAt = now;
    bucket.count = 0;
  }
  bucket.count += 1;
  rateBuckets.set(id, bucket);
  return bucket.count > RATE_LIMIT_PER_MINUTE;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 8 * 1024) reject(new Error('Request quá lớn.'));
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(body || '{}'));
      } catch (_) {
        reject(new Error('Request JSON không hợp lệ.'));
      }
    });
    req.on('error', reject);
  });
}

async function scan(req, res) {
  if (isRateLimited(req)) {
    sendJson(res, 429, { error: 'Bạn đã vượt giới hạn lượt quét. Thử lại sau một phút.' });
    return;
  }

  let body;
  try {
    body = await readBody(req);
  } catch (error) {
    sendJson(res, 400, { error: error.message });
    return;
  }

  const detected = detectIOC(body.value);
  if (!detected.type || (body.type && body.type !== detected.type)) {
    sendJson(res, 400, { error: 'IOC không hợp lệ hoặc không khớp loại dữ liệu.' });
    return;
  }

  const group = groupOf(detected.type);
  const needed = PROVIDERS_BY_GROUP[group];
  const outcomes = {};

  await Promise.all(needed.map(async (providerId) => {
    const apiKey = API_KEYS[providerId];
    if (!apiKey) {
      outcomes[providerId] = { error: 'Provider chưa được cấu hình trên server.' };
      return;
    }
    try {
      outcomes[providerId] = { data: await providerCall(providerId, group, apiKey, detected.value) };
    } catch (error) {
      outcomes[providerId] = { error: error.message || 'Provider request thất bại.' };
    }
  }));

  const { verdict, score } = aggregateVerdict({
    vt: outcomes.virustotal?.data,
    abuseipdb: outcomes.abuseipdb?.data,
    urlscan: outcomes.urlscan?.data
  });

  sendJson(res, 200, {
    type: detected.type,
    value: detected.value,
    needed,
    outcomes,
    verdict,
    score
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, responseHeaders());
    res.end();
    return;
  }
  if (req.method === 'GET' && req.url === '/health') {
    sendJson(res, 200, { ok: true });
    return;
  }
  if (req.method === 'GET' && req.url === '/') {
    sendJson(res, 200, {
      name: 'IOC Radar API',
      status: 'ok',
      endpoints: {
        health: 'GET /health',
        scan: 'POST /scan'
      }
    });
    return;
  }
  if (req.method === 'POST' && req.url === '/scan') {
    await scan(req, res);
    return;
  }
  sendJson(res, 404, { error: 'Endpoint không tồn tại.' });
});

server.listen(PORT, () => {
  console.log(`IOC Radar backend listening on http://localhost:${PORT}`);
});
