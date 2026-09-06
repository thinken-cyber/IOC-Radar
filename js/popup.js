import { detectIOC, isHash, typeLabel, IOC_TYPES } from '../lib/detect.js';
import { pruneCache } from '../lib/cache.js';
import { VERDICT_LABEL_VI } from '../lib/aggregate.js';

const $ = (sel) => document.querySelector(sel);

const iocInput = $('#iocInput');
const typeBadge = $('#typeBadge');
const scanBtn = $('#scanBtn');
const statusEl = $('#status');
const resultsEl = $('#results');
const recentWrap = $('#recent');
const recentChips = $('#recentChips');
const BACKEND_URL = 'https://ioc-radar.onrender.com';

const RECENT_KEY = 'recentLookups';
const MAX_RECENT = 8;

const PROVIDER_META = {
  virustotal: { label: 'VirusTotal', key: 'virustotal' },
  abuseipdb: { label: 'AbuseIPDB', key: 'abuseipdb' },
  urlscan: { label: 'urlscan.io', key: 'urlscan' }
};

/* ---------------- Icons ---------------- */
const ICONS = {
  clean:
    '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2 4 5v6c0 5 3.4 8.7 8 9 4.6-.3 8-4 8-9V5l-8-3Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="m8.5 12 2.3 2.3L15.8 9" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  suspicious:
    '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2 4 5v6c0 5 3.4 8.7 8 9 4.6-.3 8-4 8-9V5l-8-3Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 8v4.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="15.3" r="0.9" fill="currentColor"/></svg>',
  malicious:
    '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2 4 5v6c0 5 3.4 8.7 8 9 4.6-.3 8-4 8-9V5l-8-3Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="m9.5 9.5 5 5m0-5-5 5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
  unknown:
    '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2 4 5v6c0 5 3.4 8.7 8 9 4.6-.3 8-4 8-9V5l-8-3Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M10.3 9.6a1.8 1.8 0 1 1 2.7 1.6c-.7.4-1 .8-1 1.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><circle cx="12" cy="15.3" r="0.9" fill="currentColor"/></svg>',
  chevron: '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="m6 9 6 6 6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
};

/* ---------------- Init ---------------- */
init();

async function init() {
  if (!chrome?.storage?.local) {
    iocInput.focus();
    return;
  }

  pruneCache().catch(() => {});
  await loadRecent();

  if (chrome?.storage?.session) {
    const session = await chrome.storage.session.get('pendingIOC');
    if (session.pendingIOC) {
      await chrome.storage.session.remove('pendingIOC');
      iocInput.value = session.pendingIOC;
      handleInput();
      runScan();
      return;
    }
  }

  iocInput.focus();
}

iocInput.addEventListener('input', handleInput);
iocInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !scanBtn.disabled) runScan();
});
scanBtn.addEventListener('click', runScan);

function handleInput() {
  const { type, value } = detectIOC(iocInput.value);
  if (type) {
    typeBadge.textContent = typeLabel(type);
    typeBadge.hidden = false;
    scanBtn.disabled = false;
  } else {
    typeBadge.hidden = true;
    scanBtn.disabled = true;
  }
}

/* ---------------- Scan orchestration ---------------- */
async function runScan() {
  const { type, value } = detectIOC(iocInput.value);
  if (!type) {
    showStatus('Không nhận diện được định dạng. Hãy nhập hash (MD5/SHA1/SHA256), domain, URL hoặc IP.', true);
    return;
  }

  resultsEl.hidden = true;
  resultsEl.innerHTML = '';
  scanBtn.disabled = true;
  showStatus(`Đang tra cứu ${typeLabel(type).toLowerCase()}…`, false, true);

  try {
    const response = await fetch(`${BACKEND_URL}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, value })
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || `Backend lỗi HTTP ${response.status}.`);

    renderResults(payload);
    await pushRecent({ type, value, verdict: payload.verdict });
  } catch (err) {
    showStatus(err.message || 'Không thể kết nối backend.', true);
  } finally {
    scanBtn.disabled = false;
  }
}

/* ---------------- Status ---------------- */
function showStatus(text, isError = false, loading = false) {
  statusEl.hidden = false;
  statusEl.classList.toggle('error', isError);
  statusEl.innerHTML = loading ? `<span class="spinner"></span><span>${escapeHtml(text)}</span>` : escapeHtml(text);
}
function hideStatus() {
  statusEl.hidden = true;
}

/* ---------------- Rendering ---------------- */
function renderResults({ type, value, needed, outcomes, verdict, score }) {
  hideStatus();
  resultsEl.hidden = false;
  resultsEl.innerHTML = '';

  resultsEl.appendChild(buildVerdictBanner({ type, value, verdict, score }));

  for (const providerId of needed) {
    resultsEl.appendChild(buildProviderCard(providerId, type, outcomes[providerId]));
  }

  const actions = document.createElement('div');
  actions.className = 'results-actions';
  const copyBtn = document.createElement('button');
  copyBtn.className = 'ghost-btn';
  copyBtn.textContent = 'Sao chép JSON';
  copyBtn.addEventListener('click', () => copyJSON({ type, value, verdict, score, outcomes }, copyBtn));
  actions.appendChild(copyBtn);
  resultsEl.appendChild(actions);
}

function buildVerdictBanner({ type, value, verdict, score }) {
  const div = document.createElement('div');
  div.className = `verdict-banner ${verdict}`;
  const scoreText = score === null ? '—' : String(score);
  div.innerHTML = `
    <div class="verdict-icon">${ICONS[verdict]}</div>
    <div class="verdict-text">
      <div class="verdict-title">${escapeHtml(VERDICT_LABEL_VI[verdict])}</div>
      <div class="verdict-sub">${escapeHtml(typeLabel(type))} · ${escapeHtml(value)}</div>
    </div>
    <div class="verdict-score">${scoreText}<small>điểm rủi ro</small></div>
  `;
  return div;
}

function buildProviderCard(providerId, type, outcome) {
  const meta = PROVIDER_META[providerId];
  const card = document.createElement('div');
  card.className = 'provider-card';

  const head = document.createElement('div');
  head.className = 'provider-head';

  const pillClass = providerPillClass(providerId, outcome);
  const pillText = providerPillText(providerId, outcome);

  head.innerHTML = `
    <span class="provider-name">${escapeHtml(meta.label)} <span class="provider-pill ${pillClass}">${escapeHtml(pillText)}</span></span>
    <span class="chevron">${ICONS.chevron}</span>
  `;
  head.addEventListener('click', () => card.classList.toggle('open'));

  const body = document.createElement('div');
  body.className = 'provider-body';
  body.innerHTML = providerBodyHTML(providerId, type, outcome);

  card.appendChild(head);
  card.appendChild(body);
  return card;
}

function providerPillClass(providerId, outcome) {
  if (!outcome || outcome.skipped || outcome.error) return 'unknown';
  const d = outcome.data;
  if (!d || d.found === false) return 'unknown';
  if (providerId === 'virustotal') {
    if (d.malicious > 0) return 'malicious';
    if (d.suspicious > 0) return 'suspicious';
    return 'clean';
  }
  if (providerId === 'abuseipdb') {
    if (d.abuseScore >= 30) return 'malicious';
    if (d.abuseScore >= 5) return 'suspicious';
    return 'clean';
  }
  if (providerId === 'urlscan') {
    if (d.verdictMalicious) return 'malicious';
    return 'clean';
  }
  return 'unknown';
}

function providerPillText(providerId, outcome) {
  if (!outcome) return '—';
  if (outcome.skipped) return 'Chưa có key';
  if (outcome.error) return 'Lỗi';
  const d = outcome.data;
  if (!d || d.found === false) return d?.submitted ? 'Đã gửi quét' : 'Không có dữ liệu';
  if (providerId === 'virustotal') return `${d.malicious}/${d.total}`;
  if (providerId === 'abuseipdb') return `${d.abuseScore}%`;
  if (providerId === 'urlscan') return d.verdictMalicious ? 'Độc hại' : 'Sạch';
  return '—';
}

function providerBodyHTML(providerId, type, outcome) {
  if (!outcome || outcome.skipped) {
    return '<div class="provider-empty">Provider chưa sẵn sàng.</div>';
  }
  if (outcome.error) {
    return `<div class="provider-empty">${escapeHtml(outcome.error)}</div>`;
  }
  const d = outcome.data;
  if (!d || d.found === false) {
    if (d?.submitted) {
      return `<div class="provider-empty">Chưa có dữ liệu sẵn có — đã gửi URL để phân tích. Thử tra lại sau 1–2 phút.</div>${linkRow(d.link)}`;
    }
    return `<div class="provider-empty">Không tìm thấy dữ liệu cho mục này trên ${escapeHtml(PROVIDER_META[providerId].label)}.</div>`;
  }

  if (providerId === 'virustotal') return vtBodyHTML(type, d);
  if (providerId === 'abuseipdb') return abuseBodyHTML(d);
  if (providerId === 'urlscan') return urlscanBodyHTML(d);
  return '';
}

function vtBodyHTML(type, d) {
  const rows = [
    ['Phát hiện độc hại', `${d.malicious} / ${d.total}`],
    ['Nghi ngờ', String(d.suspicious)],
    ['Sạch', String(d.harmless)],
    ['Danh tiếng (reputation)', d.reputation ?? '—']
  ];
  if (isHash(type)) {
    rows.push(['Loại tệp', d.fileType || '—']);
    if (d.fileNames?.length) rows.push(['Tên tệp từng thấy', d.fileNames.join(', ')]);
  }
  if (type === IOC_TYPES.DOMAIN) {
    if (d.categories?.length) rows.push(['Danh mục', d.categories.join(', ')]);
    if (d.registrar) rows.push(['Registrar', d.registrar]);
  }
  if (type === IOC_TYPES.IP) {
    rows.push(['ASN', d.asn ? `AS${d.asn}` : '—']);
    rows.push(['Tổ chức', d.asOwner || '—']);
    rows.push(['Quốc gia', d.country || '—']);
  }
  if (type === IOC_TYPES.URL && d.title) rows.push(['Tiêu đề trang', d.title]);
  if (d.tags?.length) rows.push(['Tags', d.tags.slice(0, 6).join(', ')]);
  rows.push(['Cập nhật lần cuối', formatDate(d.lastAnalysisDate)]);

  return kvGrid(rows);
}

function abuseBodyHTML(d) {
  const rows = [
    ['Điểm nghi vấn (abuse score)', `${d.abuseScore}%`],
    ['Tổng số báo cáo', String(d.totalReports)],
    ['ISP', d.isp || '—'],
    ['Loại sử dụng', d.usageType || '—'],
    ['Quốc gia', d.countryCode || '—'],
    ['Là nút Tor?', d.isTor ? 'Có' : 'Không'],
    ['Báo cáo gần nhất', formatDate(d.lastReportedAt)]
  ];
  return kvGrid(rows);
}

function urlscanBodyHTML(d) {
  const rows = [
    ['Đánh giá tổng quan', d.verdictMalicious ? 'Độc hại' : 'Không phát hiện độc hại'],
    ['Điểm rủi ro urlscan', d.score ?? '—'],
    ['IP máy chủ', d.ip || '—'],
    ['Server', d.server || '—'],
    ['Quốc gia', d.country || '—'],
    ['Thời điểm quét', formatDate(d.scanDate)]
  ];
  let html = kvGrid(rows);
  if (d.screenshot) html += `<img class="screenshot" src="${d.screenshot}" alt="Ảnh chụp màn hình trang được quét" loading="lazy" />`;
  return html;
}

function kvGrid(rows) {
  const items = rows
    .map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(String(v))}</dd>`)
    .join('');
  return `<dl class="kv-grid">${items}</dl>`;
}

function linkRow(href, label = 'Xem chi tiết') {
  if (!href) return '';
  return `<a class="provider-link" href="${escapeHtml(href)}" target="_blank" rel="noopener">${escapeHtml(label)} ↗</a>`;
}

function formatDate(msOrIso) {
  if (!msOrIso) return '—';
  const d = typeof msOrIso === 'number' ? new Date(msOrIso) : new Date(msOrIso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString('vi-VN');
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ---------------- Copy JSON ---------------- */
async function copyJSON(payload, btn) {
  const text = JSON.stringify(payload, null, 2);
  const original = btn.textContent;
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = 'Đã sao chép ✓';
  } catch (e) {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    btn.textContent = 'Đã sao chép ✓';
  }
  setTimeout(() => (btn.textContent = original), 1500);
}

/* ---------------- Recent lookups ---------------- */
async function loadRecent() {
  if (!chrome?.storage?.local) return;
  const { [RECENT_KEY]: list = [] } = await chrome.storage.local.get(RECENT_KEY);
  if (!list.length) {
    recentWrap.hidden = true;
    return;
  }
  recentWrap.hidden = false;
  recentChips.innerHTML = '';
  for (const item of list) {
    const chip = document.createElement('button');
    chip.className = 'chip';
    chip.innerHTML = `<span class="dot" style="background:var(--${verdictColorVar(item.verdict)})"></span><span class="chip-label">${escapeHtml(item.value)}</span>`;
    chip.title = `${typeLabel(item.type)} · ${VERDICT_LABEL_VI[item.verdict]}`;
    chip.addEventListener('click', () => {
      iocInput.value = item.value;
      handleInput();
      runScan();
    });
    recentChips.appendChild(chip);
  }
}

function verdictColorVar(v) {
  if (v === VERDICT.MALICIOUS) return 'malicious';
  if (v === VERDICT.SUSPICIOUS) return 'suspicious';
  if (v === VERDICT.CLEAN) return 'clean';
  return 'unknown';
}

async function pushRecent({ type, value, verdict }) {
  if (!chrome?.storage?.local) return;
  const { [RECENT_KEY]: list = [] } = await chrome.storage.local.get(RECENT_KEY);
  const filtered = list.filter((it) => it.value !== value);
  filtered.unshift({ type, value, verdict, ts: Date.now() });
  await chrome.storage.local.set({ [RECENT_KEY]: filtered.slice(0, MAX_RECENT) });
  await loadRecent();
}
