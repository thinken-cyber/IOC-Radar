// lib/aggregate.js
// Gộp kết quả từ VirusTotal / AbuseIPDB / urlscan.io thành MỘT điểm rủi ro
// (0-100) và một nhãn đánh giá duy nhất, để người dùng không phải tự so sánh
// từng nguồn.

export const VERDICT = {
  MALICIOUS: 'malicious',
  SUSPICIOUS: 'suspicious',
  CLEAN: 'clean',
  UNKNOWN: 'unknown'
};

export const VERDICT_LABEL_VI = {
  [VERDICT.MALICIOUS]: 'Độc hại',
  [VERDICT.SUSPICIOUS]: 'Nghi ngờ',
  [VERDICT.CLEAN]: 'Sạch',
  [VERDICT.UNKNOWN]: 'Chưa đủ dữ liệu'
};

export function aggregateVerdict({ vt, abuseipdb, urlscan }) {
  let score = 0;
  let signals = 0;
  let maliciousDetection = false;

  if (vt && vt.found && vt.total > 0) {
    const ratio = (vt.malicious + vt.suspicious * 0.5) / vt.total;
    score = Math.max(score, Math.round(ratio * 100));
    maliciousDetection = vt.malicious > 0;
    signals++;
  }

  if (abuseipdb && abuseipdb.found) {
    score = Math.max(score, abuseipdb.abuseScore || 0);
    signals++;
  }

  if (urlscan && urlscan.found) {
    if (urlscan.verdictMalicious) {
      score = Math.max(score, 85);
    } else if (typeof urlscan.score === 'number' && urlscan.score > 0) {
      score = Math.max(score, Math.min(100, urlscan.score));
    }
    signals++;
  }

  if (signals === 0) return { verdict: VERDICT.UNKNOWN, score: null };
  if (maliciousDetection) score = Math.max(score, 5);

  let verdict;
  if (score >= 30) verdict = VERDICT.MALICIOUS;
  else if (score >= 5) verdict = VERDICT.SUSPICIOUS;
  else verdict = VERDICT.CLEAN;

  return { verdict, score };
}
