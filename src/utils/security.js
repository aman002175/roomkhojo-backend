const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');

const DANGEROUS_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const EXEMPT_KEYS = new Set([
  'password', 'oldPassword', 'newPassword', 'currentPassword', 'confirmPassword',
  'otp', 'resetToken', 'idToken'
]);

const asString = (value) => (typeof value === 'string' ? value : value == null ? '' : String(value));

const cleanText = (value, max = 2000) => asString(value)
  .replace(/\r\n?/g, '\n')
  .replace(/<(script|style)[^>]*>[\s\S]*?<\/\1>/gi, '')
  .replace(/<[^>]*>/g, '')
  .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
  .trim()
  .slice(0, max);

const escapeHtml = (value) => asString(value)
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

const sanitizeValue = (value, key) => {
  if (typeof value === 'string') {
    if (EXEMPT_KEYS.has(key)) return value;
    return cleanText(value, 5000);
  }
  if (Array.isArray(value)) return value.map((item) => sanitizeValue(item, key));
  if (value && typeof value === 'object' && !Buffer.isBuffer(value)) {
    const out = {};
    for (const childKey of Object.keys(value)) {
      if (DANGEROUS_KEYS.has(childKey) || childKey.startsWith('$')) continue;
      out[childKey] = sanitizeValue(value[childKey], childKey);
    }
    return out;
  }
  return value;
};

const sanitizeDeep = (value) => sanitizeValue(value, '');

const safeEqual = (left, right) => {
  const a = Buffer.from(asString(left));
  const b = Buffer.from(asString(right));
  if (a.length !== b.length) {
    crypto.timingSafeEqual(a, a);
    return false;
  }
  return crypto.timingSafeEqual(a, b);
};

const getOtpSecret = () => {
  const secret = process.env.OTP_SECRET || process.env.JWT_SECRET;
  if (!secret) throw new Error('OTP/JWT secret configure nahi hai.');
  return secret;
};

const hashWithPurpose = (purpose, value) => crypto
  .createHmac('sha256', getOtpSecret())
  .update(`${purpose}:${asString(value)}`)
  .digest('hex');

const hashOtp = (value) => hashWithPurpose('otp', value);
const hashResetToken = (value) => hashWithPurpose('reset', value);

const passwordProblem = (password, min = 8) => {
  if (typeof password !== 'string') return 'Password string hona chahiye.';
  if (password.length < min) return `Password kam se kam ${min} characters ka ho.`;
  if (Buffer.byteLength(password, 'utf8') > 72) return 'Password 72 bytes se chhota hona chahiye.';
  return '';
};

const isPrivateIp = (rawIp) => {
  let ip = asString(rawIp).toLowerCase();
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a >= 224) return true;
    return false;
  }
  if (net.isIPv6(ip)) {
    if (ip === '::' || ip === '::1') return true;
    if (ip.startsWith('fc') || ip.startsWith('fd')) return true;
    if (/^fe[89ab]/.test(ip)) return true;
    return false;
  }
  return true;
};

const isAllowedMapHost = (hostname) => {
  const host = asString(hostname).toLowerCase();
  if (host === 'goo.gl' || host === 'maps.app.goo.gl') return true;
  return /^(?:(?:www|maps)\.)?google\.(?:com|co\.[a-z]{2}|[a-z]{2,3})$/.test(host);
};

const normalizeMapUrl = (raw) => {
  const input = asString(raw).trim();
  if (!input || input.length > 300) return null;
  let url;
  try { url = new URL(input); } catch { return null; }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  if (url.username || url.password) return null;
  if (url.port && url.port !== '443' && url.port !== '80') return null;
  if (!isAllowedMapHost(url.hostname)) return null;
  url.protocol = 'https:';
  if (url.port === '80') url.port = '';
  return url.toString();
};

const resolvePublicHost = async (hostname) => {
  const host = asString(hostname).toLowerCase();
  if (!host || host === 'localhost' || host.endsWith('.localhost')) {
    throw new Error('Private host blocked');
  }
  if (net.isIP(host)) {
    if (isPrivateIp(host)) throw new Error('Private IP blocked');
    return;
  }
  const records = await dns.lookup(host, { all: true, verbatim: true });
  if (!records.length) throw new Error('Host resolve nahi hua');
  for (const record of records) {
    if (isPrivateIp(record.address)) throw new Error('Private IP blocked');
  }
};

const readLimitedText = async (response, maxBytes) => {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxBytes) throw new Error('Upstream response too large');
      chunks.push(Buffer.from(value));
    }
  } finally {
    try { await reader.cancel(); } catch { /* already closed */ }
  }
  return Buffer.concat(chunks).toString('utf8');
};

const fetchMapPage = async (rawUrl, { timeoutMs = 5000, maxBytes = 200000, maxRedirects = 3 } = {}) => {
  let current = normalizeMapUrl(rawUrl);
  if (!current) throw new Error('Map URL allowed nahi hai');
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const url = new URL(current);
    await resolvePublicHost(url.hostname);
    if (!isAllowedMapHost(url.hostname)) throw new Error('Redirect host allowed nahi hai');
    const response = await fetch(current, {
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
      headers: { 'User-Agent': 'RoomKhojo/1.0 (+https://roomkhojoo.vercel.app)' }
    });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      if (!location) throw new Error('Redirect location missing');
      const next = new URL(location, current);
      if (next.protocol !== 'https:' || next.username || next.password || (next.port && next.port !== '443') || !isAllowedMapHost(next.hostname)) {
        throw new Error('Redirect target allowed nahi hai');
      }
      current = next.toString();
      continue;
    }
    if (!response.ok) throw new Error(`Upstream ${response.status}`);
    const contentLength = Number(response.headers.get('content-length') || 0);
    if (contentLength > maxBytes) throw new Error('Upstream response too large');
    const text = await readLimitedText(response, maxBytes);
    return { text, finalUrl: current };
  }
  throw new Error('Bahut zyada redirects');
};

module.exports = {
  asString,
  cleanText,
  escapeHtml,
  sanitizeDeep,
  safeEqual,
  hashOtp,
  hashResetToken,
  passwordProblem,
  isPrivateIp,
  isAllowedMapHost,
  normalizeMapUrl,
  resolvePublicHost,
  fetchMapPage
};
