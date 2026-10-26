// ==========================================
// 🌍 GEO PROXY (P2 #43): Overpass/Nominatim ab backend se jaate hain —
// server-side User-Agent (Nominatim policy), in-memory TTL cache (upstream load kam),
// har upstream call par timeout (service hang ho toh bhi saaf 502 mile).
// Cache per-instance hai (serverless cold start par miss — best-effort, maaf).
// ==========================================
const express = require('express');
const router = express.Router();
const { createLimiter } = require('../utils/rateStore');

// P2-5 fix: public proxy abuse rok — per-IP 60 req / 15 min
// (Nominatim 1 req/s policy + kumi Overpass public instance ki raksha)
const geoLimiter = createLimiter('geo', {
  windowMs: 15 * 60 * 1000,
  max: 60,
  message: { success: false, message: 'Bahut zyada map requests. Thodi der baad try karein.' }
});
router.use(geoLimiter);

const NOMINATIM = 'https://nominatim.openstreetmap.org';
const OVERPASS = 'https://overpass.kumi.systems/api/interpreter';
const UA = 'RoomKhojo/1.0 (+https://roomkhojoo.vercel.app)';

const CACHE_MAX = 300;
const cache = new Map();
const cacheGet = (key) => {
  const hit = cache.get(key);
  if (!hit) return null;
  if (Date.now() > hit.exp) { cache.delete(key); return null; }
  return hit.body;
};
const cacheSet = (key, ttlMs, body) => {
  if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value); // FIFO: sabse purana nikaalo
  cache.set(key, { exp: Date.now() + ttlMs, body });
};

const upstreamFetch = async (url, opts = {}, timeoutMs = 10000) => {
  const res = await fetch(url, {
    ...opts,
    signal: AbortSignal.timeout(timeoutMs),
    headers: { 'User-Agent': UA, ...(opts.headers || {}) }
  });
  if (!res.ok) throw new Error(`upstream ${res.status}`);
  return res.json();
};

const num = (v, min, max) => {
  if (v === '' || v === null || v === undefined) return null;
  const n = Number(v);
  return Number.isFinite(n) && n >= min && n <= max ? n : null;
};

// GET /api/geo/search?q=... → Nominatim search (FE pehla result hi use karta hai)
router.get('/search', async (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 80);
  if (!q) return res.status(400).json({ success: false, message: 'q zaroori hai.' });
  const key = `s:${q.toLowerCase()}`;
  const cached = cacheGet(key);
  if (cached) return res.json(cached);
  try {
    const data = await upstreamFetch(`${NOMINATIM}/search?format=json&limit=1&q=${encodeURIComponent(q + ' India')}`, {}, 8000);
    const out = { success: true, results: (Array.isArray(data) ? data : []).slice(0, 3).map(x => ({ lat: parseFloat(x.lat), lng: parseFloat(x.lon), name: x.display_name || '' })) };
    cacheSet(key, 60 * 60 * 1000, out); // 1 ghanta
    res.json(out);
  } catch {
    res.status(502).json({ success: false, message: 'Search service abhi busy hai — dobara try karein.' });
  }
});

// GET /api/geo/reverse?lat=&lng= → pin ka address (landmark auto-fill ke liye)
router.get('/reverse', async (req, res) => {
  const lat = num(req.query.lat, -90, 90);
  const lng = num(req.query.lng, -180, 180);
  if (lat === null || lng === null) return res.status(400).json({ success: false, message: 'lat/lng sahi do.' });
  const key = `r:${lat.toFixed(4)}:${lng.toFixed(4)}`;
  const cached = cacheGet(key);
  if (cached) return res.json(cached);
  try {
    const data = await upstreamFetch(`${NOMINATIM}/reverse?format=json&zoom=16&lat=${lat}&lon=${lng}`, {}, 8000);
    const address = String((data && (data.name || data.display_name)) || '').slice(0, 200);
    const out = { success: true, address };
    cacheSet(key, 24 * 60 * 60 * 1000, out); // 24 ghante (address roz badalta nahi)
    res.json(out);
  } catch {
    res.status(502).json({ success: false, message: 'Address service abhi busy hai.' });
  }
});

// GET /api/geo/nearby?lat=&lng=&radius= → Overpass POIs (elements FE me process hote hain — wahi logic)
router.get('/nearby', async (req, res) => {
  const lat = num(req.query.lat, -90, 90);
  const lng = num(req.query.lng, -180, 180);
  const radius = num(req.query.radius, 100, 5000) || 1500;
  if (lat === null || lng === null) return res.status(400).json({ success: false, message: 'lat/lng sahi do.' });
  const key = `n:${lat.toFixed(3)}:${lng.toFixed(3)}:${radius}`;
  const cached = cacheGet(key);
  if (cached) return res.json(cached);
  try {
    const q = `[out:json][timeout:10];(nwr["amenity"~"^(school|college|university|training|hospital|clinic|doctors)$"](around:${radius},${lat},${lng});nwr["highway"="bus_stop"](around:${radius},${lat},${lng});nwr["amenity"="bus_station"](around:${radius},${lat},${lng});nwr["railway"~"^(station|halt)$"](around:${radius},${lat},${lng}););out center 20;`;
    const data = await upstreamFetch(OVERPASS, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'data=' + encodeURIComponent(q)
    }, 12000);
    const out = { success: true, elements: Array.isArray(data.elements) ? data.elements.slice(0, 40) : [] };
    cacheSet(key, 10 * 60 * 1000, out); // 10 min
    res.json(out);
  } catch {
    res.status(502).json({ success: false, message: 'Nearby service abhi busy hai — dobara try karein.' });
  }
});

module.exports = router;
