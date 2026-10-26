const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const mongoose = require('mongoose');
const Room = require('../models/Room');
const User = require('../models/User');
const Settings = require('../models/Settings');
const upload = require('../config/cloudinary');
const ContactReveal = require('../models/ContactReveal');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const { createLimiter } = require('../utils/rateStore');
const { normalizeMapUrl, fetchMapPage, cleanText, sanitizeDeep } = require('../utils/security');
const { logAudit, archiveRooms } = require('../utils/audit');
const { PUBLIC_ROOM_EXCLUDE } = require('../utils/roomProjection');

const viewLimiter = createLimiter('ad-view', {
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { success: false, message: 'Bahut zyada requests. Thodi der baad try karein.' }
});

// Audience types (category-wise frontend options ka union — backend guard)
const ALLOWED_TYPES = ['Boys', 'Girls', 'Family', 'Anyone'];
const cleanType = (raw) => {
  const t = String(raw || '').trim();
  return ALLOWED_TYPES.includes(t) ? t : null;
};

// 💳 Payment code: client (UPI note) ka code accept karo — dono taraf EK hi code rahe.
// Format: RK-XXXXX (frontend makePayCode). Invalid/spoofed → null (server khud banayega).
const cleanPayCode = (raw) => {
  const c = String(raw || '').trim().toUpperCase();
  return /^RK-[A-Z0-9]{4,10}$/.test(c) ? c : null;
};
const newPayCode = () => 'RK-' + crypto.randomBytes(3).toString('hex').toUpperCase();

// 💰 P1 #24: Price validation + ₹ normalization. FE `₹3000` bhejta hai (aur puraana
// data bhi `₹3000` format me hai) — isliye canonical `₹<digits>` hi store hota hai
// (display sab jagah unchanged). Junk "abc"/"3000-5000" → null (400).
// NOTE: DB me String hi (purane docs ke hydration-cast risk + FE price.replace compat).
const cleanPrice = (raw) => {
  const s = String(raw == null ? '' : raw).replace(/₹/g, '').replace(/,/g, '').trim();
  if (!/^\d+(\.\d+)?$/.test(s)) return null;
  const n = Number(s);
  if (!Number.isFinite(n) || n < 1 || n > 9999999) return null;
  return `₹${Math.round(n)}`;
};

// Settings me prices String ("₹299" / "299") hain — fee comparison ke liye number.
const moneyNum = (raw) => {
  const n = Number(String(raw == null ? '' : raw).replace(/[^\d.]/g, ''));
  return Number.isFinite(n) && n > 0 ? Math.round(n) : 0;
};

// 📍 Landmarks parse+validate (max 8, naam 120 chars, valid coords)
const cleanLandmarks = (raw) => {
  try {
    const arr = JSON.parse(raw || '[]');
    if (!Array.isArray(arr)) return [];
    return arr.slice(0, 8).map((l) => ({
      name: cleanText(l && l.name, 120),
      cat: cleanText(l && l.cat, 30),
      lat: Number(l && l.lat),
      lng: Number(l && l.lng),
      distM: Math.max(0, Math.round(Number((l && l.distM) || 0)))
    })).filter((l) => l.name && Number.isFinite(l.lat) && Number.isFinite(l.lng)
      && l.lat >= -90 && l.lat <= 90 && l.lng >= -180 && l.lng <= 180);
  } catch { return []; }
};

// Sirf malik ya admin modify kar sakta hai (C1 fix — ownership check)
const canModify = (room, user) => user.role === 'admin' || room.userId === user.id;

// Purana legacy ad? userId Mongo 24-hex NAHI hai (Google-sub digits / purana format) → orphan
const isOrphanUserId = (v) => !/^[a-f0-9]{24}$/i.test(String(v || ''));

// Indian mobile validation: 10 digits, 6-9 se shuru (91 prefix allowed)
const cleanMobile = (raw) => {
  const digits = String(raw || '').replace(/\D/g, '');
  const normalized = digits.length === 12 && digits.startsWith('91') ? digits.slice(2) : digits;
  return /^[6-9]\d{9}$/.test(normalized) ? normalized : null;
};

// Coordinate validation (range ke saath)
const toCoord = (val, min, max) => {
  if (val === '' || val === null || val === undefined) return null;
  const n = Number(val);
  return Number.isFinite(n) && n >= min && n <= max ? n : null;
};

const serverError = (res, err, label) => {
  console.error(`${label}:`, err.message);
  res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
};

// multer global xss-clean ke BAAD body parse karta hai — multipart fields ko
// yahan explicitly sanitize karo (warna room text fields raw DB me ja sakte hain).
const sanitizeMultipart = (req, res, next) => {
  if (req.body && typeof req.body === 'object') req.body = sanitizeDeep(req.body);
  next();
};

const isCloudinaryUrl = (value) => typeof value === 'string'
  && /^https:\/\/res\.cloudinary\.com\/[^\s"'<>]+$/i.test(value);

// 🛡️ P1 #15 fix: URL me galat id (e.g. /api/rooms/abc/edit) → CastError 500 ki jagah clean 404
// 🗺️ Google Maps link (optional) — strict Google host allowlist + https only
const cleanMapUrl = (raw) => {
  if (raw === undefined || raw === null || raw === '') return '';
  return normalizeMapUrl(raw);
};

// Link ke andar embedded coordinates nikaalo (short links ko expand karke bhi try)
const MAP_COORD_PATTERNS = [
  /@(-?\d{1,3}\.\d+),(-?\d{1,3}\.\d+)/,
  /[?&](?:q|query|ll|sll|destination)=(-?\d{1,3}\.\d+),(-?\d{1,3}\.\d+)/,
  /!3d(-?\d{1,3}\.\d+)!4d(-?\d{1,3}\.\d+)/
];
const coordsFromText = (text) => {
  const str = String(text || '');
  for (const re of MAP_COORD_PATTERNS) {
    const m = str.match(re);
    if (m) {
      const lat = Number(m[1]);
      const lng = Number(m[2]);
      if (Number.isFinite(lat) && Number.isFinite(lng) && lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180) {
        return { lat, lng };
      }
    }
  }
  return null;
};
const coordsFromMapUrl = async (urlStr) => {
  const direct = coordsFromText(urlStr);
  if (direct) return direct;
  // goo.gl / maps.app.goo.gl short link → manual redirect expansion, sirf Google hosts,
  // private-IP DNS guard + 200KB response cap (SSRF/DoS-safe).
  try {
    const { text, finalUrl } = await fetchMapPage(urlStr, { timeoutMs: 5000, maxBytes: 200000 });
    return coordsFromText(finalUrl) || coordsFromText(text);
  } catch { return null; }
};

// 📞 Number reveal: IST din + per-user daily limit (admin setting se)
const istDateKey = () => new Date(Date.now() + 5.5 * 60 * 60 * 1000).toISOString().slice(0, 10);
const revealLimit = (settings) => {
  const n = Number(settings && settings.contactRevealLimit);
  return Number.isFinite(n) && n >= 1 && n <= 100 ? Math.floor(n) : 15;
};

router.param('id', (req, res, next, id) => {
  if (!mongoose.isValidObjectId(id)) {
    return res.status(404).json({ success: false, message: 'Room nahi mila.' });
  }
  next();
});

// --- ADMIN: saare rooms (ADMIN ONLY — pehle x-admin-secret header tha, ab JWT) ---
router.get('/admin/all', requireAdmin, async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    // P1 #19: unbounded dump band — cap 1000 + lean (admin list isse chhoti hai)
    const rooms = await Room.find().sort({ createdAt: -1 }).limit(1000).lean();
    res.status(200).json({ success: true, rooms });
  } catch (error) { serverError(res, error, 'Admin-all error'); }
});

// --- ADMIN: purane-ad claim requests (#13 fix — mobile match hui hain, admin verify kare) ---
router.get('/admin/claims', requireAdmin, async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const rooms = await Room.find({ claimRequestedAt: { $ne: null } })
      .sort({ claimRequestedAt: -1 })
      .select('title image price mobile ownerName userId claimRequestedBy claimRequestName claimRequestedAt');
    res.status(200).json({ success: true, rooms });
  } catch (error) { serverError(res, error, 'Admin-claims error'); }
});

// Approve: ad claimant ke account se link (userId swap) + claim fields clear.
router.post('/admin/claims/:id/approve', requireAdmin, async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);
    if (!room) return res.status(404).json({ success: false, message: 'Room nahi mila.' });
    if (!room.claimRequestedBy) return res.status(400).json({ success: false, message: 'Is ad par koi claim request nahi hai.' });
    const claimant = await User.findById(room.claimRequestedBy).select('name');
    room.userId = room.claimRequestedBy;
    if (claimant && claimant.name) room.ownerName = claimant.name;
    room.claimRequestedBy = null;
    room.claimRequestName = '';
    room.claimRequestedAt = null;
    await room.save();
    await logAudit(req, { action: 'room.claim.approve', targetType: 'room', targetId: room._id, details: { claimantId: String(room.userId) } });
    res.json({ success: true, message: 'Ad claimant ke account se link ho gaya.', room });
  } catch (error) { serverError(res, error, 'Claim approve error'); }
});

router.post('/admin/claims/:id/reject', requireAdmin, async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);
    if (!room) return res.status(404).json({ success: false, message: 'Room nahi mila.' });
    room.claimRequestedBy = null;
    room.claimRequestName = '';
    room.claimRequestedAt = null;
    await room.save();
    await logAudit(req, { action: 'room.claim.reject', targetType: 'room', targetId: room._id });
    res.json({ success: true, message: 'Claim request reject kar di.' });
  } catch (error) { serverError(res, error, 'Claim reject error'); }
});

// --- POST NEW AD (LOGIN REQUIRED — C1/C6 fix) ---
// userId/ownerName token se aate hain (client-spoofing band).
// isPromoted client se NAHI liya jaata — promo sirf admin approve ke baad lagta hai.
// paymentCode server generate karta hai (client ka random code nahi).
router.post('/', requireAuth, upload.array('images', 6), sanitizeMultipart, async (req, res) => {
  // P1 #21 tracking: save fail hone par upload hui photos orphan na rahein
  let uploadedThisRequest = [];
  let savedOk = false;
  try {
    // P1-1 fix: per-user daily ad cap (10/din) — Cloudinary cost + spam abuse rok
    if (req.user.role !== 'admin') {
      const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const recentAds = await Room.countDocuments({ userId: req.user.id, createdAt: { $gte: dayAgo } });
      if (recentAds >= 10) {
        return res.status(429).json({ success: false, message: 'Ek din me max 10 ads post kar sakte ho. 24 ghante baad dobara try karo.' });
      }
    }
    const { title, price, type, category, landmark, mobile, description, lng, lat, promoPlan, paymentRef, paymentCode, bannerRequested, bannerRef, landmarks, googleMapUrl, listingType } = req.body || {};
    const isService = listingType === 'service';
    if (!title || !price || !category || (!isService && !type)) {
      return res.status(400).json({ success: false, message: isService ? 'Service ka naam, Price aur Category zaroori hain.' : 'Title, Price, Type aur Category zaroori hain.' });
    }
    const cleanTitle = cleanText(title, 120);
    if (cleanTitle.length < 3) {
      return res.status(400).json({ success: false, message: 'Title 3-120 characters ka ho.' });
    }
    const cleanCategory = cleanText(category, 60);
    if (cleanCategory.length < 2) {
      return res.status(400).json({ success: false, message: 'Sahi category chunein.' });
    }
    const cleanLandmark = cleanText(landmark, 160);
    const cleanDescription = cleanText(description, 2000);
    const cleanAudience = isService ? 'Service' : cleanType(type);
    if (!cleanAudience) {
      return res.status(400).json({ success: false, message: 'Audience (Boys/Girls/Family/Anyone) sahi chuno.' });
    }
    const cleanPhone = cleanMobile(mobile);
    if (!cleanPhone) {
      return res.status(400).json({ success: false, message: 'Sahi 10-digit mobile number daliye.' });
    }
    const cleanPriceVal = cleanPrice(price); // P1 #24: "abc" jaisa junk price reject
    if (!cleanPriceVal) {
      return res.status(400).json({ success: false, message: 'Price sirf number hona chahiye (jaise 3000).' });
    }
    // 🗺️ Optional Google Maps link — link me coords milen toh wahi use karo (zyada accurate)
    let mapLink = '';
    if (googleMapUrl !== undefined && googleMapUrl !== null) {
      mapLink = cleanMapUrl(googleMapUrl);
      if (mapLink === null) {
        return res.status(400).json({ success: false, message: 'Google Maps link sahi nahi hai. Sirf maps.google.com / maps.app.goo.gl links chalenge.' });
      }
    }
    let cleanLng = toCoord(lng, -180, 180);
    let cleanLat = toCoord(lat, -90, 90);
    if (mapLink) {
      const fromLink = await coordsFromMapUrl(mapLink);
      if (fromLink) { cleanLat = fromLink.lat; cleanLng = fromLink.lng; }
    }
    if (cleanLng === null || cleanLat === null) {
      return res.status(400).json({ success: false, message: 'Map par location select karein ya Google Maps link daalein.' });
    }
    const requestedPlan = ['regular', '7', '15', '30'].includes(promoPlan) ? promoPlan : 'regular';

    // 🧾 Service provider listing fee: duration provider chunta hai, rate admin control karta hai.
    // Fee hamesha server calculate karta hai (client ka bheja amount ignore).
    let serviceDays = 0;
    if (isService) {
      const days = Number(req.body.serviceDays);
      if (!Number.isInteger(days) || days < 1 || days > 365) {
        return res.status(400).json({ success: false, message: 'Service listing duration 1 se 365 din ke beech chunein.' });
      }
      serviceDays = days;
    }
    const appSettings = await Settings.findOne({ key: 'app_settings' }).lean();
    const rawServiceRate = Number(appSettings && appSettings.pricing && appSettings.pricing.serviceDailyRate);
    const serviceDailyRate = isService && Number.isFinite(rawServiceRate) && rawServiceRate > 0
      ? Math.min(100000, Math.floor(rawServiceRate))
      : 0;
    const serviceFee = isService ? serviceDailyRate * serviceDays : 0;
    const bannerWanted = bannerRequested === 'true' || bannerRequested === true;
    const regularFee = requestedPlan === 'regular' ? moneyNum(appSettings && appSettings.pricing && appSettings.pricing.regular) : 0;
    const promoFee = requestedPlan === 'regular' ? 0 : moneyNum(appSettings && appSettings.pricing && appSettings.pricing[`promo${requestedPlan}`]);
    const bannerFee = bannerWanted ? moneyNum(appSettings && appSettings.pricing && appSettings.pricing.bannerPrice) : 0;
    const paidTotal = serviceFee + regularFee + promoFee + bannerFee;
    const cleanPaymentRef = cleanText(paymentRef, 64);
    // UTR/UPI ref ke bina paid ad accept nahi — empty field par payment window se aage nahi.
    if (paidTotal > 0 && cleanPaymentRef.replace(/\s/g, '').length < 6) {
      return res.status(400).json({ success: false, message: 'Payment ke baad UPI Ref / UTR number daalna zaroori hai (min 6 characters).' });
    }

    let ownerName = 'Owner';
    if (req.user.role !== 'admin') {
      const owner = await User.findById(req.user.id);
      if (owner) ownerName = owner.name;
    } else {
      ownerName = 'Admin';
    }

    // 📸 Photos Cloudinary par upload karo (max 6, memory buffer se)
    let imageUrls = [];
    if (req.files && req.files.length > 0) {
      const uploaded = await Promise.all(
        req.files.slice(0, 6).map((f) => upload.uploadBufferToCloudinary(f))
      );
      uploadedThisRequest = uploaded.map((u) => u.secure_url).filter(isCloudinaryUrl);
      imageUrls = uploadedThisRequest;
    }

    const newRoom = new Room({
      title: cleanTitle,
      listingType: isService ? 'service' : 'room',
      price: cleanPriceVal,
      type: cleanAudience,
      category: cleanCategory,
      landmark: cleanLandmark,
      mobile: cleanPhone,
      description: cleanDescription,
      lng: cleanLng,
      lat: cleanLat,
      isPromoted: false, // Hamesha false — admin approve karega (C6)
      promoPlan: 'regular',
      promoRequested: requestedPlan,
      paymentRef: cleanPaymentRef,
      // 🎯 Banner add-on request (activate sirf admin karega)
      bannerRequested: bannerWanted,
      bannerRef: cleanText(bannerRef || cleanPaymentRef || '', 64),
      isBannerActive: false,
      // 🧾 Service listing duration + admin rate snapshot (approval par expiry set hogi)
      serviceDays,
      serviceDailyRate,
      serviceFee,
      // 📍 User-selected nearby landmarks
      landmarks: cleanLandmarks(landmarks),
      googleMapUrl: mapLink,
      userId: req.user.id,
      ownerName,
      image: imageUrls[0] || '',
      images: imageUrls,
      paymentCode: cleanPayCode(paymentCode) || newPayCode()
    });

    // 🟢 Auto-approve: sirf FREE/regular ads, aur sirf jab admin ne toggle ON kiya ho.
    // Promo/banner wale HAMESHA pending (payment verify hoga).
    const wantsPaid = paidTotal > 0 || requestedPlan !== 'regular' || bannerWanted || serviceFee > 0;
    if (!wantsPaid && !isService) {
      if (appSettings && appSettings.autoApproveFree) newRoom.isApproved = true;
    }

    const savedRoom = await newRoom.save();
    savedOk = true;
    const liveMsg = savedRoom.isApproved
      ? 'Ad live ho gaya!'
      : 'Ad submitted! Admin verification ke baad live hoga.';
    res.status(201).json({ success: true, message: liveMsg, room: savedRoom });
  } catch (error) {
    // P1 #21: ad save fail hui toh upload hui photos Cloudinary par orphan na rahein
    if (!savedOk && uploadedThisRequest.length > 0) {
      await upload.destroyByUrls(uploadedThisRequest).catch(() => {});
    }
    serverError(res, error, 'Post-ad error');
  }
});

// --- LIVE ROOMS (MAP VIEW — public) ---
// Promo expire hone par ad GAYAB nahi hota — NORMAL (free) ad ki tarah live rehta hai.
// Featured/normal ka faisla frontend karta hai (expiry dekh kar), isliye yahan
// expiry filter nahi hai. (Banner strip ka alag strict filter hai.)
router.get('/', async (req, res) => {
  try {
    const now = new Date();
    // Service provider listing apni chosen duration ke baad public list se hat jati hai.
    // P1 #19: unbounded dump band — cap 1000 + lean (map par isse zyada pins ka koi fayda nahi)
    const rooms = await Room.find({
      isApproved: true,
      isActive: true,
      $or: [
        { listingType: { $ne: 'service' } },
        { serviceExpiresAt: null },
        { serviceExpiresAt: { $gte: now } }
      ]
    })
      .select(PUBLIC_ROOM_EXCLUDE)
      .sort({ createdAt: -1 }).limit(1000).lean();
    res.status(200).json({ success: true, count: rooms.length, rooms });
  } catch (error) { serverError(res, error, 'Live-rooms error'); }
});

// --- LIVE BANNER ADS (top strip — public) ---
router.get('/banners', async (req, res) => {
  try {
    const now = new Date();
    // Paid banners + approved service providers (tiffin/laundry etc.) dono top strip me.
    const rooms = await Room.find({
      isApproved: true,
      isActive: true,
      $or: [
        { isBannerActive: true, $or: [{ bannerExpires: null }, { bannerExpires: { $gte: now } }] },
        { listingType: 'service', $or: [{ serviceExpiresAt: null }, { serviceExpiresAt: { $gte: now } }] }
      ]
    }).select(PUBLIC_ROOM_EXCLUDE).sort({ createdAt: -1 }).limit(50).lean(); // P1 #19 (top strip chhota hota hai)
    res.json({ success: true, count: rooms.length, rooms });
  } catch (error) { serverError(res, error, 'Banners error'); }
});

// 📞 P1: number-reveal usage — user ko pata rahe daily limit me kitne bache hain
router.get('/contact-usage', requireAuth, async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const settings = await Settings.findOne({ key: 'app_settings' }).lean();
    const limit = revealLimit(settings);
    const used = await ContactReveal.countDocuments({ userId: req.user.id, date: istDateKey() });
    res.json({ success: true, used, limit, remaining: Math.max(0, limit - used) });
  } catch (error) { serverError(res, error, 'Contact-usage error'); }
});

// 📞 P1: logged-in user number reveal kare (daily limit + same ad dobara kholna free)
router.get('/:id/contact', requireAuth, async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const room = await Room.findById(req.params.id).select('mobile isApproved isActive userId listingType serviceExpiresAt').lean();
    if (!room || !room.mobile) {
      return res.status(404).json({ success: false, message: 'Is ad ka number available nahi hai.' });
    }
    const isOwner = room.userId === req.user.id;
    const serviceExpired = room.listingType === 'service' && room.serviceExpiresAt && new Date(room.serviceExpiresAt) <= new Date();
    if (!isOwner && req.user.role !== 'admin' && (!(room.isApproved && room.isActive) || serviceExpired)) {
      return res.status(404).json({ success: false, message: 'Ye ad ab live nahi hai.' });
    }
    const date = istDateKey();
    const settings = await Settings.findOne({ key: 'app_settings' }).lean();
    const limit = revealLimit(settings);
    const already = await ContactReveal.exists({ userId: req.user.id, roomId: req.params.id, date });
    if (!already) {
      const used = await ContactReveal.countDocuments({ userId: req.user.id, date });
      if (used >= limit) {
        return res.status(429).json({
          success: false,
          message: `Aaj ka number-reveal limit khatam ho gaya (${used}/${limit}). Kal dobara try karo.`,
          used, limit, remaining: 0
        });
      }
      try {
        await ContactReveal.create({ userId: req.user.id, roomId: req.params.id, date });
      } catch { /* unique-race: pehle se revealed — count dobara nahi badhta */ }
    }
    const usedNow = await ContactReveal.countDocuments({ userId: req.user.id, date });
    res.json({
      success: true,
      mobile: room.mobile,
      whatsapp: room.mobile,
      used: usedNow,
      limit,
      remaining: Math.max(0, limit - usedNow)
    });
  } catch (error) { serverError(res, error, 'Contact-reveal error'); }
});

// --- ADMIN: banner approve/revoke (payment verify ke baad) ---
router.patch('/:id/banner', requireAdmin, async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);
    if (!room) return res.status(404).json({ success: false, message: 'Room nahi mila.' });
    const { approve } = req.body || {};
    if (approve) {
      const s = await Settings.findOne({ key: 'app_settings' });
      const days = parseInt(s && s.pricing && s.pricing.bannerDays, 10);
      const validDays = Number.isFinite(days) && days > 0 ? days : 7;
      room.isBannerActive = true;
      room.bannerExpires = new Date(Date.now() + validDays * 24 * 60 * 60 * 1000);
      room.bannerAmount = Number((s && s.pricing && s.pricing.bannerPrice) || 0) || 0; // 💰 #56: banner revenue record
    } else {
      room.isBannerActive = false;
      room.bannerExpires = null;
    }
    await room.save();
    await logAudit(req, { action: approve ? 'room.banner.approve' : 'room.banner.revoke', targetType: 'room', targetId: room._id });
    res.json({ success: true, message: approve ? 'Banner live ho gaya!' : 'Banner hata diya gaya.', room });
  } catch (error) { serverError(res, error, 'Banner error'); }
});

// User Dashboard Ads (SELF OR ADMIN — H1 fix, pehle koi bhi kisi ka dekh sakta tha)
router.get('/user/:userId', requireAuth, async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    if (!mongoose.isValidObjectId(req.params.userId)) {
      return res.status(404).json({ success: false, message: 'User nahi mila.' });
    }
    if (req.user.role !== 'admin' && req.params.userId !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Access Denied!' });
    }
    const rooms = await Room.find({ userId: req.params.userId }).sort({ createdAt: -1 }).limit(500).lean(); // P1 #19
    res.json({ success: true, rooms });
  } catch (error) { serverError(res, error, 'User-rooms error'); }
});

// Toggle active/inactive (OWNER OR ADMIN — C1 fix + M15 null check)
router.patch('/:id/toggle-status', requireAuth, async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);
    if (!room) return res.status(404).json({ success: false, message: 'Room nahi mila.' });
    if (!canModify(room, req.user)) {
      return res.status(403).json({ success: false, message: 'Access Denied! Ye ad aapka nahi hai.' });
    }
    room.isActive = !room.isActive;
    await room.save();
    res.json({ success: true, isActive: room.isActive, message: 'Status Updated' });
  } catch (error) { serverError(res, error, 'Toggle-status error'); }
});

// SMART EDIT ROUTE (OWNER OR ADMIN — C1 fix; edit = dobara pending)
// NOTE: auth check multer se PEHLE hai taaki bina-login upload na ho.
router.put('/:id/edit', requireAuth, upload.array('images', 6), sanitizeMultipart, async (req, res) => {
  // P1 #21 tracking: edit fail hone par nayi upload hui photos orphan na rahein
  let uploadedThisRequest = [];
  let savedOk = false;
  try {
    const room = await Room.findById(req.params.id);
    if (!room) return res.status(404).json({ success: false, message: 'Room not found' });
    if (!canModify(room, req.user)) {
      return res.status(403).json({ success: false, message: 'Access Denied! Ye ad aapka nahi hai.' });
    }

    const isServiceListing = room.listingType === 'service';
    if (req.body.title !== undefined) {
      const cleanTitle = cleanText(req.body.title, 120);
      if (cleanTitle.length < 3) return res.status(400).json({ success: false, message: 'Title 3-120 characters ka ho.' });
      room.title = cleanTitle;
    }
    if (req.body.price) {
      const cleanPriceVal = cleanPrice(req.body.price); // P1 #24
      if (!cleanPriceVal) return res.status(400).json({ success: false, message: 'Price sirf number hona chahiye (jaise 3000).' });
      room.price = cleanPriceVal;
    }
    if (req.body.type && !isServiceListing) {
      const cleanAudience = cleanType(req.body.type);
      if (!cleanAudience) return res.status(400).json({ success: false, message: 'Audience (Boys/Girls/Family/Anyone) sahi chuno.' });
      room.type = cleanAudience;
    }
    if (req.body.category !== undefined) {
      const cleanCategory = cleanText(req.body.category, 60);
      if (cleanCategory.length < 2) return res.status(400).json({ success: false, message: 'Sahi category chunein.' });
      room.category = cleanCategory;
    }
    if (req.body.landmark !== undefined) room.landmark = cleanText(req.body.landmark, 160);
    if (req.body.mobile) {
      const cleanPhone = cleanMobile(req.body.mobile);
      if (!cleanPhone) return res.status(400).json({ success: false, message: 'Sahi 10-digit mobile number daliye.' });
      room.mobile = cleanPhone;
    }
    if (req.body.description !== undefined) room.description = cleanText(req.body.description, 2000);
    // 📍 Landmarks dobara select kiye hon toh replace (bheje hi nahi toh puraane safe)
    if (req.body.landmarks !== undefined) room.landmarks = cleanLandmarks(req.body.landmarks);

    if (req.body.lng !== undefined) {
      const cleanLng = toCoord(req.body.lng, -180, 180);
      if (cleanLng === null) return res.status(400).json({ success: false, message: 'Sahi location select karein.' });
      room.lng = cleanLng;
    }
    if (req.body.lat !== undefined) {
      const cleanLat = toCoord(req.body.lat, -90, 90);
      if (cleanLat === null) return res.status(400).json({ success: false, message: 'Sahi location select karein.' });
      room.lat = cleanLat;
    }

    // 🗺️ Google Maps link (optional) — link mile toh coords bhi update (accurate location)
    if (req.body.googleMapUrl !== undefined) {
      const link = cleanMapUrl(req.body.googleMapUrl);
      if (link === null) {
        return res.status(400).json({ success: false, message: 'Google Maps link sahi nahi hai.' });
      }
      room.googleMapUrl = link;
      if (link) {
        const fromLink = await coordsFromMapUrl(link);
        if (fromLink) { room.lat = fromLink.lat; room.lng = fromLink.lng; }
      }
    }

    // 📸 Gallery: keep-list (sirf mevcut photos me se) + naye uploads, max 6
    const currentGallery = (room.images && room.images.length > 0)
      ? [...room.images]
      : (room.image ? [room.image] : []);
    let keepList = [...currentGallery];
    if (req.body.keepImages !== undefined) {
      try {
        const arr = JSON.parse(req.body.keepImages || '[]');
        keepList = Array.isArray(arr)
          ? arr.filter((u) => typeof u === 'string' && currentGallery.includes(u)).slice(0, 6)
          : [];
      } catch { keepList = []; }
    }
    let newUrls = [];
    if (req.files && req.files.length > 0) {
      const uploaded = await Promise.all(
        req.files.slice(0, 6).map((f) => upload.uploadBufferToCloudinary(f))
      );
      uploadedThisRequest = uploaded.map((u) => u.secure_url).filter(isCloudinaryUrl);
      newUrls = uploadedThisRequest;
    }
    const finalGallery = [...keepList.filter(isCloudinaryUrl), ...newUrls].slice(0, 6);
    // P1 #21: jo purani photos is edit me hata di gayi, wo Cloudinary par orphan na rahein
    const removedUrls = currentGallery.filter((u) => !finalGallery.includes(u));
    room.images = finalGallery;
    room.image = finalGallery[0] || '';

    // 🚨 FRAUD PROTECTION: User ne edit kiya = Approve hategi aur Pending me jayega!
    room.isApproved = false;

    await room.save();
    savedOk = true;
    if (removedUrls.length > 0) await upload.destroyByUrls(removedUrls).catch(() => {}); // P1 #21
    res.status(200).json({ success: true, message: 'Ad updated! Sent to Admin for verification.', room });
  } catch (error) {
    if (!savedOk && uploadedThisRequest.length > 0) {
      await upload.destroyByUrls(uploadedThisRequest).catch(() => {}); // P1 #21: save hua hi nahi
    }
    serverError(res, error, 'Edit-room error');
  }
});

// --- ADMIN APPROVE LOGIC (ADMIN ONLY — C1 fix) ---
// Promo tabhi lagta hai jab admin payment verify karke approve kare (C6 fix).
router.patch('/:id/approve', requireAdmin, async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);
    if (!room) return res.status(404).json({ success: false, message: 'Room nahi mila.' });
    room.isApproved = true;

    // 💰 #56: payment verify hone par amount record karo (admin stats isi par based hai)
    const st = await Settings.findOne({ key: 'app_settings' });
    const pricing = (st && st.pricing) || {};
    if (room.listingType === 'service') {
      // Service fee submit-time snapshot hai — approve par amount dobara mat badlo.
      room.paymentAmount = Number(room.serviceFee) || 0;
      // Timer admin approval se shuru: provider ko review time ka loss nahi.
      if (!room.serviceExpiresAt && Number(room.serviceDays) > 0) {
        const start = new Date();
        room.serviceStartsAt = start;
        room.serviceExpiresAt = new Date(start.getTime() + Number(room.serviceDays) * 24 * 60 * 60 * 1000);
      }
    } else {
      const reqPlanKey = room.promoRequested && room.promoRequested !== 'regular' ? `promo${room.promoRequested}` : 'regular';
      room.paymentAmount = Number(pricing[reqPlanKey] || 0) || 0;
    }

    if (room.listingType !== 'service' && room.promoRequested && room.promoRequested !== 'regular') {
      const newPlan = room.promoRequested;
      const planChanged = room.promoPlan !== newPlan;
      room.isPromoted = true;
      room.promoPlan = newPlan;
      // Expiry reset: pehli baar, plan badalne par, ya renew par (puraani expiry beet chuki ho)
      const expired = !room.expiryDate || room.expiryDate <= new Date();
      if (planChanged || expired) {
        const days = parseInt(newPlan, 10);
        if (Number.isFinite(days) && days > 0) {
          room.expiryDate = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
        }
      }
    }

    await room.save();
    await logAudit(req, { action: 'room.approve', targetType: 'room', targetId: room._id });
    res.status(200).json({ success: true, message: room.listingType === 'service' ? 'Service listing approved!' : 'Room Approved!', room });
  } catch (error) { serverError(res, error, 'Approve error'); }
});

// --- RENEW PROMO PLAN (OWNER OR ADMIN) ---
// Expired promo dobara khareedo: naya plan + UPI ref → dobara pending (admin verify karega).
// Expiry approve ke time fresh set hogi (upar logic).
router.post('/:id/renew', requireAuth, async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);
    if (!room) return res.status(404).json({ success: false, message: 'Room nahi mila.' });
    if (!canModify(room, req.user)) {
      return res.status(403).json({ success: false, message: 'Access Denied! Ye ad aapka nahi hai.' });
    }
    const { promoPlan, paymentRef, paymentCode } = req.body || {};
    if (!['7', '15', '30'].includes(promoPlan)) {
      return res.status(400).json({ success: false, message: 'Plan 7, 15 ya 30 din ka chuno.' });
    }
    const renewRef = cleanText(paymentRef, 64);
    if (renewRef.replace(/\s/g, '').length < 6) {
      return res.status(400).json({ success: false, message: 'Payment ke baad UPI Ref / UTR number daalna zaroori hai (min 6 characters).' });
    }
    room.promoRequested = promoPlan;
    room.paymentRef = renewRef;
    room.paymentCode = cleanPayCode(paymentCode) || newPayCode();
    room.isApproved = false; // Dobara admin verification (payment check)
    await room.save();
    res.json({ success: true, message: 'Renew request bheji gayi! Payment verify hote hi ad live hoga.', room });
  } catch (error) { serverError(res, error, 'Renew error'); }
});

// --- PURANE AD CLAIM (#13 fix): step 1 — mobile se apne orphan ads dhundho ---
// Ad ka mobile number PUBLIC hota hai, isliye mobile match akela proof nahi hai —
// match hone par sirf claim REQUEST banti hai, final link ADMIN approve karta hai.
router.get('/claimable', requireAuth, async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const clean = cleanMobile(req.query.mobile);
    if (!clean) return res.status(400).json({ success: false, message: 'Sahi 10-digit mobile number daliye.' });
    const candidates = await Room.find({ isActive: true })
      .sort({ createdAt: -1 })
      .limit(500)
      .select('userId mobile title image price createdAt claimRequestedBy');
    const mine = candidates.filter((r) => isOrphanUserId(r.userId) && cleanMobile(r.mobile) === clean);
    res.json({
      success: true,
      rooms: mine.map((r) => ({
        _id: r._id,
        title: r.title,
        image: r.image,
        price: r.price,
        createdAt: r.createdAt,
        claimPending: Boolean(r.claimRequestedBy),
        claimByMe: r.claimRequestedBy === String(req.user.id)
      }))
    });
  } catch (error) { serverError(res, error, 'Claimable error'); }
});

// --- PURANE AD CLAIM: step 2 — claim request bhejo (admin verify karega) ---
router.post('/:id/claim', requireAuth, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(404).json({ success: false, message: 'Room nahi mila.' });
    }
    const room = await Room.findById(req.params.id);
    if (!room) return res.status(404).json({ success: false, message: 'Room nahi mila.' });
    if (!isOrphanUserId(room.userId)) {
      return res.status(400).json({ success: false, message: 'Ye ad already kisi account se link hai.' });
    }
    if (room.claimRequestedBy === String(req.user.id)) {
      return res.json({ success: true, message: 'Claim request pehle hi bheji hui hai — admin approval ka intezaar karein.' });
    }
    if (room.claimRequestedBy) {
      return res.status(409).json({ success: false, message: 'Is ad par kisi aur ki claim request pehle se hai. Admin se baat karein.' });
    }
    const clean = cleanMobile(req.body && req.body.mobile);
    if (!clean || clean !== cleanMobile(room.mobile)) {
      return res.status(400).json({ success: false, message: 'Mobile number ad ke number se match nahi hua. Wahi number daliye jo ad par tha.' });
    }
    const claimant = await User.findById(req.user.id).select('name');
    room.claimRequestedBy = String(req.user.id);
    room.claimRequestName = (claimant && claimant.name) || '';
    room.claimRequestedAt = new Date();
    await room.save();
    res.json({ success: true, message: 'Claim request bhej di! Admin verify karke ad aapke account me daal dega.' });
  } catch (error) { serverError(res, error, 'Claim error'); }
});

// --- REPORT UNAVAILABLE (atomic + spam-guard — M1/P0 fix) ---
// P1-2 fix: report ke liye LOGIN zaroori (1 account = 1 report — IP-rotation griefing band).
// userId ka sha1 hash dedupe (raw id store nahi) + atomic $push/$inc (race-safe).
// Threshold 5 alag users: itne reports par ad AUTO-HIDE ho jata hai.
router.put('/:id/report-unavailable', requireAuth, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(404).json({ success: false, message: 'Room nahi mila.' });
    }
    const reportKey = crypto.createHash('sha1').update(`u:${req.user.id}`).digest('hex').slice(0, 24);
    const updated = await Room.findOneAndUpdate(
      { _id: req.params.id, reportedBy: { $ne: reportKey } },
      { $push: { reportedBy: { $each: [reportKey], $slice: -500 } }, $inc: { unavailableReportCount: 1 } },
      { new: true }
    );
    if (!updated) {
      const exists = await Room.exists({ _id: req.params.id });
      if (!exists) return res.status(404).json({ success: false, message: 'Room nahi mila.' });
      return res.status(429).json({ success: false, message: 'Aap ye report pehle hi kar chuke hain.' });
    }
    // 🛡️ 5+ alag users ke reports par AUTO-HIDE — race-safe (sirf tab jab abhi active ho)
    let hidden = false;
    if (updated.unavailableReportCount >= 5 && updated.isActive) {
      const r = await Room.updateOne({ _id: updated._id, isActive: true }, { $set: { isActive: false } });
      hidden = r.modifiedCount > 0;
    }
    res.status(200).json({
      success: true,
      message: hidden ? 'Report noted. 5+ reports par ad auto-hide ho gaya hai.' : 'Reported successfully',
      count: updated.unavailableReportCount,
      hidden
    });
  } catch (error) { serverError(res, error, 'Report error'); }
});

// --- AD VIEW COUNTER (public, D1) — server-side dedupe (IP+din), fail silent (UX na toote)
router.put('/:id/view', viewLimiter, async (req, res) => {
  try {
    const day = new Date().toISOString().slice(0, 10);
    const viewKey = crypto.createHash('sha1').update(`${req.ip || 'unknown'}|${day}`).digest('hex').slice(0, 24);
    const updated = await Room.findOneAndUpdate(
      { _id: req.params.id, isApproved: true, isActive: true, viewKeys: { $ne: viewKey } },
      { $push: { viewKeys: { $each: [viewKey], $slice: -3000 } }, $inc: { views: 1 } },
      { projection: { _id: 1 } }
    );
    res.json({ success: Boolean(updated) });
  } catch { res.json({ success: false }); }
});

// Delete ad (OWNER OR ADMIN — C1 fix + M15 null check)
router.delete('/:id', requireAuth, async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);
    if (!room) return res.status(404).json({ success: false, message: 'Room nahi mila.' });
    if (!canModify(room, req.user)) {
      return res.status(403).json({ success: false, message: 'Access Denied! Ye ad aapka nahi hai.' });
    }
    // Data-loss safeguard: pehle snapshot archive karo, archive fail ho toh delete abort.
    const archived = await archiveRooms(room.toObject(), {
      deletedBy: req.user.id,
      deletedByRole: req.user.role === 'admin' ? 'admin' : 'user',
      reason: 'room delete'
    });
    if (archived !== 1) {
      return res.status(503).json({ success: false, message: 'Delete abhi safe nahi hai. Thodi der baad try karein.' });
    }
    await Room.findByIdAndDelete(req.params.id);
    // P1 #21: ad delete par uski saari photos Cloudinary se bhi hatao (bounded, best-effort)
    const galleryToDelete = [...(room.images || []), room.image].filter(Boolean);
    await upload.destroyByUrls(galleryToDelete).catch(() => {});
    await logAudit(req, {
      action: 'room.delete',
      targetType: 'room',
      targetId: room._id,
      details: { title: room.title, listingType: room.listingType }
    });
    res.status(200).json({ success: true, message: 'Room Deleted!' });
  } catch (error) { serverError(res, error, 'Delete error'); }
});

module.exports = router;
