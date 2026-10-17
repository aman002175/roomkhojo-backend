const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const mongoose = require('mongoose');
const Room = require('../models/Room');
const User = require('../models/User');
const Settings = require('../models/Settings');
const upload = require('../config/cloudinary');
const { requireAuth, requireAdmin } = require('../middleware/auth');

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

// 📍 Landmarks parse+validate (max 8, naam 120 chars, valid coords)
const cleanLandmarks = (raw) => {
  try {
    const arr = JSON.parse(raw || '[]');
    if (!Array.isArray(arr)) return [];
    return arr.slice(0, 8).map((l) => ({
      name: String((l && l.name) || '').trim().slice(0, 120),
      cat: String((l && l.cat) || '').trim().slice(0, 30),
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
  const n = Number(val);
  return Number.isFinite(n) && n >= min && n <= max ? n : null;
};

const serverError = (res, err, label) => {
  console.error(`${label}:`, err.message);
  res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
};

// 🛡️ P1 #15 fix: URL me galat id (e.g. /api/rooms/abc/edit) → CastError 500 ki jagah clean 404
router.param('id', (req, res, next, id) => {
  if (!mongoose.isValidObjectId(id)) {
    return res.status(404).json({ success: false, message: 'Room nahi mila.' });
  }
  next();
});

// --- ADMIN: saare rooms (ADMIN ONLY — pehle x-admin-secret header tha, ab JWT) ---
router.get('/admin/all', requireAdmin, async (req, res) => {
  try {
    // P1 #19: unbounded dump band — cap 1000 + lean (admin list isse chhoti hai)
    const rooms = await Room.find().sort({ createdAt: -1 }).limit(1000).lean();
    res.status(200).json({ success: true, rooms });
  } catch (error) { serverError(res, error, 'Admin-all error'); }
});

// --- ADMIN: purane-ad claim requests (#13 fix — mobile match hui hain, admin verify kare) ---
router.get('/admin/claims', requireAdmin, async (req, res) => {
  try {
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
    res.json({ success: true, message: 'Claim request reject kar di.' });
  } catch (error) { serverError(res, error, 'Claim reject error'); }
});

// --- POST NEW AD (LOGIN REQUIRED — C1/C6 fix) ---
// userId/ownerName token se aate hain (client-spoofing band).
// isPromoted client se NAHI liya jaata — promo sirf admin approve ke baad lagta hai.
// paymentCode server generate karta hai (client ka random code nahi).
router.post('/', requireAuth, upload.array('images', 6), async (req, res) => {
  // P1 #21 tracking: save fail hone par upload hui photos orphan na rahein
  let uploadedThisRequest = [];
  let savedOk = false;
  try {
    const { title, price, type, category, landmark, mobile, description, lng, lat, promoPlan, paymentRef, paymentCode, bannerRequested, bannerRef, landmarks } = req.body || {};

    if (!title || !price || !type || !category) {
      return res.status(400).json({ success: false, message: 'Title, Price, Type aur Category zaroori hain.' });
    }
    const cleanAudience = cleanType(type);
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
    const cleanLng = toCoord(lng, -180, 180);
    const cleanLat = toCoord(lat, -90, 90);
    if (cleanLng === null || cleanLat === null) {
      return res.status(400).json({ success: false, message: 'Map par sahi location select karein.' });
    }
    const requestedPlan = ['regular', '7', '15', '30'].includes(promoPlan) ? promoPlan : 'regular';

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
      uploadedThisRequest = uploaded.map((u) => u.secure_url).filter(Boolean);
      imageUrls = uploadedThisRequest;
    }

    const newRoom = new Room({
      title: String(title).trim(),
      price: cleanPriceVal,
      type: cleanAudience,
      category: String(category).trim(),
      landmark: String(landmark || '').trim(),
      mobile: cleanPhone,
      description: String(description || '').trim(),
      lng: cleanLng,
      lat: cleanLat,
      isPromoted: false, // Hamesha false — admin approve karega (C6)
      promoPlan: 'regular',
      promoRequested: requestedPlan,
      paymentRef: String(paymentRef || '').trim().slice(0, 64),
      // 🎯 Banner add-on request (activate sirf admin karega)
      bannerRequested: bannerRequested === 'true' || bannerRequested === true,
      bannerRef: String(bannerRef || paymentRef || '').trim().slice(0, 64),
      isBannerActive: false,
      // 📍 User-selected nearby landmarks
      landmarks: cleanLandmarks(landmarks),
      userId: req.user.id,
      ownerName,
      image: imageUrls[0] || '',
      images: imageUrls,
      paymentCode: cleanPayCode(paymentCode) || newPayCode()
    });

    // 🟢 Auto-approve: sirf FREE/regular ads, aur sirf jab admin ne toggle ON kiya ho.
    // Promo/banner wale HAMESHA pending (payment verify hoga).
    const wantsPaid = requestedPlan !== 'regular' || newRoom.bannerRequested;
    if (!wantsPaid) {
      const appSettings = await Settings.findOne({ key: 'app_settings' });
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
    // P1 #19: unbounded dump band — cap 1000 + lean (map par isse zyada pins ka koi fayda nahi)
    const rooms = await Room.find({ isApproved: true, isActive: true })
      .select('-reportedIPs -paymentRef -paymentCode -bannerRef -viewKeys')
      .sort({ createdAt: -1 }).limit(1000).lean();
    res.status(200).json({ success: true, count: rooms.length, rooms });
  } catch (error) { serverError(res, error, 'Live-rooms error'); }
});

// --- LIVE BANNER ADS (top strip — public) ---
router.get('/banners', async (req, res) => {
  try {
    const now = new Date();
    const rooms = await Room.find({
      isApproved: true,
      isActive: true,
      isBannerActive: true,
      $or: [{ bannerExpires: null }, { bannerExpires: { $gte: now } }]
    }).select('-reportedIPs -paymentRef -paymentCode -bannerRef -viewKeys').sort({ createdAt: -1 }).limit(50).lean(); // P1 #19 (top strip chhota hota hai)
    res.json({ success: true, count: rooms.length, rooms });
  } catch (error) { serverError(res, error, 'Banners error'); }
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
    res.json({ success: true, message: approve ? 'Banner live ho gaya!' : 'Banner hata diya gaya.', room });
  } catch (error) { serverError(res, error, 'Banner error'); }
});

// User Dashboard Ads (SELF OR ADMIN — H1 fix, pehle koi bhi kisi ka dekh sakta tha)
router.get('/user/:userId', requireAuth, async (req, res) => {
  try {
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
router.put('/:id/edit', requireAuth, upload.array('images', 6), async (req, res) => {
  // P1 #21 tracking: edit fail hone par nayi upload hui photos orphan na rahein
  let uploadedThisRequest = [];
  let savedOk = false;
  try {
    const room = await Room.findById(req.params.id);
    if (!room) return res.status(404).json({ success: false, message: 'Room not found' });
    if (!canModify(room, req.user)) {
      return res.status(403).json({ success: false, message: 'Access Denied! Ye ad aapka nahi hai.' });
    }

    if (req.body.title) room.title = String(req.body.title).trim();
    if (req.body.price) {
      const cleanPriceVal = cleanPrice(req.body.price); // P1 #24
      if (!cleanPriceVal) return res.status(400).json({ success: false, message: 'Price sirf number hona chahiye (jaise 3000).' });
      room.price = cleanPriceVal;
    }
    if (req.body.type) {
      const cleanAudience = cleanType(req.body.type);
      if (!cleanAudience) return res.status(400).json({ success: false, message: 'Audience (Boys/Girls/Family/Anyone) sahi chuno.' });
      room.type = cleanAudience;
    }
    if (req.body.category) room.category = String(req.body.category).trim();
    if (req.body.landmark !== undefined) room.landmark = String(req.body.landmark).trim();
    if (req.body.mobile) {
      const cleanPhone = cleanMobile(req.body.mobile);
      if (!cleanPhone) return res.status(400).json({ success: false, message: 'Sahi 10-digit mobile number daliye.' });
      room.mobile = cleanPhone;
    }
    if (req.body.description !== undefined) room.description = String(req.body.description).trim();
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
      uploadedThisRequest = uploaded.map((u) => u.secure_url).filter(Boolean);
      newUrls = uploadedThisRequest;
    }
    const finalGallery = [...keepList, ...newUrls].slice(0, 6);
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
    const reqPlanKey = room.promoRequested && room.promoRequested !== 'regular' ? `promo${room.promoRequested}` : 'regular';
    room.paymentAmount = Number(pricing[reqPlanKey] || 0) || 0;

    if (room.promoRequested && room.promoRequested !== 'regular') {
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
    res.status(200).json({ success: true, message: 'Room Approved!', room });
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
    room.promoRequested = promoPlan;
    room.paymentRef = String(paymentRef || '').trim().slice(0, 64);
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
// IP hash se dedupe (raw IP store nahi — privacy) + atomic $push/$inc (race-safe).
router.put('/:id/report-unavailable', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(404).json({ success: false, message: 'Room nahi mila.' });
    }
    const ipKey = crypto.createHash('sha1').update(String(req.ip || 'unknown')).digest('hex').slice(0, 24);
    const updated = await Room.findOneAndUpdate(
      { _id: req.params.id, reportedIPs: { $ne: ipKey } },
      { $push: { reportedIPs: { $each: [ipKey], $slice: -500 } }, $inc: { unavailableReportCount: 1 } },
      { new: true }
    );
    if (!updated) {
      const exists = await Room.exists({ _id: req.params.id });
      if (!exists) return res.status(404).json({ success: false, message: 'Room nahi mila.' });
      return res.status(429).json({ success: false, message: 'Aap ye report pehle hi kar chuke hain.' });
    }
    // 🛡️ C1: 3+ reports par ad AUTO-HIDE — race-safe (sirf tab jab abhi active ho)
    let hidden = false;
    if (updated.unavailableReportCount >= 3 && updated.isActive) {
      const r = await Room.updateOne({ _id: updated._id, isActive: true }, { $set: { isActive: false } });
      hidden = r.modifiedCount > 0;
    }
    res.status(200).json({
      success: true,
      message: hidden ? 'Report noted. Ad zyada reports par auto-hide ho gaya hai.' : 'Reported successfully',
      count: updated.unavailableReportCount,
      hidden
    });
  } catch (error) { serverError(res, error, 'Report error'); }
});

// --- AD VIEW COUNTER (public, D1) — server-side dedupe (IP+din), fail silent (UX na toote)
router.put('/:id/view', async (req, res) => {
  try {
    const day = new Date().toISOString().slice(0, 10);
    const viewKey = crypto.createHash('sha1').update(`${req.ip || 'unknown'}|${day}`).digest('hex').slice(0, 24);
    await Room.findOneAndUpdate(
      { _id: req.params.id, viewKeys: { $ne: viewKey } },
      { $push: { viewKeys: { $each: [viewKey], $slice: -3000 } }, $inc: { views: 1 } }
    );
    res.json({ success: true });
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
    await Room.findByIdAndDelete(req.params.id);
    // P1 #21: ad delete par uski saari photos Cloudinary se bhi hatao (bounded, best-effort)
    const galleryToDelete = [...(room.images || []), room.image].filter(Boolean);
    await upload.destroyByUrls(galleryToDelete).catch(() => {});
    res.status(200).json({ success: true, message: 'Room Deleted!' });
  } catch (error) { serverError(res, error, 'Delete error'); }
});

module.exports = router;
