const express = require('express');
const router = express.Router();
const crypto = require('crypto');
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

// --- ADMIN: saare rooms (ADMIN ONLY — pehle x-admin-secret header tha, ab JWT) ---
router.get('/admin/all', requireAdmin, async (req, res) => {
  try {
    const rooms = await Room.find().sort({ createdAt: -1 });
    res.status(200).json({ success: true, rooms });
  } catch (error) { serverError(res, error, 'Admin-all error'); }
});

// --- POST NEW AD (LOGIN REQUIRED — C1/C6 fix) ---
// userId/ownerName token se aate hain (client-spoofing band).
// isPromoted client se NAHI liya jaata — promo sirf admin approve ke baad lagta hai.
// paymentCode server generate karta hai (client ka random code nahi).
router.post('/', requireAuth, upload.array('images', 6), async (req, res) => {
  try {
    const { title, price, type, category, landmark, mobile, description, lng, lat, promoPlan, paymentRef, bannerRequested, bannerRef, landmarks } = req.body || {};

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
      imageUrls = uploaded.map((u) => u.secure_url).filter(Boolean);
    }

    const newRoom = new Room({
      title: String(title).trim(),
      price: String(price).trim(),
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
      paymentCode: 'RK-' + crypto.randomBytes(3).toString('hex').toUpperCase()
    });

    // 🟢 Auto-approve: sirf FREE/regular ads, aur sirf jab admin ne toggle ON kiya ho.
    // Promo/banner wale HAMESHA pending (payment verify hoga).
    const wantsPaid = requestedPlan !== 'regular' || newRoom.bannerRequested;
    if (!wantsPaid) {
      const appSettings = await Settings.findOne({ key: 'app_settings' });
      if (appSettings && appSettings.autoApproveFree) newRoom.isApproved = true;
    }

    const savedRoom = await newRoom.save();
    const liveMsg = savedRoom.isApproved
      ? 'Ad live ho gaya! 🎉'
      : 'Ad submitted! Admin verification ke baad live hoga.';
    res.status(201).json({ success: true, message: liveMsg, room: savedRoom });
  } catch (error) { serverError(res, error, 'Post-ad error'); }
});

// --- LIVE ROOMS (MAP VIEW — public) ---
router.get('/', async (req, res) => {
  try {
    const currentDate = new Date();
    const rooms = await Room.find({
      isApproved: true,
      isActive: true,
      $or: [{ expiryDate: null }, { expiryDate: { $gte: currentDate } }]
    });
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
    }).sort({ createdAt: -1 });
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
    } else {
      room.isBannerActive = false;
      room.bannerExpires = null;
    }
    await room.save();
    res.json({ success: true, message: approve ? 'Banner live ho gaya! 🎯' : 'Banner hata diya gaya.', room });
  } catch (error) { serverError(res, error, 'Banner error'); }
});

// User Dashboard Ads (SELF OR ADMIN — H1 fix, pehle koi bhi kisi ka dekh sakta tha)
router.get('/user/:userId', requireAuth, async (req, res) => {
  try {
    if (req.user.role !== 'admin' && req.params.userId !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Access Denied!' });
    }
    const rooms = await Room.find({ userId: req.params.userId }).sort({ createdAt: -1 });
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
  try {
    const room = await Room.findById(req.params.id);
    if (!room) return res.status(404).json({ success: false, message: 'Room not found' });
    if (!canModify(room, req.user)) {
      return res.status(403).json({ success: false, message: 'Access Denied! Ye ad aapka nahi hai.' });
    }

    if (req.body.title) room.title = String(req.body.title).trim();
    if (req.body.price) room.price = String(req.body.price).trim();
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
      newUrls = uploaded.map((u) => u.secure_url).filter(Boolean);
    }
    const finalGallery = [...keepList, ...newUrls].slice(0, 6);
    room.images = finalGallery;
    room.image = finalGallery[0] || '';

    // 🚨 FRAUD PROTECTION: User ne edit kiya = Approve hategi aur Pending me jayega!
    room.isApproved = false;

    await room.save();
    res.status(200).json({ success: true, message: 'Ad updated! Sent to Admin for verification.', room });
  } catch (error) { serverError(res, error, 'Edit-room error'); }
});

// --- ADMIN APPROVE LOGIC (ADMIN ONLY — C1 fix) ---
// Promo tabhi lagta hai jab admin payment verify karke approve kare (C6 fix).
router.patch('/:id/approve', requireAdmin, async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);
    if (!room) return res.status(404).json({ success: false, message: 'Room nahi mila.' });
    room.isApproved = true;

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
    const { promoPlan, paymentRef } = req.body || {};
    if (!['7', '15', '30'].includes(promoPlan)) {
      return res.status(400).json({ success: false, message: 'Plan 7, 15 ya 30 din ka chuno.' });
    }
    room.promoRequested = promoPlan;
    room.paymentRef = String(paymentRef || '').trim().slice(0, 64);
    room.paymentCode = 'RK-' + crypto.randomBytes(3).toString('hex').toUpperCase();
    room.isApproved = false; // Dobara admin verification (payment check)
    await room.save();
    res.json({ success: true, message: 'Renew request bheji gayi! Payment verify hote hi ad live hoga.', room });
  } catch (error) { serverError(res, error, 'Renew error'); }
});

// --- REPORT UNAVAILABLE (spam-guard ke saath — M1 fix) ---
// Ek IP ek room ko ek hi baar report kar sakta hai.
router.put('/:id/report-unavailable', async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);
    if (!room) return res.status(404).json({ success: false, message: 'Room nahi mila.' });
    const ip = req.ip || 'unknown';
    if ((room.reportedIPs || []).includes(ip)) {
      return res.status(429).json({ success: false, message: 'Aap ye report pehle hi kar chuke hain.' });
    }
    room.reportedIPs = [...(room.reportedIPs || []), ip].slice(-500);
    room.unavailableReportCount = (room.unavailableReportCount || 0) + 1;
    await room.save();
    res.status(200).json({ success: true, message: 'Reported successfully', count: room.unavailableReportCount });
  } catch (error) { serverError(res, error, 'Report error'); }
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
    res.status(200).json({ success: true, message: 'Room Deleted!' });
  } catch (error) { serverError(res, error, 'Delete error'); }
});

module.exports = router;
