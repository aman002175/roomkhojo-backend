const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const Room = require('../models/Room');
const User = require('../models/User');
const upload = require('../config/cloudinary');
const { requireAuth, requireAdmin } = require('./auth');

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
router.post('/', requireAuth, upload.single('image'), async (req, res) => {
  try {
    const { title, price, type, category, landmark, mobile, description, lng, lat, promoPlan, paymentRef } = req.body || {};

    if (!title || !price || !type || !category) {
      return res.status(400).json({ success: false, message: 'Title, Price, Type aur Category zaroori hain.' });
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

    // Photo Cloudinary par upload karo (memory buffer se)
    let imageUrl = '';
    if (req.file) {
      const uploaded = await upload.uploadBufferToCloudinary(req.file);
      imageUrl = uploaded.secure_url || '';
    }

    const newRoom = new Room({
      title: String(title).trim(),
      price: String(price).trim(),
      type: String(type).trim(),
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
      userId: req.user.id,
      ownerName,
      image: imageUrl,
      paymentCode: 'RK-' + crypto.randomBytes(3).toString('hex').toUpperCase()
    });

    const savedRoom = await newRoom.save();
    res.status(201).json({ success: true, message: 'Ad submitted! Admin verification ke baad live hoga.', room: savedRoom });
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
router.put('/:id/edit', requireAuth, upload.single('image'), async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);
    if (!room) return res.status(404).json({ success: false, message: 'Room not found' });
    if (!canModify(room, req.user)) {
      return res.status(403).json({ success: false, message: 'Access Denied! Ye ad aapka nahi hai.' });
    }

    if (req.body.title) room.title = String(req.body.title).trim();
    if (req.body.price) room.price = String(req.body.price).trim();
    if (req.body.type) room.type = String(req.body.type).trim();
    if (req.body.category) room.category = String(req.body.category).trim();
    if (req.body.landmark !== undefined) room.landmark = String(req.body.landmark).trim();
    if (req.body.mobile) {
      const cleanPhone = cleanMobile(req.body.mobile);
      if (!cleanPhone) return res.status(400).json({ success: false, message: 'Sahi 10-digit mobile number daliye.' });
      room.mobile = cleanPhone;
    }
    if (req.body.description !== undefined) room.description = String(req.body.description).trim();

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

    // Nayi photo aayi ho toh Cloudinary par upload karke update karo
    if (req.file) {
      const uploaded = await upload.uploadBufferToCloudinary(req.file);
      if (uploaded.secure_url) room.image = uploaded.secure_url;
    }

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
      room.isPromoted = true;
      room.promoPlan = room.promoRequested;
    }

    // 🚨 TIMER LOCK: Sirf pehli baar approve hone par hi Expiry Date set hogi.
    if (room.isPromoted && room.promoPlan !== 'regular' && !room.expiryDate) {
      const days = parseInt(room.promoPlan, 10);
      if (Number.isFinite(days) && days > 0) {
        room.expiryDate = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
      }
    }

    await room.save();
    res.status(200).json({ success: true, message: 'Room Approved!', room });
  } catch (error) { serverError(res, error, 'Approve error'); }
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
