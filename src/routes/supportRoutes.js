const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');
const router = express.Router();
const SupportTicket = require('../models/SupportTicket');
const upload = require('../config/cloudinary');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const { createLimiter } = require('../utils/rateStore');
const { cleanText } = require('../utils/security');

const CATEGORIES = ['Payment Issue', 'Ad Approval', 'Account & Login', 'Report Fake Ad', 'Other'];
const AUTH_ISSUES = {
  login: 'Login nahi ho raha',
  signup: 'Sign up nahi ho raha',
  otp: 'OTP nahi aa raha / galat',
  google: 'Google sign-in issue',
  other: 'Kuch aur account issue'
};
// Public form hai (user login hi nahi kar pa raha) — per-IP hourly limit + screenshot max 2MB.
const authHelpLimiter = createLimiter('auth-help', {
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: { success: false, message: 'Bahut zyada reports. Kripya 1 ghante baad try karein.' }
});
const isValidEmail = (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || '').trim());
const cleanPhone = (raw) => {
  const digits = String(raw || '').replace(/\D/g, '');
  const normalized = digits.length === 12 && digits.startsWith('91') ? digits.slice(2) : digits;
  return /^[6-9]\d{9}$/.test(normalized) ? normalized : '';
};

const serverError = (res, err, label) => {
  console.error(`${label}:`, err.message);
  res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
};

router.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// --- PUBLIC: login/signup troubleshooting (account banane/login karne se pehle bhi) ---
// Screenshot optional. Admin panel ke Support tab me ticket aata hai; admin email/phone se contact karega.
router.post('/auth-help', authHelpLimiter, upload.single('images'), async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const body = req.body || {};
    const issueType = Object.prototype.hasOwnProperty.call(AUTH_ISSUES, body.issueType) ? body.issueType : 'other';
    const cleanMsg = cleanText(body.message, 2000);
    if (cleanMsg.length < 10) {
      return res.status(400).json({ success: false, message: 'Dikkat thode detail me likhein (min 10 characters).' });
    }
    const rawEmail = cleanText(body.contactEmail, 120).toLowerCase();
    const email = isValidEmail(rawEmail) ? rawEmail : '';
    const phone = cleanPhone(body.contactPhone);
    if (!email && !phone) {
      return res.status(400).json({ success: false, message: 'Reply ke liye sahi email ya 10-digit mobile number dalein.' });
    }
    let imageUrl = '';
    if (req.file) {
      try {
        const uploaded = await upload.uploadBufferToCloudinary(req.file);
        imageUrl = uploaded.secure_url || '';
      } catch (uploadErr) {
        // Screenshot fail ho toh bhi complaint save — user ko dobara form na bharna pade.
        console.error('Auth-help photo upload failed (ticket bina photo):', uploadErr.message);
      }
    }
    const contactKey = email || phone;
    const guestId = 'guest:' + crypto.createHash('sha256').update(contactKey).digest('hex').slice(0, 32);
    const ticket = await SupportTicket.create({
      userId: guestId,
      userName: 'Auth Help (Guest)',
      userEmail: email,
      contactPhone: phone,
      source: 'auth-help',
      category: 'Account & Login',
      message: `[${AUTH_ISSUES[issueType]}] ${cleanMsg}`,
      image: imageUrl
    });
    res.status(201).json({ success: true, message: 'Report admin ko bhej di gayi. Admin aapke email/mobile par contact karega.', ticket });
  } catch (error) { serverError(res, error, 'Auth-help ticket error'); }
});

// --- USER: naya ticket (login zaroori, photo optional) ---
router.post('/', requireAuth, upload.single('images'), async (req, res) => {
  try {
    const { category } = req.body || {};
    if (!CATEGORIES.includes(category)) {
      return res.status(400).json({ success: false, message: 'Sahi category chuno.' });
    }
    const cleanMsg = cleanText(req.body && req.body.message, 2000);
    if (cleanMsg.length < 5) {
      return res.status(400).json({ success: false, message: 'Apni dikkat thode detail me likho (min 5 letters).' });
    }
    let imageUrl = '';
    if (req.file) {
      try {
        const uploaded = await upload.uploadBufferToCloudinary(req.file);
        imageUrl = uploaded.secure_url || '';
      } catch (uploadErr) {
        // Photo fail ho toh bhi complaint REGISTER hogi (bina photo) — kabhi 500 nahi
        console.error('Ticket-photo upload failed (ticket bina photo save hoga):', uploadErr.message);
      }
    }
    const ticket = await SupportTicket.create({
      userId: req.user.id,
      userName: req.user.role === 'admin' ? 'Admin' : '',
      userEmail: req.user.email || '',
      category,
      message: cleanMsg,
      image: imageUrl
    });
    res.status(201).json({ success: true, message: 'Complaint mil gayi! Admin jald reply karega.', ticket });
  } catch (error) { serverError(res, error, 'Ticket-create error'); }
});

// --- USER: apne tickets (replies ke saath) ---
router.get('/mine', requireAuth, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({ userId: req.user.id }).sort({ updatedAt: -1 });
    res.json({ success: true, tickets });
  } catch (error) { serverError(res, error, 'My-tickets error'); }
});

// --- USER: apne ticket par jawab do (two-way thread) ---
router.post('/:id/reply', requireAuth, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(404).json({ success: false, message: 'Ticket nahi mila.' });
    }
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) return res.status(404).json({ success: false, message: 'Ticket nahi mila.' });
    if (req.user.role !== 'admin' && ticket.userId !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Access Denied!' });
    }
    if (ticket.status === 'closed') {
      return res.status(400).json({ success: false, message: 'Ye ticket closed hai.' });
    }
    const text = cleanText((req.body || {}).text, 2000);
    if (text.length < 1) {
      return res.status(400).json({ success: false, message: 'Jawab khaali nahi ho sakta.' });
    }
    ticket.replies.push({ by: req.user.role === 'admin' ? 'admin' : 'user', text });
    if (req.user.role !== 'admin') ticket.status = 'open'; // user ne likha = phir se khula
    await ticket.save();
    res.json({ success: true, message: 'Jawab bhej diya.', ticket });
  } catch (error) { serverError(res, error, 'Reply error'); }
});

// --- ADMIN: saare tickets ---
router.get('/admin/all', requireAdmin, async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const tickets = await SupportTicket.find().sort({ updatedAt: -1 }).limit(1000);
    const openCount = await SupportTicket.countDocuments({ status: 'open' });
    res.json({ success: true, openCount, tickets });
  } catch (error) { serverError(res, error, 'Admin-tickets error'); }
});

// --- ADMIN: status badlo (open/closed) ---
router.patch('/admin/:id/status', requireAdmin, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(404).json({ success: false, message: 'Ticket nahi mila.' });
    }
    const { status } = req.body || {};
    if (!['open', 'closed'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Status open ya closed ho.' });
    }
    const ticket = await SupportTicket.findByIdAndUpdate(
      req.params.id, { status }, { new: true }
    );
    if (!ticket) return res.status(404).json({ success: false, message: 'Ticket nahi mila.' });
    res.json({ success: true, message: `Ticket ${status} kar diya.`, ticket });
  } catch (error) { serverError(res, error, 'Ticket-status error'); }
});

module.exports = router;
