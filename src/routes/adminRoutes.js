const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const Admin = require('../models/Admin');
const Settings = require('../models/Settings');
const User = require('../models/User');
const Room = require('../models/Room');
const { signAdmin, requireAdmin } = require('../middleware/auth');

// Login par brute-force protection: 15 min me max 10 attempts (H4)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: 'Bahut zyada login attempts. 15 minute baad try karein.' }
});

// --- Default Admin Seed (SAFE VERSION — C3 fix) ---
// Normal: sirf tabhi banta hai jab DB me koi admin na ho.
// Recovery: ADMIN_FORCE_RESET=true ho toh har start par env values se
// dobara banata hai (password bhoolne par: Vercel me naya password + ye
// flag set karo, redeploy karo, login karo, phir flag hata do).
const seedAdmin = async () => {
  try {
    const forceReset = process.env.ADMIN_FORCE_RESET === 'true';
    const count = await Admin.countDocuments();
    if (count > 0 && !forceReset) return; // Pehle se admin hai → kuch mat karo
    if (forceReset) await Admin.deleteMany({});
    const initialPassword = process.env.ADMIN_INITIAL_PASSWORD || crypto.randomBytes(12).toString('hex');
    await Admin.create({
      username: process.env.ADMIN_INITIAL_USERNAME || 'admin',
      password: initialPassword // Model hook ise hash karke save karega
    });
    console.log('✅ Default admin account banaya gaya (username: admin).');
    if (!process.env.ADMIN_INITIAL_PASSWORD) {
      console.log(`🔑 Generated admin password (login karke turant badal lena): ${initialPassword}`);
    }
  } catch (error) {
    console.log('⚠️ Admin Seed Failed:', error.message);
  }
};

if (mongoose.connection.readyState === 1) {
  seedAdmin();
} else {
  mongoose.connection.once('open', seedAdmin);
}

// --- Admin Login API (bcrypt + JWT — C4/C5 fix) ---
router.post('/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username aur password dono zaroori hain.' });
    }
    const admin = await Admin.findOne({ username });
    if (!admin || !(await admin.comparePassword(password))) {
      return res.status(401).json({ success: false, message: 'Username ya Password galat hai!' });
    }
    const token = signAdmin(admin);
    res.json({ success: true, message: 'Login successful', token });
  } catch (error) {
    console.error('Admin login error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// --- Admin Credentials Change API (JWT protected — C5 fix) ---
// Puraana password bcrypt se verify hota hai, sirf logged-in admin badal sakta hai.
router.post('/change-credentials', requireAdmin, async (req, res) => {
  try {
    const { oldPassword, newUsername, newPassword } = req.body || {};
    const admin = await Admin.findById(req.user.id);
    if (!admin || !(await admin.comparePassword(oldPassword))) {
      return res.status(401).json({ success: false, message: 'Purana password galat hai!' });
    }
    if (newUsername) admin.username = newUsername;
    if (newPassword) admin.password = newPassword; // Model hook hash karega
    await admin.save();
    res.json({ success: true, message: 'Credentials successfully updated!' });
  } catch (error) {
    console.error('Change-credentials error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// Default Settings Create Karein (Agar pehle se nahi hai)
const seedSettings = async () => {
  try {
    const count = await Settings.countDocuments();
    if (count === 0) await Settings.create({});
  } catch (err) { /* pehli baar DB na mile toh agli baar try hoga */ }
};
if (mongoose.connection.readyState === 1) seedSettings();
else mongoose.connection.once('open', seedSettings);

// --- Get App Settings API (public — categories/facilities sabko chahiye) ---
router.get('/settings', async (req, res) => {
  try {
    const settings = await Settings.findOne({ key: 'app_settings' });
    res.json({ success: true, settings });
  } catch (error) {
    console.error('Get settings error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// --- Update App Settings API (ADMIN ONLY — C2 fix) ---
// Pehle ye khula tha: koi bhi pricing/UPI ID badal sakta tha.
// Sirf bheje gaye fields update hote hain (partial update safe).
const RESERVED_PATHS = ['/', '/dashboard', '/about', '/terms', '/refund'];
const cleanAdminPath = (raw) => {
  let p = String(raw || '').trim();
  if (p && !p.startsWith('/')) p = `/${p}`;
  if (p.length < 2 || p.length > 64) return null;
  if (!/^\/[A-Za-z0-9-_]+$/.test(p)) return null;
  if (RESERVED_PATHS.includes(p.toLowerCase())) return null;
  return p;
};

router.post('/settings', requireAdmin, async (req, res) => {
  try {
    const { categories, facilities, pricing, adminPath, autoApproveFree } = req.body || {};

    const update = {};
    if (categories !== undefined) update.categories = categories;
    if (facilities !== undefined) update.facilities = facilities;
    if (pricing !== undefined) update.pricing = pricing;
    if (autoApproveFree !== undefined) update.autoApproveFree = autoApproveFree === true || autoApproveFree === 'true';
    if (adminPath !== undefined) {
      const clean = cleanAdminPath(adminPath);
      if (!clean) {
        return res.status(400).json({ success: false, message: 'Admin path galat hai. Sirf a-z, 0-9, -, _ (2-64 chars, / se shuru).' });
      }
      update.adminPath = clean;
    }

    const settings = await Settings.findOneAndUpdate(
      { key: 'app_settings' },
      update,
      { new: true, upsert: true }
    );

    res.json({ success: true, message: 'Settings securely updated!', settings });
  } catch (error) {
    console.error('🔥 SETTINGS ERROR:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// --- Purane ads migrate (ONE-TIME FIX) ---
// Puraani login IDs (Google-sub numbers, 'unknown') wale rooms ko
// email se mile user ki Mongo-ID par shift karta hai.
// Valid Mongo-ID wale rooms ko haath NAHI lagata (safe).
router.post('/migrate-rooms', requireAdmin, async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email zaroori hai.' });
    }
    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (!user) {
      return res.status(404).json({ success: false, message: 'Is email ka user nahi mila. Pehle us email se app me login karo.' });
    }
    const allIds = await Room.distinct('userId');
    const orphanIds = allIds.filter((id) => !mongoose.Types.ObjectId.isValid(id));
    if (orphanIds.length === 0) {
      return res.json({ success: true, migrated: 0, message: 'Koi puraana (bina-link) ad nahi mila. Sab linked hain.' });
    }
    const result = await Room.updateMany(
      { userId: { $in: orphanIds } },
      { $set: { userId: user._id.toString() } }
    );
    res.json({ success: true, migrated: result.modifiedCount, message: `${result.modifiedCount} puraane ads ${user.email} se link ho gaye! Dashboard refresh karo.` });
  } catch (error) {
    console.error('Migrate error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

module.exports = router;
