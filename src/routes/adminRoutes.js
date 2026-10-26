const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const mongoose = require('mongoose');
const { createLimiter } = require('../utils/rateStore'); // Upstash-ready
const Admin = require('../models/Admin');
const Settings = require('../models/Settings');
const User = require('../models/User');
const Room = require('../models/Room');
const Favorite = require('../models/Favorite');
const ActionOtp = require('../models/ActionOtp');
const SignupRequest = require('../models/SignupRequest');
const ConsentLog = require('../models/ConsentLog');
const { signAdmin, requireAdmin } = require('../middleware/auth');
const { cleanText, passwordProblem } = require('../utils/security');
const { logAudit, archiveRooms } = require('../utils/audit');

// Login par brute-force protection: 15 min me max 10 attempts (H4)
// 🚦 Upstash Redis env set hone par shared store (serverless-safe)
const loginLimiter = createLimiter('admin-login', {
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: 'Bahut zyada login attempts. 15 minute baad try karein.' }
});

router.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// --- Default Admin Seed (SAFE VERSION — C3 fix) ---
// Normal: sirf tabhi banta hai jab DB me koi admin na ho.
// Recovery: ADMIN_FORCE_RESET=true + Settings.forceResetAt khali ho tabhi ek
// baar chalta hai (password bhoolne par: Vercel me naya password + flag set
// karo, redeploy karo, login karke password badlo, flag hata do).
// 🔐 P0 fix: one-shot marker — flag Vercel me bhool jao toh bhi har cold
// start par admins delete nahi honge.
const seedAdmin = async () => {
  try {
    const forceReset = process.env.ADMIN_FORCE_RESET === 'true';
    const configuredPassword = process.env.ADMIN_INITIAL_PASSWORD;
    const isProd = process.env.NODE_ENV === 'production' || Boolean(process.env.VERCEL);
    const count = await Admin.countDocuments();
    if (count > 0 && !forceReset) return; // Pehle se admin hai → kuch mat karo
    if (forceReset) {
      const settings = await Settings.findOne({ key: 'app_settings' });
      if (settings && settings.forceResetAt) {
        console.log('⚠️ ADMIN_FORCE_RESET skip — ye recovery pehle hi use ho chuki hai. Dobara chahiye toh DB me settings.forceResetAt = null karein.');
        return;
      }
      if (!configuredPassword) {
        console.error('❌ ADMIN_FORCE_RESET ke liye ADMIN_INITIAL_PASSWORD zaroori hai — admins delete nahi kiye.');
        return;
      }
    }
    if (!configuredPassword && isProd) {
      console.error('❌ ADMIN_INITIAL_PASSWORD set nahi hai — production me admin seed nahi banega.');
      return;
    }
    const initialPassword = configuredPassword || crypto.randomBytes(12).toString('hex');
    const seedPasswordProblem = passwordProblem(initialPassword, 8);
    if (seedPasswordProblem) {
      console.error(`❌ Admin seed password weak hai: ${seedProblem}`);
      return;
    }
    if (forceReset) await Admin.deleteMany({});
    await Admin.create({
      username: cleanText(process.env.ADMIN_INITIAL_USERNAME || 'admin', 60) || 'admin',
      password: initialPassword // Model hook ise hash karke save karega
    });
    if (forceReset) {
      await Settings.findOneAndUpdate({ key: 'app_settings' }, { forceResetAt: new Date() }, { upsert: true });
    }
    console.log('✅ Default admin account seed ho gaya.');
    if (!configuredPassword) {
      console.log('🔑 Dev admin password generated tha — ise terminal se copy karke turant badlein.');
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
const MAX_LOGIN_FAILURES = 5;
const LOGIN_LOCK_MS = 15 * 60 * 1000;

router.post('/login', loginLimiter, async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const username = cleanText(req.body && req.body.username, 60);
    const password = req.body && req.body.password;
    if (!username || typeof password !== 'string') {
      return res.status(400).json({ success: false, message: 'Username aur password dono zaroori hain.' });
    }
    if (password.length > 200) {
      return res.status(400).json({ success: false, message: 'Username ya Password galat hai!' });
    }
    const admin = await Admin.findOne({ username });
    if (!admin) {
      return res.status(401).json({ success: false, message: 'Username ya Password galat hai!' });
    }
    if (admin.lockedUntil && admin.lockedUntil > new Date()) {
      return res.status(429).json({ success: false, message: 'Bahut zyada galat attempts. 15 minute baad try karein.' });
    }
    if (!(await admin.comparePassword(password))) {
      admin.failedLoginAttempts = (admin.failedLoginAttempts || 0) + 1;
      if (admin.failedLoginAttempts >= MAX_LOGIN_FAILURES) {
        admin.lockedUntil = new Date(Date.now() + LOGIN_LOCK_MS);
        admin.failedLoginAttempts = 0;
      }
      await admin.save();
      await logAudit(req, { action: 'admin.login_failed', targetType: 'admin', targetId: admin._id, actorId: admin._id, actorRole: 'system' });
      return res.status(401).json({ success: false, message: 'Username ya Password galat hai!' });
    }
    if (admin.failedLoginAttempts || admin.lockedUntil) {
      admin.failedLoginAttempts = 0;
      admin.lockedUntil = null;
      await admin.save();
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
    res.set('Cache-Control', 'no-store');
    const body = req.body || {};
    const oldPassword = typeof body.oldPassword === 'string' ? body.oldPassword : '';
    const newPassword = body.newPassword === undefined ? '' : body.newPassword;
    const newUsername = body.newUsername === undefined ? '' : body.newUsername;
    if (!oldPassword) {
      return res.status(400).json({ success: false, message: 'Purana password zaroori hai.' });
    }
    if (!newUsername && !newPassword) {
      return res.status(400).json({ success: false, message: 'Naya username ya password me se kuch dijiye.' });
    }
    const admin = await Admin.findById(req.user.id);
    if (!admin || !(await admin.comparePassword(oldPassword))) {
      return res.status(401).json({ success: false, message: 'Purana password galat hai!' });
    }
    if (newUsername !== '') {
      const cleanedUser = cleanText(newUsername, 40);
      if (!/^[A-Za-z0-9._-]{3,40}$/.test(cleanedUser)) {
        return res.status(400).json({ success: false, message: 'Username 3-40 characters ka ho (a-z, 0-9, ., -, _).' });
      }
      const taken = await Admin.findOne({ username: cleanedUser, _id: { $ne: admin._id } }).select('_id').lean();
      if (taken) {
        return res.status(409).json({ success: false, message: 'Ye username pehle se use ho raha hai.' });
      }
      admin.username = cleanedUser;
    }
    if (newPassword !== '') {
      const pwProblem = passwordProblem(newPassword, 12);
      if (pwProblem) return res.status(400).json({ success: false, message: pwProblem });
      if (newPassword === oldPassword) {
        return res.status(400).json({ success: false, message: 'Naya password purane se alag hona chahiye.' });
      }
      admin.password = newPassword;
    }
    admin.tokenVersion = (admin.tokenVersion || 0) + 1;
    admin.failedLoginAttempts = 0;
    admin.lockedUntil = null;
    await admin.save();
    await logAudit(req, { action: 'admin.credentials_changed', targetType: 'admin', targetId: admin._id });
    const token = signAdmin(admin);
    res.json({ success: true, message: 'Credentials successfully updated!', token });
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

const publicSettings = (raw) => {
  if (!raw) return null;
  const settings = raw.toObject ? raw.toObject() : raw;
  const { forceResetAt, __v, ...safe } = settings;
  return safe;
};

// --- Get App Settings API (public — categories/facilities sabko chahiye) ---
router.get('/settings', async (req, res) => {
  try {
    const settings = await Settings.findOne({ key: 'app_settings' }).lean();
    res.set('Cache-Control', 'public, max-age=300');
    res.json({ success: true, settings: publicSettings(settings) });
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

const cleanStringList = (value, maxItems, maxLen) => {
  if (!Array.isArray(value) || value.length > maxItems) return null;
  const out = [];
  for (const item of value) {
    if (typeof item !== 'string') return null;
    const clean = cleanText(item, maxLen);
    if (!clean) continue;
    if (!out.includes(clean)) out.push(clean);
  }
  return out;
};

const cleanMoney = (value, max = 100000) => {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const n = Number(String(value).replace(/[^\d.]/g, ''));
  if (!Number.isFinite(n) || n < 0 || n > max) return null;
  return String(Math.round(n));
};

const cleanPricing = (pricing) => {
  if (!pricing || typeof pricing !== 'object' || Array.isArray(pricing)) return null;
  const out = {};
  for (const key of ['regular', 'promo7', 'promo15', 'promo30', 'bannerPrice', 'serviceDailyRate']) {
    if (pricing[key] === undefined) continue;
    const value = cleanMoney(pricing[key]);
    if (value === null) return null;
    out[key] = value;
  }
  if (pricing.bannerDays !== undefined) {
    const days = Number(pricing.bannerDays);
    if (!Number.isInteger(days) || days < 1 || days > 365) return null;
    out.bannerDays = String(days);
  }
  if (pricing.upiId !== undefined) {
    const upi = String(pricing.upiId || '').trim();
    if (!/^[A-Za-z0-9._-]{2,64}@[A-Za-z]{2,32}$/.test(upi)) return null;
    out.upiId = upi;
  }
  for (const key of Object.keys(pricing)) {
    if (!['regular', 'promo7', 'promo15', 'promo30', 'bannerPrice', 'bannerDays', 'serviceDailyRate', 'upiId'].includes(key)) return null;
  }
  return out;
};

router.post('/settings', requireAdmin, async (req, res) => {
  try {
    const { categories, facilities, pricing, adminPath, autoApproveFree, contactRevealLimit } = req.body || {};

    const update = {};
    if (categories !== undefined) {
      const clean = cleanStringList(categories, 20, 40);
      if (!clean) return res.status(400).json({ success: false, message: 'Categories list sahi nahi hai (max 20, har item 40 chars).' });
      update.categories = clean;
    }
    if (facilities !== undefined) {
      const clean = cleanStringList(facilities, 30, 40);
      if (!clean) return res.status(400).json({ success: false, message: 'Facilities list sahi nahi hai (max 30, har item 40 chars).' });
      update.facilities = clean;
    }
    if (pricing !== undefined) {
      const clean = cleanPricing(pricing);
      if (!clean) return res.status(400).json({ success: false, message: 'Pricing values sahi nahi hain.' });
      const existing = await Settings.findOne({ key: 'app_settings' }).lean();
      update.pricing = { ...((existing && existing.pricing) || {}), ...clean };
    }
    if (autoApproveFree !== undefined) update.autoApproveFree = autoApproveFree === true || autoApproveFree === 'true';
    if (contactRevealLimit !== undefined) {
      const limit = Number(contactRevealLimit);
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        return res.status(400).json({ success: false, message: 'Number reveal limit 1 se 100 ke beech honi chahiye.' });
      }
      update.contactRevealLimit = limit;
    }
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
      { new: true, upsert: true, runValidators: true }
    );
    await logAudit(req, { action: 'admin.settings_updated', targetType: 'settings', targetId: 'app_settings', details: { fields: Object.keys(update) } });

    res.json({ success: true, message: 'Settings securely updated!', settings: publicSettings(settings) });
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
    const { email, dryRun } = req.body || {};
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
    // 🛡️ #55: dry-run — pehle sirf preview (count + sample titles), koi write nahi
    if (dryRun) {
      const orphanCount = await Room.countDocuments({ userId: { $in: orphanIds } });
      const sample = await Room.find({ userId: { $in: orphanIds } }).select('title mobile').sort({ createdAt: -1 }).limit(5).lean();
      return res.json({
        success: true,
        dryRun: true,
        count: orphanCount,
        sample: sample.map((r) => ({ title: r.title, mobile: r.mobile })),
        message: `${orphanCount} puraane ads ${user.email} se link honge.`
      });
    }
    const result = await Room.updateMany(
      { userId: { $in: orphanIds } },
      { $set: { userId: user._id.toString() } }
    );
    await logAudit(req, { action: 'admin.rooms_migrated', targetType: 'user', targetId: user._id, details: { migrated: result.modifiedCount } });
    res.json({ success: true, migrated: result.modifiedCount, message: `${result.modifiedCount} puraane ads ${user.email} se link ho gaye! Dashboard refresh karo.` });
  } catch (error) {
    console.error('Migrate error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// 📊 #56: Admin stats — SERVER aggregation (promo 15/30 ka sahi price, banner revenue included).
// NOTE: revenue sirf un ads ka jinka paymentAmount record hua hai (ye fix lagne ke baad ke approvals).
// Puraane ads free/manual the — unki amount history reliable nahi thi, isliye unhe 0 mana jata hai.
router.get('/stats', requireAdmin, async (req, res) => {
  try {
    const rooms = await Room.find({})
      .select('userId listingType isApproved isPromoted promoPlan promoRequested paymentAmount bannerAmount isBannerActive serviceExpiresAt createdAt')
      .lean();
    const acc = {
      totalAds: rooms.length, liveAds: 0, pendingAds: 0, expiredAds: 0, promoAds: 0, bannerActive: 0,
      promoRevenue: 0, serviceRevenue: 0, bannerRevenue: 0,
      byPlan: { regular: 0, promo7: 0, promo15: 0, promo30: 0 },
      userIds: new Set()
    };
    const now = new Date();
    rooms.forEach((r) => {
      const serviceExpired = r.listingType === 'service' && r.serviceExpiresAt && new Date(r.serviceExpiresAt) <= now;
      if (r.isApproved && !serviceExpired) acc.liveAds++;
      else if (!r.isApproved) acc.pendingAds++;
      else acc.expiredAds++;
      if (r.isPromoted) acc.promoAds++;
      if (r.isBannerActive) acc.bannerActive++;
      const amt = Number(r.paymentAmount) || 0;
      if (r.listingType === 'service') {
        acc.serviceRevenue += amt;
      } else {
        acc.promoRevenue += amt;
        if (r.promoPlan && ['7', '15', '30'].includes(String(r.promoPlan))) {
          acc.byPlan[`promo${r.promoPlan}`] += amt;
        } else if (r.isApproved) {
          acc.byPlan.regular += amt;
        }
      }
      acc.bannerRevenue += Number(r.bannerAmount) || 0;
      if (mongoose.Types.ObjectId.isValid(r.userId)) acc.userIds.add(String(r.userId));
    });
    const registeredUsers = await User.countDocuments();
    res.json({
      success: true,
      stats: {
        registeredUsers,
        totalAds: acc.totalAds,
        liveAds: acc.liveAds,
        pendingAds: acc.pendingAds,
        expiredAds: acc.expiredAds,
        promoAds: acc.promoAds,
        bannerActive: acc.bannerActive,
        uniqueUsers: acc.userIds.size,
        promoRevenue: acc.promoRevenue,
        serviceRevenue: acc.serviceRevenue,
        bannerRevenue: acc.bannerRevenue,
        totalRevenue: acc.promoRevenue + acc.serviceRevenue + acc.bannerRevenue,
        byPlan: acc.byPlan
      }
    });
  } catch (error) {
    console.error('Stats error:', error.message);
    res.status(500).json({ success: false, message: 'Stats load nahi hue. Baad me try karein.' });
  }
});

// --- ADMIN: registered users list (search + pagination + listing count) ---
router.get('/users', requireAdmin, async (req, res) => {
  try {
    const search = String(req.query.search || '').trim().slice(0, 80);
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const filter = {};
    if (search) {
      const safe = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const rx = new RegExp(safe, 'i');
      filter.$or = [{ name: rx }, { email: rx }, { phone: rx }];
    }
    const total = await User.countDocuments(filter);
    const users = await User.find(filter)
      .select('name email phone profilePic isGoogleUser status statusReason createdAt')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();
    const ids = users.map((u) => String(u._id));
    const counts = await Room.aggregate([
      { $match: { userId: { $in: ids } } },
      { $group: { _id: '$userId', count: { $sum: 1 } } }
    ]);
    const countMap = {};
    counts.forEach((c) => { countMap[String(c._id)] = c.count; });
    res.json({
      success: true,
      total,
      page,
      pages: Math.max(1, Math.ceil(total / limit)),
      users: users.map((u) => ({
        id: u._id,
        name: u.name,
        email: u.email,
        phone: u.phone || '',
        pic: u.profilePic || '',
        isGoogleUser: Boolean(u.isGoogleUser),
        status: u.status || 'active',
        statusReason: u.statusReason || '',
        createdAt: u.createdAt,
        listingCount: countMap[String(u._id)] || 0
      }))
    });
  } catch (error) {
    console.error('Admin users error:', error.message);
    res.status(500).json({ success: false, message: 'Users load nahi hue. Baad me try karein.' });
  }
});

// --- ADMIN: ek user ki profile + uske saare listings ---
router.get('/users/:id', requireAdmin, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(404).json({ success: false, message: 'User nahi mila.' });
    }
    const user = await User.findById(req.params.id)
      .select('name email phone profilePic isGoogleUser status statusReason statusChangedAt createdAt termsAcceptedAt termsVersion')
      .lean();
    if (!user) return res.status(404).json({ success: false, message: 'User nahi mila.' });
    const rooms = await Room.find({ userId: req.params.id })
      .select('title price type category listingType landmark mobile image images isApproved isActive isPromoted promoPlan createdAt')
      .sort({ createdAt: -1 })
      .limit(200)
      .lean();
    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone || '',
        pic: user.profilePic || '',
        isGoogleUser: Boolean(user.isGoogleUser),
        status: user.status || 'active',
        statusReason: user.statusReason || '',
        statusChangedAt: user.statusChangedAt || null,
        createdAt: user.createdAt,
        termsAcceptedAt: user.termsAcceptedAt || null,
        termsVersion: user.termsVersion || ''
      },
      rooms,
      stats: {
        total: rooms.length,
        live: rooms.filter((r) => r.isApproved && r.isActive).length,
        pending: rooms.filter((r) => !r.isApproved).length,
        services: rooms.filter((r) => r.listingType === 'service').length
      }
    });
  } catch (error) {
    console.error('Admin user detail error:', error.message);
    res.status(500).json({ success: false, message: 'User profile load nahi hui. Baad me try karein.' });
  }
});

// --- ADMIN: suspend / ban / activate (purane tokens turant invalid) ---
router.patch('/users/:id/status', requireAdmin, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(404).json({ success: false, message: 'User nahi mila.' });
    }
    const status = String((req.body || {}).status || '').trim();
    if (!['active', 'suspended', 'banned'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Status active, suspended ya banned hona chahiye.' });
    }
    const reason = cleanText((req.body || {}).reason, 200);
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: 'User nahi mila.' });
    user.status = status;
    user.statusReason = status === 'active' ? '' : reason;
    user.statusChangedAt = new Date();
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    await user.save();
    await logAudit(req, { action: 'admin.user_status', targetType: 'user', targetId: user._id, details: { status, reason } });
    const messages = {
      active: 'User account dobara activate ho gaya.',
      suspended: 'User account suspend ho gaya.',
      banned: 'User account ban ho gaya.'
    };
    res.json({ success: true, message: messages[status], user: { id: user._id, status: user.status, statusReason: user.statusReason } });
  } catch (error) {
    console.error('Admin user status error:', error.message);
    res.status(500).json({ success: false, message: 'Status update nahi hua. Baad me try karein.' });
  }
});

// --- ADMIN: user delete (account + ads + favorites cleanup) ---
router.delete('/users/:id', requireAdmin, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(404).json({ success: false, message: 'User nahi mila.' });
    }
    if (String((req.body || {}).confirm || '') !== 'DELETE') {
      return res.status(400).json({ success: false, message: 'Confirm ke liye DELETE bhejein.' });
    }
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: 'User nahi mila.' });
    const rooms = await Room.find({ userId: user._id }).limit(1001).lean();
    if (rooms.length > 1000) {
      return res.status(503).json({ success: false, message: 'User ke paas bahut zyada listings hain — bulk delete support se karein.' });
    }
    const archived = await archiveRooms(rooms, {
      deletedBy: req.user.id,
      deletedByRole: 'admin',
      reason: `admin user delete: ${user.email}`
    });
    if (rooms.length > 0 && archived < rooms.length) {
      return res.status(500).json({ success: false, message: 'Archive fail hua — delete safety ke liye rok diya.' });
    }
    const urls = [];
    rooms.forEach((r) => {
      if (r.image && /^https?:\/\//.test(r.image)) urls.push(r.image);
      (r.images || []).forEach((u) => { if (u && /^https?:\/\//.test(u)) urls.push(u); });
    });
    await Promise.all([
      Room.deleteMany({ userId: user._id }),
      Favorite.deleteMany({ userId: user._id }),
      ActionOtp.deleteMany({ userId: user._id }),
      SignupRequest.deleteOne({ email: String(user.email).toLowerCase().trim() }),
      ConsentLog.updateMany(
        { emailHash: require('crypto').createHash('sha256').update(String(user.email).toLowerCase().trim()).digest('hex'), withdrawnAt: null },
        { $set: { withdrawnAt: new Date() } }
      ),
      User.deleteOne({ _id: user._id })
    ]);
    try {
      const upload = require('../config/cloudinary');
      if (urls.length > 0) await upload.destroyByUrls(urls);
    } catch { /* images orphan maaf — account delete ho chuka */ }
    await logAudit(req, { action: 'admin.user_deleted', targetType: 'user', targetId: user._id, details: { email: user.email, rooms: rooms.length } });
    res.json({ success: true, message: `${user.name} ka account aur ${rooms.length} listings delete ho gaye.` });
  } catch (error) {
    console.error('Admin user delete error:', error.message);
    res.status(500).json({ success: false, message: 'User delete nahi hua. Baad me try karein.' });
  }
});

module.exports = router;
