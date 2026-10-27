const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { createLimiter } = require('../utils/rateStore'); // Upstash-ready (env na ho toh MemoryStore)
const { OAuth2Client } = require('google-auth-library');
const User = require('../models/User');
const Otp = require('../models/Otp');
const Room = require('../models/Room');
const Favorite = require('../models/Favorite');
const ConsentLog = require('../models/ConsentLog');
const SignupRequest = require('../models/SignupRequest');
const ActionOtp = require('../models/ActionOtp');
const mongoose = require('mongoose');
const { signUser, requireAuth, requireAdmin } = require('../middleware/auth');
const { sendOtpEmail, sendOtpEmailFor } = require('../config/mailer');
const { hashOtp, hashResetToken, safeEqual, cleanText, passwordProblem } = require('../utils/security');
const { logAudit, archiveRooms } = require('../utils/audit');
const { PUBLIC_ROOM_EXCLUDE } = require('../utils/roomProjection');

// Brute-force protection (H4): login/google par 15 min me max 20,
// OTP maangne par 15 min me max 10 (plus per-email 3/15min andar)
// 🚦 createLimiter: Upstash Redis env set hone par shared store (serverless-safe)
const authLimiter = createLimiter('auth', {
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: 'Bahut zyada attempts. 15 minute baad try karein.' }
});
const otpRequestLimiter = createLimiter('otp-req', {
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: 'Bahut zyada OTP requests. 15 minute baad try karein.' }
});

// P1 #23: Google verify kabhi indefinite na latke — 8s timeout (hung Google → clean fail)
const verifyGoogleToken = (client, idToken) => Promise.race([
  client.verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT_ID }),
  new Promise((_, reject) => setTimeout(() => reject(new Error('GOOGLE_VERIFY_TIMEOUT')), 8000))
]);
// 🔐 P0 fix: verify-otp / reset-password par bhi limiter (pehle sirf per-record
// 5-attempts tha — attacker naye records bana ke brute force kar sakta tha)
const otpVerifyLimiter = createLimiter('otp-verify', {
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { success: false, message: 'Bahut zyada OTP attempts. 15 minute baad try karein.' }
});

const sha256 = (val) => crypto.createHash('sha256').update(val).digest('hex');
const publicUser = (user) => ({ id: user._id, name: user.name, email: user.email, phone: user.phone || '', pic: user.profilePic });
// Indian mobile: 10 digits, 6-9 se shuru (91 prefix accept)
const cleanPhone = (raw) => {
  const digits = String(raw || '').replace(/\D/g, '');
  const normalized = digits.length === 12 && digits.startsWith('91') ? digits.slice(2) : digits;
  return /^[6-9]\d{9}$/.test(normalized) ? normalized : null;
};
const accountBlockMessage = (user) => user && user.status === 'banned'
  ? 'Ye account permanently ban hai. Support se sampark karein.'
  : user && user.status === 'suspended'
    ? 'Ye account suspend hai. Support se sampark karein.'
    : '';
const maskEmail = (email) => {
  const [name, domain] = String(email || '').split('@');
  if (!name || !domain) return '';
  return `${name.slice(0, 2)}${'•'.repeat(Math.max(2, Math.min(6, name.length - 2)))}@${domain}`;
};
// Basic email-format check (nodemailer addressparser abuse + galat input rokne ke liye)
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());
// Legal documents ka current version — consent proof ke liye user par save hota hai
const TERMS_VERSION = '2026-10';
// Weak/common passwords — signup/reset/change par block (8+ chars base requirement)
const WEAK_PASSWORDS = new Set([
  'password', 'password1', 'password123', '12345678', '123456789', '1234567890',
  'qwerty123', 'qwertyuiop', 'iloveyou', 'admin123', 'welcome1', 'abc12345',
  'roomkhojo', 'roomkhojoo', 'letmein1', 'changeme', 'a1234567'
]);
const isWeakPassword = (pw) => {
  const v = String(pw || '');
  if (WEAK_PASSWORDS.has(v.toLowerCase())) return true;
  if (/^(.)\1+$/.test(v)) return true; // sab same character
  if (/^(0123456789|9876543210|abcdefgh|12345678|87654321)/.test(v.toLowerCase())) return true;
  return false;
};
const passwordError = (value, min = 8) => passwordProblem(value, min)
  || (isWeakPassword(value) ? 'Ye password bahut common hai. Strong password chunein.' : '');
const emailValue = (value) => {
  if (typeof value !== 'string') return '';
  const email = value.trim().toLowerCase();
  return email.length <= 254 ? email : '';
};
const otpValue = (value) => (typeof value === 'string' ? value.trim().slice(0, 10) : '');
const otpMatches = (input, stored) => Boolean(stored) && safeEqual(hashOtp(otpValue(input)), stored);
const lockMessage = 'Bahut zyada galat attempts. 15 minute baad try karein.';
const MAX_LOGIN_FAILURES = 5;
const LOGIN_LOCK_MS = 15 * 60 * 1000;

router.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// 1. Signup step-1: email OTP bhejo (account ab OTP verify hone par hi banta hai)
// Password ka bcrypt hash yahan short-lived SignupRequest me rakha jaata hai,
// taaki OTP full-page/reload ke baad bhi verify ho sake (plain password store nahi).
router.post('/signup/request-otp', otpRequestLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    const { name, phone, password } = body;
    const cleanEmail = emailValue(body.email);
    if (typeof name !== 'string' || !phone || !cleanEmail || typeof password !== 'string') {
      return res.status(400).json({ success: false, message: 'Naam, Mobile, Email aur Password charo zaroori hain.' });
    }
    if (!isValidEmail(cleanEmail)) {
      return res.status(400).json({ success: false, message: 'Sahi email address daliye.' });
    }
    const cleanName = cleanText(name, 60);
    if (cleanName.length < 2) {
      return res.status(400).json({ success: false, message: 'Naam 2-60 characters ka ho.' });
    }
    const cleanNumber = cleanPhone(phone);
    if (!cleanNumber) {
      return res.status(400).json({ success: false, message: 'Sahi 10-digit mobile number daliye.' });
    }
    const pwError = passwordError(password);
    if (pwError) {
      return res.status(400).json({ success: false, message: pwError });
    }
    if (await User.findOne({ email: cleanEmail })) {
      return res.status(409).json({ success: false, message: 'Ye Email pehle se registered hai. Sign in karein.' });
    }

    const now = new Date();
    const record = await SignupRequest.findOne({ email: cleanEmail });
    const inWindow = record && record.sendWindowStart && (now - record.sendWindowStart) < 15 * 60 * 1000;
    if (inWindow && (record.sendCount || 0) >= 3) {
      return res.status(429).json({ success: false, message: 'Bahut zyada OTP requests. 15 minute baad try karein.' });
    }
    const otp = String(crypto.randomInt(100000, 999999));
    const passwordHash = await bcrypt.hash(password, 10);
    await SignupRequest.findOneAndUpdate(
      { email: cleanEmail },
      {
        name: cleanName,
        phone: cleanNumber,
        passwordHash,
        otpHash: hashOtp(otp),
        otpExpires: new Date(Date.now() + 10 * 60 * 1000),
        attempts: 0,
        lastSentAt: now,
        sendCount: inWindow ? (record.sendCount || 0) + 1 : 1,
        sendWindowStart: inWindow ? record.sendWindowStart : now
      },
      { upsert: true, new: true }
    );
    try {
      await sendOtpEmailFor(cleanEmail, otp, 'signup');
    } catch (mailErr) {
      if (mailErr.code === 'EMAIL_NOT_CONFIGURED') {
        return res.status(503).json({ success: false, message: 'Email service abhi setup nahi hai. Admin se sampark karein.' });
      }
      console.error('Signup OTP mail failed:', mailErr.message);
      return res.status(502).json({ success: false, message: 'OTP email bhejne me dikkat aayi. Thodi der baad try karein.' });
    }
    res.json({ success: true, message: 'OTP aapke email par bhej diya gaya hai.', email: cleanEmail, maskedEmail: maskEmail(cleanEmail) });
  } catch (error) {
    console.error('Signup OTP error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// 1a. Signup OTP resend — full-page verify me password dobara nahi maangna padta.
router.post('/signup/resend-otp', otpRequestLimiter, async (req, res) => {
  try {
    const cleanEmail = emailValue(req.body && req.body.email);
    if (!cleanEmail || !isValidEmail(cleanEmail)) {
      return res.status(400).json({ success: false, message: 'Sahi email address daliye.' });
    }
    if (await User.findOne({ email: cleanEmail })) {
      return res.status(409).json({ success: false, message: 'Ye Email pehle se registered hai. Sign in karein.' });
    }
    const record = await SignupRequest.findOne({ email: cleanEmail });
    if (!record || !record.passwordHash) {
      return res.status(400).json({ success: false, message: 'Signup request nahi mili. Dobara signup shuru karein.' });
    }

    const now = new Date();
    const inWindow = record.sendWindowStart && (now - record.sendWindowStart) < 15 * 60 * 1000;
    if (inWindow && (record.sendCount || 0) >= 3) {
      return res.status(429).json({ success: false, message: 'Bahut zyada OTP requests. 15 minute baad try karein.' });
    }
    const otp = String(crypto.randomInt(100000, 999999));
    await SignupRequest.updateOne(
      { _id: record._id },
      {
        $set: {
          otpHash: hashOtp(otp),
          otpExpires: new Date(Date.now() + 10 * 60 * 1000),
          attempts: 0,
          lastSentAt: now,
          sendCount: inWindow ? (record.sendCount || 0) + 1 : 1,
          sendWindowStart: inWindow ? record.sendWindowStart : now
        }
      }
    );
    try {
      await sendOtpEmailFor(cleanEmail, otp, 'signup');
    } catch (mailErr) {
      if (mailErr.code === 'EMAIL_NOT_CONFIGURED') {
        return res.status(503).json({ success: false, message: 'Email service abhi setup nahi hai. Admin se sampark karein.' });
      }
      console.error('Signup OTP resend failed:', mailErr.message);
      return res.status(502).json({ success: false, message: 'OTP email bhejne me dikkat aayi. Thodi der baad try karein.' });
    }
    res.json({ success: true, message: 'Naya OTP aapke email par bhej diya gaya hai.', email: cleanEmail, maskedEmail: maskEmail(cleanEmail) });
  } catch (error) {
    console.error('Signup OTP resend error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// 1b. Signup step-2: OTP verify → account create + login token
router.post('/signup/verify-otp', otpVerifyLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    const cleanEmail = emailValue(body.email);
    const cleanOtp = otpValue(body.otp);
    if (!cleanEmail || !cleanOtp) {
      return res.status(400).json({ success: false, message: 'Email aur OTP dono zaroori hain.' });
    }
    const record = await SignupRequest.findOne({ email: cleanEmail });
    if (!record || !record.passwordHash || !record.otpHash || !record.otpExpires || record.otpExpires < new Date()) {
      return res.status(400).json({ success: false, message: 'OTP galat ya expire ho gaya hai. Naya OTP bhejein.' });
    }
    if ((record.attempts || 0) >= 5) {
      return res.status(429).json({ success: false, message: 'Bahut zyada galat attempts. Naya OTP bhejein.' });
    }
    if (!otpMatches(cleanOtp, record.otpHash)) {
      await SignupRequest.updateOne({ _id: record._id, attempts: { $lt: 5 } }, { $inc: { attempts: 1 } });
      return res.status(400).json({ success: false, message: 'OTP galat hai.' });
    }
    if (await User.findOne({ email: cleanEmail })) {
      await SignupRequest.deleteOne({ email: cleanEmail });
      return res.status(409).json({ success: false, message: 'Ye Email pehle se registered hai. Sign in karein.' });
    }
    const newUser = new User({
      name: record.name,
      email: cleanEmail,
      phone: record.phone,
      termsAcceptedAt: new Date(),
      termsVersion: TERMS_VERSION
    });
    newUser.password = record.passwordHash;
    newUser.$locals.passwordAlreadyHashed = true;
    await newUser.save();
    ConsentLog.create({ emailHash: sha256(cleanEmail), termsVersion: TERMS_VERSION }).catch(() => {});
    await SignupRequest.deleteOne({ email: cleanEmail });
    const token = signUser(newUser);
    res.status(201).json({ success: true, message: 'Email verify ho gaya — account ban gaya!', token, user: publicUser(newUser) });
  } catch (error) {
    console.error('Signup verify error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// Purana direct-signup route band: OTP ke bina account nahi banega.
router.post('/signup', authLimiter, (req, res) => {
  res.status(410).json({ success: false, message: 'App update karein — ab signup email OTP verify karne ke baad hota hai.' });
});

// 2. Email & Password Login (bcrypt compare + JWT — C4/C7 fix)
router.post('/login', authLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    const cleanEmail = emailValue(body.email);
    const password = body.password;
    if (!cleanEmail || typeof password !== 'string') {
      return res.status(400).json({ success: false, message: 'Email aur Password dono zaroori hain.' });
    }
    if (password.length > 200) {
      return res.status(401).json({ success: false, message: 'Email ya Password galat hai!' });
    }
    const user = await User.findOne({ email: cleanEmail });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Email ya Password galat hai!' });
    }
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      return res.status(429).json({ success: false, message: lockMessage });
    }
    if (!(await user.comparePassword(password))) {
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
      if (user.failedLoginAttempts >= MAX_LOGIN_FAILURES) {
        user.lockedUntil = new Date(Date.now() + LOGIN_LOCK_MS);
        user.failedLoginAttempts = 0;
      }
      await user.save();
      return res.status(401).json({ success: false, message: 'Email ya Password galat hai!' });
    }
    const blockedMsg = accountBlockMessage(user);
    if (blockedMsg) return res.status(403).json({ success: false, message: blockedMsg });
    let dirty = false;
    if (user.failedLoginAttempts || user.lockedUntil) {
      user.failedLoginAttempts = 0;
      user.lockedUntil = null;
      dirty = true;
    }
    // Login par checkbox tick tha → consent proof update (acceptedTerms FE bhejta hai)
    if (body.acceptedTerms === true) {
      if (user.termsVersion !== TERMS_VERSION) {
        ConsentLog.create({ emailHash: sha256(user.email.toLowerCase().trim()), termsVersion: TERMS_VERSION }).catch(() => {});
      }
      user.termsAcceptedAt = new Date();
      user.termsVersion = TERMS_VERSION;
      dirty = true;
    }
    if (dirty) await user.save();
    const token = signUser(user);
    res.json({ success: true, message: `Welcome ${user.name}!`, token, user: publicUser(user) });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// 3. Google Login API (ID-TOKEN SERVER PAR VERIFY — C7 fix)
// Frontend Google ka idToken bhejta hai; hum Google se verify karte hain.
// Client ke bheje {name,email} par bharosa NAHI hota (impersonation fix).
router.post('/google', authLimiter, async (req, res) => {
  try {
    const { idToken } = req.body || {};
    if (!idToken) {
      return res.status(400).json({ success: false, message: 'Google token missing hai.' });
    }
    if (!process.env.GOOGLE_CLIENT_ID) {
      console.error('❌ GOOGLE_CLIENT_ID .env me set nahi hai!');
      return res.status(500).json({ success: false, message: 'Server configuration error.' });
    }
    const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
    const ticket = await verifyGoogleToken(client, idToken); // P1 #23 (8s timeout)
    const payload = ticket.getPayload();
    const googleEmail = emailValue(payload && payload.email);
    if (!payload || !googleEmail || !payload.email_verified) {
      return res.status(401).json({ success: false, message: 'Google verification fail ho gayi.' });
    }

    let user = await User.findOne({ email: googleEmail });
    if (!user) {
      const picture = typeof payload.picture === 'string' && /^https:\/\//i.test(payload.picture)
        ? payload.picture.slice(0, 500)
        : '';
      user = await User.create({
        name: cleanText(payload.name, 60) || 'User',
        email: googleEmail,
        profilePic: picture,
        isGoogleUser: true,
        termsAcceptedAt: new Date(),
        termsVersion: TERMS_VERSION
      });
      ConsentLog.create({ emailHash: sha256(googleEmail), termsVersion: TERMS_VERSION }).catch(() => {});
    } else {
      const blockedMsg = accountBlockMessage(user);
      if (blockedMsg) return res.status(403).json({ success: false, message: blockedMsg });
    }
    if (user && req.body && req.body.acceptedTerms === true) {
      // Existing user: checkbox tick tha → consent proof refresh
      if (user.termsVersion !== TERMS_VERSION) {
        ConsentLog.create({ emailHash: sha256(user.email.toLowerCase()), termsVersion: TERMS_VERSION }).catch(() => {});
      }
      user.termsAcceptedAt = new Date();
      user.termsVersion = TERMS_VERSION;
      await user.save();
    }

    const token = signUser(user);
    res.json({ success: true, message: 'Google Login Successful!', token, user: publicUser(user) });
  } catch (error) {
    console.error('Google login error:', error.message);
    res.status(401).json({ success: false, message: 'Google verification fail ho gayi.' });
  }
});

// 4. Forgot Password — OTP bhejo (R1)
// User ho ya na ho, response same (account enumeration rokne ke liye).
router.post('/forgot-password', otpRequestLimiter, async (req, res) => {
  try {
    const cleanEmail = emailValue(req.body && req.body.email);
    if (!cleanEmail || !isValidEmail(cleanEmail)) {
      // Invalid format par bhi generic response (enumeration oracle nahi banana)
      return res.json({ success: true, message: 'Agar ye email registered hai toh OTP bhej diya gaya hai.' });
    }
    const done = () => res.json({ success: true, message: 'Agar ye email registered hai toh OTP bhej diya gaya hai.' });

    const user = await User.findOne({ email: cleanEmail });
    if (!user || user.isGoogleUser || !user.password) return done(); // Google users ka password reset nahi hota

    // Per-email abuse limit: 15 min window me max 3 OTP
    const now = new Date();
    const record = await Otp.findOne({ email: user.email });
    if (record && record.sendWindowStart && (now - record.sendWindowStart) < 15 * 60 * 1000) {
      // Same generic response (registered vs unregistered enumeration na ho)
      if ((record.sendCount || 0) >= 3) return done();
    }
    const inWindow = record && record.sendWindowStart && (now - record.sendWindowStart) < 15 * 60 * 1000;

    const otp = String(crypto.randomInt(100000, 999999)); // 6-digit
    await Otp.findOneAndUpdate(
      { email: user.email },
      {
        otpHash: hashOtp(otp),
        otpExpires: new Date(Date.now() + 10 * 60 * 1000),
        attempts: 0,
        resetTokenHash: null,
        resetExpires: null,
        lastSentAt: now,
        sendCount: inWindow ? (record.sendCount || 0) + 1 : 1,
        sendWindowStart: inWindow ? record.sendWindowStart : now
      },
      { upsert: true }
    );

    try {
      await sendOtpEmail(user.email, otp);
    } catch (mailErr) {
      if (mailErr.code === 'EMAIL_NOT_CONFIGURED') {
        return res.status(503).json({ success: false, message: 'Email service abhi setup nahi hai. Admin se sampark karein.' });
      }
      // SMTP auth/network fail — user ko saaf message (generic 500 nahi)
      console.error('OTP mail send failed:', mailErr.message);
      return res.status(502).json({ success: false, message: 'OTP email bhejne me dikkat aayi. Thodi der baad try karein.' });
    }
    return done();
  } catch (error) {
    console.error('Forgot-password error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// 5. OTP Verify — sahi hone par single-use reset token (R2)
router.post('/verify-otp', otpVerifyLimiter, async (req, res) => {
  try {
    const cleanEmail = emailValue(req.body && req.body.email);
    const cleanOtp = otpValue(req.body && req.body.otp);
    if (!cleanEmail || !cleanOtp) {
      return res.status(400).json({ success: false, message: 'Email aur OTP dono zaroori hain.' });
    }
    const record = await Otp.findOne({ email: cleanEmail });
    if (!record || !record.otpHash || !record.otpExpires || record.otpExpires < new Date()) {
      return res.status(400).json({ success: false, message: 'OTP galat ya expire ho gaya hai. Naya OTP mangwayein.' });
    }
    if ((record.attempts || 0) >= 5) {
      return res.status(429).json({ success: false, message: 'Bahut zyada galat attempts. Naya OTP mangwayein.' });
    }
    if (!otpMatches(cleanOtp, record.otpHash)) {
      await Otp.updateOne({ _id: record._id, attempts: { $lt: 5 } }, { $inc: { attempts: 1 } });
      return res.status(400).json({ success: false, message: 'OTP galat hai.' });
    }
    const resetToken = crypto.randomBytes(32).toString('hex');
    const consumed = await Otp.findOneAndUpdate(
      { _id: record._id, otpHash: record.otpHash, attempts: { $lt: 5 } },
      {
        $set: {
          resetTokenHash: hashResetToken(resetToken),
          resetExpires: new Date(Date.now() + 15 * 60 * 1000),
          otpHash: null,
          otpExpires: null,
          attempts: 0
        }
      }
    );
    if (!consumed) {
      return res.status(400).json({ success: false, message: 'OTP galat ya expire ho gaya hai. Naya OTP mangwayein.' });
    }
    res.json({ success: true, message: 'OTP verify ho gaya.', resetToken });
  } catch (error) {
    console.error('Verify-otp error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// 6. Reset Password — reset token se naya password (R3)
// Saare puraane sessions invalidate ho jaate hain (tokenVersion bump).
router.post('/reset-password', otpVerifyLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    const cleanEmail = emailValue(body.email);
    const resetToken = typeof body.resetToken === 'string' ? body.resetToken.trim().slice(0, 200) : '';
    const newPassword = body.newPassword;
    if (!cleanEmail || !resetToken || typeof newPassword !== 'string') {
      return res.status(400).json({ success: false, message: 'Email, token aur naya password zaroori hain.' });
    }
    const pwError = passwordError(newPassword);
    if (pwError) return res.status(400).json({ success: false, message: pwError });
    const record = await Otp.findOne({ email: cleanEmail });
    if (!record || !record.resetTokenHash || !record.resetExpires || record.resetExpires < new Date()
        || !safeEqual(hashResetToken(resetToken), record.resetTokenHash)) {
      return res.status(400).json({ success: false, message: 'Link galat ya expire ho gaya hai. Dobara OTP mangwayein.' });
    }
    const user = await User.findOne({ email: cleanEmail });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Account nahi mila.' });
    }
    const consumed = await Otp.findOneAndUpdate(
      { _id: record._id, resetTokenHash: record.resetTokenHash, resetExpires: { $gt: new Date() } },
      { $set: { resetTokenHash: null, resetExpires: null } }
    );
    if (!consumed) {
      return res.status(400).json({ success: false, message: 'Link galat ya expire ho gaya hai. Dobara OTP mangwayein.' });
    }
    user.password = newPassword; // Model hook hash karega
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    user.failedLoginAttempts = 0;
    user.lockedUntil = null;
    await user.save();
    res.json({ success: true, message: 'Password badal gaya hai. Dobara login karein.' });
  } catch (error) {
    console.error('Reset-password error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// 7. Logged-in user ka password change (R4)
router.post('/change-password', requireAuth, async (req, res) => {
  try {
    const body = req.body || {};
    const oldPassword = body.oldPassword;
    const newPassword = body.newPassword;
    if (typeof oldPassword !== 'string' || typeof newPassword !== 'string' || !oldPassword || !newPassword) {
      return res.status(400).json({ success: false, message: 'Puraana aur naya password dono zaroori hain.' });
    }
    const pwError = passwordError(newPassword);
    if (pwError) return res.status(400).json({ success: false, message: pwError });
    if (oldPassword.length > 200) {
      return res.status(401).json({ success: false, message: 'Puraana password galat hai!' });
    }
    const user = await User.findById(req.user.id);
    if (!user || !(await user.comparePassword(oldPassword))) {
      return res.status(401).json({ success: false, message: 'Puraana password galat hai!' });
    }
    user.password = newPassword;
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    await user.save();
    res.json({ success: true, message: 'Password update ho gaya hai.' });
  } catch (error) {
    console.error('Change-password error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// P2 #48 + #6: Email change — nayi email par OTP verify hone ke baad hi update
router.post('/change-email/request-otp', otpRequestLimiter, requireAuth, async (req, res) => {
  try {
    const body = req.body || {};
    const cleanEmail = emailValue(body.newEmail);
    const password = body.password;
    if (!cleanEmail || !isValidEmail(cleanEmail)) {
      return res.status(400).json({ success: false, message: 'Sahi naya email address daliye.' });
    }
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: 'Account nahi mila.' });
    if (!user.password || user.isGoogleUser) {
      return res.status(400).json({ success: false, message: 'Google account ka email Google se manage hota hai.' });
    }
    if (cleanEmail === user.email) {
      return res.status(400).json({ success: false, message: 'Ye wahi purana email hai.' });
    }
    if (typeof password !== 'string' || !password || password.length > 200 || !(await user.comparePassword(password))) {
      return res.status(401).json({ success: false, message: 'Password galat hai!' });
    }
    if (await User.findOne({ email: cleanEmail })) {
      return res.status(409).json({ success: false, message: 'Ye email kisi aur account par pehle se hai.' });
    }

    const now = new Date();
    const record = await ActionOtp.findOne({ userId: user._id, purpose: 'email-change' });
    const inWindow = record && record.sendWindowStart && (now - record.sendWindowStart) < 15 * 60 * 1000;
    if (inWindow && (record.sendCount || 0) >= 3) {
      return res.status(429).json({ success: false, message: 'Bahut zyada OTP requests. 15 minute baad try karein.' });
    }
    const otp = String(crypto.randomInt(100000, 999999));
    await ActionOtp.findOneAndUpdate(
      { userId: user._id, purpose: 'email-change' },
      {
        newEmail: cleanEmail,
        otpHash: hashOtp(otp),
        otpExpires: new Date(Date.now() + 10 * 60 * 1000),
        attempts: 0,
        lastSentAt: now,
        sendCount: inWindow ? (record.sendCount || 0) + 1 : 1,
        sendWindowStart: inWindow ? record.sendWindowStart : now
      },
      { upsert: true, new: true }
    );
    try {
      await sendOtpEmailFor(cleanEmail, otp, 'email-change');
    } catch (mailErr) {
      if (mailErr.code === 'EMAIL_NOT_CONFIGURED') {
        return res.status(503).json({ success: false, message: 'Email service abhi setup nahi hai. Admin se sampark karein.' });
      }
      console.error('Email-change OTP mail failed:', mailErr.message);
      return res.status(502).json({ success: false, message: 'OTP email bhejne me dikkat aayi. Thodi der baad try karein.' });
    }
    res.json({ success: true, message: `OTP ${maskEmail(cleanEmail)} par bhej diya gaya hai.`, maskedEmail: maskEmail(cleanEmail) });
  } catch (error) {
    console.error('Change-email OTP error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

router.post('/change-email/verify', otpVerifyLimiter, requireAuth, async (req, res) => {
  try {
    const cleanEmail = emailValue(req.body && req.body.newEmail);
    const cleanOtp = otpValue(req.body && req.body.otp);
    if (!cleanEmail || !isValidEmail(cleanEmail) || !cleanOtp) {
      return res.status(400).json({ success: false, message: 'Naya email aur OTP dono zaroori hain.' });
    }
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: 'Account nahi mila.' });
    if (!user.password || user.isGoogleUser) {
      return res.status(400).json({ success: false, message: 'Google account ka email Google se manage hota hai.' });
    }
    const record = await ActionOtp.findOne({ userId: user._id, purpose: 'email-change' });
    if (!record || record.newEmail !== cleanEmail || !record.otpHash || !record.otpExpires || record.otpExpires < new Date()) {
      return res.status(400).json({ success: false, message: 'OTP galat ya expire ho gaya hai. Naya OTP bhejein.' });
    }
    if ((record.attempts || 0) >= 5) {
      return res.status(429).json({ success: false, message: 'Bahut zyada galat attempts. Naya OTP bhejein.' });
    }
    if (!otpMatches(cleanOtp, record.otpHash)) {
      await ActionOtp.updateOne({ _id: record._id, attempts: { $lt: 5 } }, { $inc: { attempts: 1 } });
      return res.status(400).json({ success: false, message: 'OTP galat hai.' });
    }
    if (await User.findOne({ email: cleanEmail })) {
      return res.status(409).json({ success: false, message: 'Ye email kisi aur account par pehle se hai.' });
    }
    user.email = cleanEmail;
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    await user.save();
    await ActionOtp.deleteOne({ userId: user._id, purpose: 'email-change' });
    const token = signUser(user);
    res.json({ success: true, message: 'Email verify ho gaya aur update ho gaya!', token, user: publicUser(user) });
  } catch (error) {
    console.error('Change-email verify error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// Purana direct-change route band (OTP bypass nahi).
router.post('/change-email', authLimiter, requireAuth, (req, res) => {
  res.status(410).json({ success: false, message: 'App update karein — email change ab OTP verify karne ke baad hota hai.' });
});

// #6: Account delete step-1 — current email par OTP
router.post('/delete-account/request-otp', otpRequestLimiter, requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: 'Account nahi mila.' });
    const now = new Date();
    const record = await ActionOtp.findOne({ userId: user._id, purpose: 'delete-account' });
    const inWindow = record && record.sendWindowStart && (now - record.sendWindowStart) < 15 * 60 * 1000;
    if (inWindow && (record.sendCount || 0) >= 3) {
      return res.status(429).json({ success: false, message: 'Bahut zyada OTP requests. 15 minute baad try karein.' });
    }
    const otp = String(crypto.randomInt(100000, 999999));
    await ActionOtp.findOneAndUpdate(
      { userId: user._id, purpose: 'delete-account' },
      {
        newEmail: '',
        otpHash: hashOtp(otp),
        otpExpires: new Date(Date.now() + 10 * 60 * 1000),
        attempts: 0,
        lastSentAt: now,
        sendCount: inWindow ? (record.sendCount || 0) + 1 : 1,
        sendWindowStart: inWindow ? record.sendWindowStart : now
      },
      { upsert: true, new: true }
    );
    try {
      await sendOtpEmailFor(user.email, otp, 'delete-account');
    } catch (mailErr) {
      if (mailErr.code === 'EMAIL_NOT_CONFIGURED') {
        return res.status(503).json({ success: false, message: 'Email service abhi setup nahi hai. Admin se sampark karein.' });
      }
      console.error('Delete-account OTP mail failed:', mailErr.message);
      return res.status(502).json({ success: false, message: 'OTP email bhejne me dikkat aayi. Thodi der baad try karein.' });
    }
    res.json({ success: true, message: `OTP ${maskEmail(user.email)} par bhej diya gaya hai.`, maskedEmail: maskEmail(user.email) });
  } catch (error) {
    console.error('Delete-account OTP error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// #6: Account delete step-2 — DELETE confirm + current email ka OTP verify
// Cloudinary images best-effort destroy (bounded) — fail ho toh delete rukna nahi chahiye.
router.post('/delete-account', otpVerifyLimiter, requireAuth, async (req, res) => {
  try {
    const body = req.body || {};
    const confirm = body.confirm;
    const cleanOtp = otpValue(body.otp);
    if (confirm !== 'DELETE') {
      return res.status(400).json({ success: false, message: 'Confirm ke liye DELETE likhein.' });
    }
    if (!cleanOtp) {
      return res.status(400).json({ success: false, message: 'Pehle email par OTP bhejein, phir OTP dalein.' });
    }
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: 'Account nahi mila.' });
    const record = await ActionOtp.findOne({ userId: user._id, purpose: 'delete-account' });
    if (!record || !record.otpHash || !record.otpExpires || record.otpExpires < new Date()) {
      return res.status(400).json({ success: false, message: 'OTP galat ya expire ho gaya hai. Naya OTP bhejein.' });
    }
    if ((record.attempts || 0) >= 5) {
      return res.status(429).json({ success: false, message: 'Bahut zyada galat attempts. Naya OTP bhejein.' });
    }
    if (!otpMatches(cleanOtp, record.otpHash)) {
      await ActionOtp.updateOne({ _id: record._id, attempts: { $lt: 5 } }, { $inc: { attempts: 1 } });
      return res.status(400).json({ success: false, message: 'OTP galat hai.' });
    }
    // Delete se pehle archive + image URLs jama karo (baad me docs gayab ho jayenge).
    // 1001 dekh kar >1000 par abort — warna baaki rooms bina archive delete ho jate.
    const rooms = await Room.find({ userId: user._id }).limit(1001).lean();
    if (rooms.length > 1000) {
      return res.status(503).json({ success: false, message: 'Account me bahut zyada ads hain. Support se delete karwayein.' });
    }
    const archived = await archiveRooms(rooms, {
      deletedBy: req.user.id,
      deletedByRole: 'user',
      reason: 'self account delete'
    });
    if (rooms.length > 0 && archived < rooms.length) {
      return res.status(500).json({ success: false, message: 'Delete safety check fail hua. Baad me try karein.' });
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
      User.deleteOne({ _id: user._id })
    ]);
    // 🧾 Consent withdrawal ka proof (hashed) — 180 din baad cleanup cron delete karega
    ConsentLog.updateMany(
      { emailHash: sha256(String(user.email).toLowerCase().trim()), withdrawnAt: null },
      { $set: { withdrawnAt: new Date() } }
    ).catch(() => {});
    try {
      const upload = require('../config/cloudinary');
      if (urls.length > 0) await upload.destroyByUrls(urls);
    } catch { /* orphan images maaf — account delete ho chuka */ }
    await logAudit(req, { action: 'user.account_deleted', targetType: 'user', targetId: user._id, actorId: user._id, actorRole: 'user', details: { rooms: rooms.length } });
    res.json({ success: true, message: 'Account aur saare ads delete ho gaye. Alvida!' });
  } catch (error) {
    console.error('Delete-account error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// NOTE: purana `/claim-orphans` (one-tap saare legacy ads claim) HATA diya gaya (P0 #13 fix).// Wajah: koi bhi naya user ek click me SAARE orphan ads le leta tha — abuse-prone.
// Naya safe flow (rooms routes me): mobile-match + admin-approval
//   GET  /api/rooms/claimable?mobile=   → apne purane ads dhundho
//   POST /api/rooms/:id/claim           → claim request (admin verify karega)
//   GET/POST /api/rooms/admin/claims... → admin approve/reject

// 9. Apna naam badlo (logged-in user — settings panel se)
router.patch('/profile', requireAuth, async (req, res) => {
  try {
    const body = req.body || {};
    const hasName = body.name !== undefined;
    const hasPhone = body.phone !== undefined;
    if (!hasName && !hasPhone) {
      return res.status(400).json({ success: false, message: 'Naam ya mobile me se kuch update karein.' });
    }
    let cleanName = '';
    if (hasName) {
      if (typeof body.name !== 'string') {
        return res.status(400).json({ success: false, message: 'Naam 2-60 characters ka ho.' });
      }
      cleanName = cleanText(body.name, 60);
      if (cleanName.length < 2) {
        return res.status(400).json({ success: false, message: 'Naam 2-60 characters ka ho.' });
      }
    }
    let cleanNumber = '';
    if (hasPhone) {
      cleanNumber = cleanPhone(body.phone);
      if (!cleanNumber) {
        return res.status(400).json({ success: false, message: 'Sahi 10-digit mobile number daliye.' });
      }
    }
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: 'Account nahi mila.' });
    if (hasName) user.name = cleanName;
    if (hasPhone) user.phone = cleanNumber;
    await user.save();
    res.json({ success: true, message: 'Profile update ho gayi!', user: publicUser(user) });
  } catch (error) {
    console.error('Profile error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// 10. ❤️ Saved ads list (full room data ke saath)
router.get('/favorites', requireAuth, async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const favs = await Favorite.find({ userId: req.user.id }).sort({ createdAt: -1 });
    const rooms = await Room.find({ _id: { $in: favs.map((f) => f.roomId) } })
      .select(PUBLIC_ROOM_EXCLUDE)
      .lean();
    const order = {};
    favs.forEach((f, i) => { order[f.roomId.toString()] = i; });
    rooms.sort((a, b) => (order[a._id.toString()] || 0) - (order[b._id.toString()] || 0));
    res.json({ success: true, rooms });
  } catch (error) {
    console.error('Favorites error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// 11. ❤️ Save/Unsave toggle
router.post('/favorites/:roomId/toggle', requireAuth, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.roomId)) { // P1 #15: galat id → 500 nahi
      return res.status(404).json({ success: false, message: 'Room nahi mila.' });
    }
    const room = await Room.findById(req.params.roomId);
    if (!room) return res.status(404).json({ success: false, message: 'Room nahi mila.' });
    const existing = await Favorite.findOne({ userId: req.user.id, roomId: room._id });
    if (existing) {
      await Favorite.deleteOne({ _id: existing._id });
      return res.json({ success: true, saved: false, message: 'Saved se hataya.' });
    }
    await Favorite.create({ userId: req.user.id, roomId: room._id });
    res.json({ success: true, saved: true, message: 'Save ho gaya!' });
  } catch (error) {
    if (error.code === 11000) return res.json({ success: true, saved: true });
    console.error('Favorite toggle error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// GET Total Users Count — ADMIN ONLY (M14 fix, pehle public tha)
router.get('/count', requireAdmin, async (req, res) => {
  try {
    const count = await User.countDocuments();
    res.json({ success: true, count });
  } catch (error) {
    console.error('User count error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

module.exports = router;
