const express = require('express');
const router = express.Router();
const crypto = require('crypto');
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

// 1. Signup step-1: email OTP bhejo (account ab OTP verify hone par hi banta hai)
// Password is request me validate hota hai par store NAHI hota — verify par dobara aata hai.
router.post('/signup/request-otp', otpRequestLimiter, async (req, res) => {
  try {
    const { name, phone, email, password } = req.body || {};
    if (!name || !phone || !email || !password) {
      return res.status(400).json({ success: false, message: 'Naam, Mobile, Email aur Password charo zaroori hain.' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, message: 'Sahi email address daliye.' });
    }
    const cleanName = String(name).trim();
    if (cleanName.length < 2 || cleanName.length > 60) {
      return res.status(400).json({ success: false, message: 'Naam 2-60 characters ka ho.' });
    }
    const cleanNumber = cleanPhone(phone);
    if (!cleanNumber) {
      return res.status(400).json({ success: false, message: 'Sahi 10-digit mobile number daliye.' });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ success: false, message: 'Password kam se kam 8 characters ka ho.' });
    }
    if (isWeakPassword(password)) {
      return res.status(400).json({ success: false, message: 'Ye password bahut common hai. Strong password chunein.' });
    }
    const cleanEmail = String(email).toLowerCase().trim();
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
    await SignupRequest.findOneAndUpdate(
      { email: cleanEmail },
      {
        name: cleanName,
        phone: cleanNumber,
        otpHash: sha256(otp),
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

// 1b. Signup step-2: OTP verify → account create + login token
router.post('/signup/verify-otp', otpVerifyLimiter, async (req, res) => {
  try {
    const { email, otp, password } = req.body || {};
    if (!email || !otp || !password) {
      return res.status(400).json({ success: false, message: 'Email, OTP aur Password zaroori hain.' });
    }
    if (String(password).length < 8 || isWeakPassword(password)) {
      return res.status(400).json({ success: false, message: 'Password strong (8+ characters) hona chahiye.' });
    }
    const cleanEmail = String(email).toLowerCase().trim();
    const record = await SignupRequest.findOne({ email: cleanEmail });
    if (!record || !record.otpHash || !record.otpExpires || record.otpExpires < new Date()) {
      return res.status(400).json({ success: false, message: 'OTP galat ya expire ho gaya hai. Naya OTP bhejein.' });
    }
    if ((record.attempts || 0) >= 5) {
      return res.status(429).json({ success: false, message: 'Bahut zyada galat attempts. Naya OTP bhejein.' });
    }
    if (sha256(String(otp).trim()) !== record.otpHash) {
      record.attempts = (record.attempts || 0) + 1;
      await record.save();
      return res.status(400).json({ success: false, message: 'OTP galat hai.' });
    }
    if (await User.findOne({ email: cleanEmail })) {
      await SignupRequest.deleteOne({ email: cleanEmail });
      return res.status(409).json({ success: false, message: 'Ye Email pehle se registered hai. Sign in karein.' });
    }
    const newUser = await User.create({
      name: record.name,
      email: cleanEmail,
      phone: record.phone,
      password,
      termsAcceptedAt: new Date(),
      termsVersion: TERMS_VERSION
    });
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
    const { email, password } = req.body || {};
    if (!email || !password) {
      console.warn('Login 400: missing fields', { hasEmail: Boolean(email), hasPassword: Boolean(password) });
      return res.status(400).json({ success: false, message: 'Email aur Password dono zaroori hain.' });
    }
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user || !(await user.comparePassword(password))) {
      console.warn('Login 401: userExists=', Boolean(user));
      return res.status(401).json({ success: false, message: 'Email ya Password galat hai!' });
    }
    const blockedMsg = accountBlockMessage(user);
    if (blockedMsg) return res.status(403).json({ success: false, message: blockedMsg });
    // Login par checkbox tick tha → consent proof update (acceptedTerms FE bhejta hai)
    if (req.body && req.body.acceptedTerms === true) {
      if (user.termsVersion !== TERMS_VERSION) {
        ConsentLog.create({ emailHash: sha256(user.email.toLowerCase().trim()), termsVersion: TERMS_VERSION }).catch(() => {});
      }
      user.termsAcceptedAt = new Date();
      user.termsVersion = TERMS_VERSION;
      await user.save();
    }
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
    if (!payload || !payload.email || !payload.email_verified) {
      return res.status(401).json({ success: false, message: 'Google verification fail ho gayi.' });
    }

    let user = await User.findOne({ email: payload.email.toLowerCase() });
    if (!user) {
      user = await User.create({
        name: payload.name || 'User',
        email: payload.email,
        profilePic: payload.picture || '',
        isGoogleUser: true,
        termsAcceptedAt: new Date(),
        termsVersion: TERMS_VERSION
      });
      ConsentLog.create({ emailHash: sha256(payload.email.toLowerCase()), termsVersion: TERMS_VERSION }).catch(() => {});
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
    const { email } = req.body || {};
    if (!email || !isValidEmail(email)) {
      // Invalid format par bhi generic response (enumeration oracle nahi banana)
      return res.json({ success: true, message: 'Agar ye email registered hai toh OTP bhej diya gaya hai.' });
    }
    const done = () => res.json({ success: true, message: 'Agar ye email registered hai toh OTP bhej diya gaya hai.' });

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user || user.isGoogleUser || !user.password) return done(); // Google users ka password reset nahi hota

    // Per-email abuse limit: 15 min window me max 3 OTP
    const now = new Date();
    const record = await Otp.findOne({ email: user.email });
    if (record && record.sendWindowStart && (now - record.sendWindowStart) < 15 * 60 * 1000) {
      if ((record.sendCount || 0) >= 3) {
        return res.status(429).json({ success: false, message: 'Bahut zyada OTP requests. 15 minute baad try karein.' });
      }
    }
    const inWindow = record && record.sendWindowStart && (now - record.sendWindowStart) < 15 * 60 * 1000;

    const otp = String(crypto.randomInt(100000, 999999)); // 6-digit
    await Otp.findOneAndUpdate(
      { email: user.email },
      {
        otpHash: sha256(otp),
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
    const { email, otp } = req.body || {};
    if (!email || !otp) {
      return res.status(400).json({ success: false, message: 'Email aur OTP dono zaroori hain.' });
    }
    const record = await Otp.findOne({ email: email.toLowerCase().trim() });
    if (!record || !record.otpHash || !record.otpExpires || record.otpExpires < new Date()) {
      return res.status(400).json({ success: false, message: 'OTP galat ya expire ho gaya hai. Naya OTP mangwayein.' });
    }
    if ((record.attempts || 0) >= 5) {
      return res.status(429).json({ success: false, message: 'Bahut zyada galat attempts. Naya OTP mangwayein.' });
    }
    if (sha256(String(otp).trim()) !== record.otpHash) {
      record.attempts = (record.attempts || 0) + 1;
      await record.save();
      return res.status(400).json({ success: false, message: 'OTP galat hai.' });
    }
    const resetToken = crypto.randomBytes(32).toString('hex');
    record.resetTokenHash = sha256(resetToken);
    record.resetExpires = new Date(Date.now() + 15 * 60 * 1000);
    record.otpHash = null;
    record.otpExpires = null;
    record.attempts = 0;
    await record.save();
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
    const { email, resetToken, newPassword } = req.body || {};
    if (!email || !resetToken || !newPassword) {
      return res.status(400).json({ success: false, message: 'Email, token aur naya password zaroori hain.' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, message: 'Password kam se kam 8 characters ka ho.' });
    }
    if (isWeakPassword(newPassword)) {
      return res.status(400).json({ success: false, message: 'Ye password bahut common hai. Strong password chunein.' });
    }
    const record = await Otp.findOne({ email: email.toLowerCase().trim() });
    if (!record || !record.resetTokenHash || !record.resetExpires || record.resetExpires < new Date()
        || sha256(resetToken) !== record.resetTokenHash) {
      return res.status(400).json({ success: false, message: 'Link galat ya expire ho gaya hai. Dobara OTP mangwayein.' });
    }
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Account nahi mila.' });
    }
    user.password = newPassword; // Model hook hash karega
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    await user.save();
    await Otp.deleteOne({ email: user.email }); // Token single-use tha
    res.json({ success: true, message: 'Password badal gaya hai. Dobara login karein.' });
  } catch (error) {
    console.error('Reset-password error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// 7. Logged-in user ka password change (R4)
router.post('/change-password', requireAuth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body || {};
    if (!oldPassword || !newPassword) {
      return res.status(400).json({ success: false, message: 'Puraana aur naya password dono zaroori hain.' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, message: 'Password kam se kam 8 characters ka ho.' });
    }
    if (isWeakPassword(newPassword)) {
      return res.status(400).json({ success: false, message: 'Ye password bahut common hai. Strong password chunein.' });
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
    const { password, newEmail } = req.body || {};
    if (!isValidEmail(newEmail)) {
      return res.status(400).json({ success: false, message: 'Sahi naya email address daliye.' });
    }
    const cleanEmail = String(newEmail).toLowerCase().trim();
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: 'Account nahi mila.' });
    if (!user.password || user.isGoogleUser) {
      return res.status(400).json({ success: false, message: 'Google account ka email Google se manage hota hai.' });
    }
    if (cleanEmail === user.email) {
      return res.status(400).json({ success: false, message: 'Ye wahi purana email hai.' });
    }
    if (!password || !(await user.comparePassword(password))) {
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
        otpHash: sha256(otp),
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
    const { newEmail, otp } = req.body || {};
    if (!isValidEmail(newEmail) || !otp) {
      return res.status(400).json({ success: false, message: 'Naya email aur OTP dono zaroori hain.' });
    }
    const cleanEmail = String(newEmail).toLowerCase().trim();
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
    if (sha256(String(otp).trim()) !== record.otpHash) {
      record.attempts = (record.attempts || 0) + 1;
      await record.save();
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
        otpHash: sha256(otp),
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
    const { otp, confirm } = req.body || {};
    if (confirm !== 'DELETE') {
      return res.status(400).json({ success: false, message: 'Confirm ke liye DELETE likhein.' });
    }
    if (!otp) {
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
    if (sha256(String(otp).trim()) !== record.otpHash) {
      record.attempts = (record.attempts || 0) + 1;
      await record.save();
      return res.status(400).json({ success: false, message: 'OTP galat hai.' });
    }
    // Delete se pehle image URLs jama karo (baad me docs gayab ho jayenge)
    const rooms = await Room.find({ userId: user._id }).select('image images').lean();
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
      cleanName = String(body.name || '').trim();
      if (cleanName.length < 2 || cleanName.length > 60) {
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
    const favs = await Favorite.find({ userId: req.user.id }).sort({ createdAt: -1 });
    const rooms = await Room.find({ _id: { $in: favs.map((f) => f.roomId) } });
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
