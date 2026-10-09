const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');
const User = require('../models/User');
const Otp = require('../models/Otp');
const { signUser, requireAuth, requireAdmin } = require('../middleware/auth');
const { sendOtpEmail } = require('../config/mailer');

// Brute-force protection (H4): login/google par 15 min me max 20,
// OTP maangne par 15 min me max 10 (plus per-email 3/15min andar)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: 'Bahut zyada attempts. 15 minute baad try karein.' }
});
const otpRequestLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: 'Bahut zyada OTP requests. 15 minute baad try karein.' }
});

const sha256 = (val) => crypto.createHash('sha256').update(val).digest('hex');
const publicUser = (user) => ({ id: user._id, name: user.name, email: user.email, pic: user.profilePic });
// Basic email-format check (nodemailer addressparser abuse + galat input rokne ke liye)
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());

// 1. Email & Password Signup (bcrypt hash + JWT — C4/C7 fix)
router.post('/signup', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: 'Naam, Email aur Password teeno zaroori hain.' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, message: 'Sahi email address daliye.' });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password kam se kam 6 characters ka ho.' });
    }
    const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Ye Email pehle se registered hai!' });
    }
    const newUser = await User.create({ name, email, password }); // Model hook hash karega
    const token = signUser(newUser);
    res.status(201).json({ success: true, message: 'Account ban gaya!', token, user: publicUser(newUser) });
  } catch (error) {
    console.error('Signup error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// 2. Email & Password Login (bcrypt compare + JWT — C4/C7 fix)
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email aur Password dono zaroori hain.' });
    }
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ success: false, message: 'Email ya Password galat hai!' });
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
    const ticket = await client.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID
    });
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
        isGoogleUser: true
      });
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
      throw mailErr;
    }
    return done();
  } catch (error) {
    console.error('Forgot-password error:', error.message);
    res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
  }
});

// 5. OTP Verify — sahi hone par single-use reset token (R2)
router.post('/verify-otp', async (req, res) => {
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
router.post('/reset-password', async (req, res) => {
  try {
    const { email, resetToken, newPassword } = req.body || {};
    if (!email || !resetToken || !newPassword) {
      return res.status(400).json({ success: false, message: 'Email, token aur naya password zaroori hain.' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ success: false, message: 'Password kam se kam 6 characters ka ho.' });
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
    if (newPassword.length < 6) {
      return res.status(400).json({ success: false, message: 'Password kam se kam 6 characters ka ho.' });
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
