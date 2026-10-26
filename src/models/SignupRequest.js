const mongoose = require('mongoose');

// Email-OTP signup: account tabhi banta hai jab email par bheja OTP verify ho.
// Password yahan save NAHI hota — verify step par user dobara bhejta hai (hash User hook karta hai).
const signupRequestSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  name: { type: String, required: true, trim: true, maxlength: 60 },
  phone: { type: String, required: true, trim: true },
  otpHash: { type: String, default: null },
  otpExpires: { type: Date, default: null },
  attempts: { type: Number, default: 0 },
  sendCount: { type: Number, default: 0 },
  sendWindowStart: { type: Date, default: null },
  lastSentAt: { type: Date, default: null }
}, { timestamps: true });

// Thoda extra buffer ke baad stale request auto-clean
signupRequestSchema.index({ otpExpires: 1 }, { expireAfterSeconds: 3600 });

module.exports = mongoose.model('SignupRequest', signupRequestSchema);
