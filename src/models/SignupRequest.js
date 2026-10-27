const mongoose = require('mongoose');

// Email-OTP signup: account tabhi banta hai jab email par bheja OTP verify ho.
// Password hash yahan short-lived rakha jaata hai taaki OTP page reload/background
// ke baad bhi account create ho sake — plain password client me store nahi hota.
const signupRequestSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  name: { type: String, required: true, trim: true, maxlength: 60 },
  phone: { type: String, required: true, trim: true },
  passwordHash: { type: String, default: null },
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
